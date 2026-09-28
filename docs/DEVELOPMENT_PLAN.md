# TaskHQ — Development Plan (Audit → Priorities → Phases)

Status: Phase 5 done, Phase 7 done, Phase 6 next. The five decisions are recorded in section 4.

## 1. What the system already does (keep, do not rebuild)

Verified by reading the code and by querying the live database.

| Area | State |
| --- | --- |
| Auth | Session login, `csrf_token` on every POST, `verify_password` with plaintext upgrade, `access_denied` audit on failure |
| RBAC | 46 permission keys, scopes `OWN`/`TEAM`/`ANY`, custom roles, `*_own` synthesis for edit/delete/assign, role editor UI, `permissions.view` gate |
| Audit | Scoped (`ANY`/`TEAM`/`OWN` via `audit_log_scope_owners`), live Socket.IO stream, filters, search, periods, pagination, CSV/xlsx/pdf export, 91 rows live |
| Notifications | Feed, mark read, per-user preferences, SMTP send with `email_logs`, category classification |
| Mentions | `@username` in comments is parsed and notifies the mentioned user (main.py:3838) |
| Automation | `status_changed` / `overdue` × `equals` / `changes_to` × `notify` / `email`, dedupe markers, runs inside the status request, admin UI |
| Reports | `task_report` real aggregate (summary / by assignee / by team), CSV, xlsx, pdf |
| Import | CSV and xlsx, `validate_import_rows`, session-staged preview, explicit confirm |
| Export | `admin_required` plus per-resource grants |
| Realtime | JWT token, room allow-list, per-event visibility re-check, presence, reconnect sync |
| Attachments | Signature + size validation, storage outside the database, preview/download/delete |
| Tasks | Create, edit, status, priority, due date, dependencies with cycle detection, delete |
| AI assistant | Real LLM when `AI_API_KEY` is set (OpenAI-compatible), rule-based fallback otherwise |

## 2. Gaps found, by severity

### Critical — authorization defects

1. **The sender can change the status of their own task.** `update_status` (main.py:3146) only checks `tasks.change_status`. The rule the product wants — *the sender does not change the status* — exists in the UI as `can_change_status` (main.py:3017) but is computed from the **role name** and is not enforced anywhere in the backend. The button is hidden; a crafted POST succeeds.
2. **Four routes still gate on role names instead of permissions**, which the product rule forbids:
   - `/teams` POST — `session["role"] in {"Admin","Manager"}` (main.py:2182)
   - `/tasks/<id>/dependencies` — `role == "Admin" or task.creator_id == user` (no permission key)
   - `/teams/<id>/meeting/start|end` — role or `TeamMember.permissions` string
   - `/analytics` team-health visibility — `session.get("role") not in {"Admin","Manager"}`
3. **Four permission keys are grantable but never checked**: `tasks.reassign`, `comments.edit`, `comments.delete`, plus `comments.*` edit/delete have no route at all. An admin can tick them on the role screen and nothing changes.

### High — missing product features

4. **Dashboard `/` shows two numbers** (`tasks_count`, `users_count`, main.py:2175). None of the 13 requested metrics, no charts.
5. **No reassign**: no route, no UI, no notification, no audit action.
6. **No comment edit/delete**, no edit timestamp.
7. **No per-task history / activity timeline / related tasks** page.
8. **Task list has no server-side pagination**, search covers the title only, there is no sorting, and the filter inputs duplicate work the backend already does.
9. **AI features are chat-only**: no workload analysis, no assignee recommendation, no daily summary, no risk scoring. `assistant.html` even prints `MOCK MODE` to the user.
10. **Notification types missing**: reassignment, deadline approaching, overdue, AI warning, AI recommendation. `/notifications/read` only marks the caller's own unread rows — there is no per-item or explicit "mark all" contract.
11. **Roles**: only `Super Admin`, `Admin`, `Manager`, `User` are seeded. `Supervisor` and `Employee` do not exist.
12. **Import/Export**: no JSON; the tasks/users/teams PDF path truncates to 100 rows and 110 characters per line; the import preview is capped at 1000 rows with no duplicate reporting.

### High — database

13. **No index on any foreign key or filter column.** Only primary keys and unique constraints exist. Hot paths that filter or join on `tasks.user_id`, `tasks.status`, `tasks.due_date`, `tasks.team_id`, `comments.task_id`, `notifications.user_id`, `audit_logs.created_at`, `audit_logs.entity`, `ai_requests.user_id` are all unindexed. Fine at 22 tasks, expensive at 22 000.
14. **No `department` and no `skills`**, so "tasks by department" and skill-based assignee recommendations have nothing to read.
15. Schema is created by `db.create_all()` plus nine hand-written idempotent `ALTER TABLE` blocks in the import path (main.py:774-821) — no migration history, no rollback, and the `attachments` table can be created by raw DDL with an `INTEGER`-only shape.
16. Live database: `Task Management System` on `.\SQLEXPRESS`, 23 app tables, 51 users, 22 tasks, 3 teams. Contains obvious test rows (task titles `2222222222`, `from khalid`, `FROM KHALIL`).

### Medium — frontend

17. `login.html` bypasses `base.html` and loads its own Tailwind/Alpine; `layout.html` is dead.
18. No shared table, modal, dropdown, or pagination component; `tasks.html` invents its own table and two modals.
19. `add_task.html` builds a file list with `innerHTML` from user-controlled filenames — a stored-XSS vector.
20. `users.html:48` and `tasks.html:139-148` interpolate user data into Alpine expressions unescaped.
21. Three `target="_blank"` links lack `rel="noopener"`.
22. Destructive task actions (delete task, reject task, remove dependency) have no confirmation; dropdowns and modals are not keyboard operable; no `role="dialog"`, no focus management.
23. `.status-pending` (4.1:1) and `--muted` on `--canvas` (4.3:1) fall below WCAG AA for normal text.
24. Chart colors are hardcoded in `analytics.html` instead of using the CSS tokens.

### Medium — reliability and performance

25. **No error handler.** An unhandled exception returns a raw 500 page. This is what produced the `/reports` failure earlier today.
26. N+1 queries: `analytics` calls `db.session.get(Team, ...)` inside a per-task loop; `roles()` calls `get_shared_data()` twice; `audit_resource_url` re-reads per row.
27. `permission_required` (main.py:1425) is dead code and would evaluate its resource argument at import time if it were ever wired up.

### Medium — tests

28. No tests for: dashboard metrics, the sender/status rule, comments edit/delete, mentions, reassign, task list search/pagination/sorting, the error handler, or any of the AI modules. Existing suite: 123 passed, 1 skipped on SQLite; 123 passed on SQL Server.

## 3. Phases

| Phase | Content | Gate |
| --- | --- | --- |
| 5 | Fix the defects above that need no decision: error handler, XSS sinks, `rel=noopener`, confirmations, dead code removal, N+1 fixes | none |
| 6 | Permission model: seed `Supervisor`/`Employee`, add the missing permission checks, replace every role-name gate with a permission check | decisions D, E |
| 7 | Sender rule enforced in the backend, mirrored by the UI, with tests for the refused case | decision A |
| 8 | Reassign, comment edit/delete, per-task history timeline, related tasks | decision A |
| 9 | Task list: server-side search, filters, sort, pagination | none |
| 10 | Dashboard: the 13 metrics and the charts, all from the database | none |
| 11 | Analytics core (deterministic, no LLM): per-user workload, per-task risk score, daily summary — each returning its inputs and its reason | decision C |
| 12 | Assistant integration: the assistant answers from those analyses; optional LLM narration on top; human confirmation before any write | decision B |
| 13 | Notifications for the new events, preferences wired per event type | phase 6-12 |
| 14 | Import/export: JSON, duplicate detection, real preview errors, uncapped exports | none |
| 15 | UI/UX: one layout, shared components, pagination everywhere, accessibility pass, design tokens | none |
| 16 | Indexes and additive columns, with a migration script that is reversible | decision E |
| 17 | Tests for every new path, including the forbidden cases | every phase |
| 18 | Full-system audit and report | all |

Rule for every phase: no feature is added without its backend check, its UI, and its test in the same change.

### Phase 7 — the sender rule, done

`can_change_task_status(user_id, task)` is the single decision point: the task must
be assigned, the caller must be the assignee, and `tasks.change_status` must still
be granted. `update_status` refuses with `task_status_change_forbidden` before it
reads the body, so a refused attempt writes no comment, no audit row and no
notification. `task_view` and the task list take their `can_change_status` from the
same function. Six tests cover it, including the sender who is also the assignee
and the unassigned task.

## 4. Decisions taken

| # | Question | Answer | Consequence |
| --- | --- | --- | --- |
| A | Sender and status | **Absolute: only the assignee changes the status.** No admin or manager exception. The one allowed case is when the sender is also the assignee | Implemented in `can_change_task_status`; both the route and the templates call it, so the button and the POST cannot disagree. A task with no assignee has nobody who may change its status — `add_task` always requires an assignee, so only legacy and imported rows are affected. Flagged as a point for human review |
| B | AI engine | **Deterministic analytics, with an LLM only for wording.** The provider stays optional, as it is today | Workload, risk, and assignee ranking must be computed from the database and return their inputs; the assistant may narrate them but never invent a number |
| C | Department and skills | **Team is the department; skills are inferred from completed tasks.** No new columns | `tasks by department` aggregates on `tasks.team_id`; the assignee ranking compares the titles and priorities a person has already completed instead of a skills column |
| D | Roles | Not yet decided | `Supervisor` and `Employee` are not seeded; a role can still be created on the roles screen today |
| E | Database | **Indexes only, on the live `Task Management System` database.** No new columns, no data changes | Phase 16 adds indexes through a script that prints what it will create and can be reversed |

## 5. Work completed so far

### Phase 5 — defects that needed no decision

- **Error handling.** `templates/error.html` plus handlers for 400, 403, 404 and any unhandled exception. The user gets a readable page and a reference code; the traceback stays in the application log; the crash is audited as `access_denied` with reason `application_error`; XHR and `/api/` routes get JSON instead of HTML. `tests/test_error_handling.py` asserts that no traceback, module name, driver name or file path reaches the browser.
- **XSS sinks closed.** `add_task.html` built its file list with `innerHTML` from user-controlled filenames; it now builds nodes and sets `textContent`. `users.html` and `tasks.html` interpolated user data into Alpine expressions as bare strings; they now use `|tojson`, which emits a safe JavaScript literal.
- **External links** in `teams.html` and `team_detail.html` were missing `rel="noopener"`.
- **Confirmations added** for deleting a task (both screens), rejecting or completing a task, and removing a dependency.
- **Dead code removed**: `permission_required`, a decorator that was never used and would have evaluated its resource at import time, and `templates/layout.html`, which no template extends. The three routes that called `get_shared_data()` twice now call it once.

