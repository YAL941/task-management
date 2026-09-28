# TaskHQ

A Flask-based task management system with role-based access, notifications, team management, automation rules, and AI assistant support.

## Features

- User authentication and role-based access
- Task creation, assignment, status updates, and dependency tracking
- Automation rules that run inside the request and notify the assignee live
- Performance reports by assignee, team, status, and priority, exportable as PDF, Excel, or CSV
- Team and member management
- Notifications and email simulation
- Audit logs and automation rules
- Data import/export (CSV / Excel / PDF)
- AI assistant with mock and provider-backed modes

## Granular RBAC

The application now resolves access through normalized `roles`, `permissions`,
`role_permissions`, and `user_roles` tables. Existing `User.role` values are
kept as a compatibility layer and are seeded into the matching system role.

Permissions are checked in the backend with `has_permission(user, key,
resource)`. Resource checks support `OWN`, `TEAM`, and `ANY` scopes. The role
management screen is available at `/roles` for users with `roles.view`, and
the current user's effective grants are available at `/api/me/permissions`.
Role changes are audited and publish `PERMISSIONS_UPDATED` over the existing
Socket.IO connection.

### Permission catalog

`permissions.key` is the grant stored in `role_permissions`; `has_permission`
is the only check. The `<entity>.<action>` pairs that end in `.edit`, `.delete`,
or `.assign` also honour the matching `*_own` grant, and only when the caller owns
the resource (`creator_id` or `user_id`) or shares a team with it.

| Group | Keys |
| --- | --- |
| Tasks | `tasks.view`, `tasks.create`, `tasks.edit`, `tasks.delete`, `tasks.assign`, `tasks.reassign`, `tasks.change_status`, `tasks.change_priority`, `tasks.change_due_date`, `tasks.cancel`, `tasks.restore`, `tasks.archive`, `tasks.export`, `tasks.edit_own`, `tasks.delete_own`, `tasks.assign_own` |
| Users | `users.view`, `users.create`, `users.edit`, `users.delete`, `users.activate`, `users.deactivate`, `users.reset_password` |
| Roles | `roles.view`, `roles.create`, `roles.edit`, `roles.delete`, `roles.assign` |
| Permissions | `permissions.view`, `permissions.manage` |
| Comments | `comments.view`, `comments.create`, `comments.edit`, `comments.delete` |
| Attachments | `attachments.view`, `attachments.upload`, `attachments.delete` |
| Notifications | `notifications.view`, `notifications.manage` |
| Reports | `reports.view`, `reports.create`, `reports.export` |
| Audit Logs | `audit_logs.view`, `audit_logs.export` |
| Settings | `settings.view`, `settings.edit` |

`PERMISSION_SCOPES` is `OWN`, `TEAM`, and `ANY`. A `TEAM` grant only applies to a
resource whose `team_id` the caller is a `TeamMember` of, and an `OWN` grant only
to a resource they created or were assigned. The seeded system roles grant: all
46 keys at `ANY` (Super Admin, Admin), 19 team keys at `TEAM` (Manager), and 12
own-level keys at `OWN` (User). The catalog is defined in `PERMISSION_CATALOG`
and the defaults in `ROLE_DEFAULTS`; both are the authoritative source.

Team membership carries its own separate permission set, stored comma-joined on
`TeamMember.permissions`: `view_tasks`, `create_tasks`, `post_messages`,
`manage_members`, `manage_meetings`. These are not part of the RBAC catalog.

`has_permission` treats a resource the caller neither owns nor shares a team
with as matching only an `ANY` grant, and fails closed when no grant exists.
`User.role` is a compatibility field: `user_roles` falls back to the system role
of the same name, so a legacy value of `User` still yields the `User` role's
twelve own-level grants.

## Automation rules

A rule is a small trigger: an event, a condition, a value, and an action. Rules
run **inside the request that satisfies them**, so the person responsible is
notified as soon as the task changes, not on the next scheduled sweep.

| Event | Condition | Value | Fires when |
| --- | --- | --- | --- |
| `status_changed` | `changes_to` | a task status | a task actually transitions into that status |
| `status_changed` | `equals` | a task status | a task is in that status |
| `overdue` | ignored | unused | a task's due date has passed and it is not `Completed` |

Actions are `notify` and `email`; `email` sends the message and also records it
in `email_logs`. The rule form rejects any other combination, so a rule that
could never fire cannot be stored.

The recipient is the **assignee** (`Task.user_id`), falling back to the creator
when the task is unassigned. They receive a stored `Notification` and a live
`NOTIFICATION_CREATED` push to their `user:<id>` room, so the bell updates
without a page reload.

Each rule fires at most once per task and state. The published event's own
`event_id` is the marker, for example `automation-7-42-Completed`, so a repeat
status change, a reconnect replay, and the worker's periodic sweep are all
idempotent. An `overdue` rule's marker carries the date, giving one notification
per day while a task stays late.

Every firing writes an `automation_triggered` audit row on the task, with the
rule, action, condition, resulting status, and recipient, scoped to the
creator, the assignee, and the recipient, so it appears in each of their audit
views.

`run_automation_once` remains the sweep for the optional `worker.py`: it covers
the time-based `overdue` event and acts as a safety net for a rule created while
a task is already in the target state. Deduplication makes a repeated sweep a
no-op.

## Performance reports

`/reports` aggregates the caller's visible tasks - the same set
`visible_tasks_for_user` returns, so a report can never show a task the caller
could not open - into a completion rate, an open and overdue count, per-status
and per-priority counts, and a per-assignee table with assigned, completed,
overdue, and completion rate. `?date_from=` and `?date_to=` narrow the period;
completed tasks are dated by `completed_at` and everything else by its due date.
A task with neither date is kept, because nothing proves it falls outside the
window and excluding it would quietly understate the totals.

`/analytics` shows the same distribution live. Both pages export the aggregate
as `GET /export/reports.<fmt>` in `csv`, `xlsx`, and `pdf`: the workbook has a
`Summary`, `By assignee`, and `By team` sheet, and the PDF is a paginated report
rather than a raw row dump. The endpoint requires `permissions.manage` from
`admin_required` and additionally `reports.view`; a missing grant records
`reports_view_forbidden` and returns `403`. `resource=tasks` still exports the
raw task rows, which is what the importer consumes.

## HTTP API

Every route is guarded by `login_required`; `/automation`, `/data`, and
`/export` are additionally guarded by `admin_required`, which requires
`permissions.manage` and redirects otherwise. The permission column lists the
check the view performs inside the request; a refusal records an
`access_denied` row with the matching `*_forbidden` reason code and flashes the
message, so it is never a silent 403. All mutating routes require the CSRF token
in the form body or the `X-CSRF-Token` header; the JSON routes answer `400` with
`{"ok": false, "error": "Invalid request"}` instead of redirecting.

| Method | Path | Permission | Notes |
| --- | --- | --- | --- |
| GET, POST | `/login` | none | `POST` needs no CSRF; writes `logged_in` or `login_failed` |
| POST | `/logout` | session | `logged_out` |
| GET | `/` | session | Dashboard |
| GET | `/tasks` | `tasks.view` | `?view=all|sent|received|urgent`, `?status`, `?priority`, `?q`, `?focus` |
| GET, POST | `/add_task` | `tasks.create` | `POST` needs a title, a priority in `Low/Medium/High`, a real assignee, and a `YYYY-MM-DD` due date if given |
| GET, POST | `/edit_task/<id>` | `tasks.edit` (or `tasks.edit_own`) | Audits only a real change; a no-op write is not recorded |
| POST | `/delete_task/<id>` | `tasks.delete` (or `tasks.delete_own`) | `comment` is required and stored as the delete reason |
| POST | `/update_task_status/<id>/<status>` | `tasks.change_status` | `status` must be in `Pending`, `In Progress`, `Completed`, `Rejected`; `Completed`/`Rejected` require `comment`; a non-admin cannot complete a task whose `Blocks`/`Blocked By` predecessor is still open |
| GET, POST | `/tasks/<id>/comments` | `comments.view`, `comments.create` | Comment bodies are never copied into audit values |
| GET | `/tasks/<id>/view` | `tasks.view` | |
| POST | `/tasks/<id>/attachments` | `attachments.upload` | Extension, MIME type, and size are validated; a refusal is `ATTACHMENT_UPLOAD_FAILED` |
| GET | `/attachments/<id>/preview`, `/download` | `attachments.view` | Both record an audit row |
| POST | `/attachments/<id>/delete` | `attachments.delete` | JSON, `400` on a bad token |
| GET, POST | `/tasks/<id>/dependencies` | sender or `Admin` | Rejects an unknown task, a self-reference, an unknown type, and cycles |
| POST | `/tasks/<id>/dependencies/<dep>/delete` | sender or `Admin` | |
| GET, POST | `/teams` | `Admin` or `Manager` for POST | `action` is `create`, `member`, or `delete`; a name and a real `leader_id` are required for `create` |
| GET, POST | `/teams/<id>` | team membership for POST | Membership, role, and meeting changes |
| GET | `/team-workspace` | session | |
| POST | `/teams/<id>/meeting/start`, `/end` | `manage_meetings` for that team | |
| GET, POST | `/users` | `users.view` to read, `users.*` to write | Legacy role column plus the RBAC role assignment |
| GET, POST | `/roles` | `roles.view` to read, `roles.create`/`roles.edit`/`roles.delete` to write | System roles cannot be deleted |
| GET | `/api/me/permissions` | session | `{"permissions": [{"key", "role", "scope"}, ...]}` |
| GET | `/api/realtime/token` | session | `{"token", "user_id"}` for the Socket.IO handshake |
| POST | `/api/ai/ask` | session | `{"prompt"}`, required, at most 2000 characters; `{"ok", "answer", "mode"}` where `mode` is `mock` or `live` |
| GET, POST | `/assistant` | session | The HTML view of the assistant |
| GET, POST | `/automation` | `permissions.manage` | `name` is required; `event`, `condition`, and `action` must be a supported combination, and a status rule's `value` must be a real status |
| POST | `/automation/<id>/toggle` | `permissions.manage` | Flips `enabled` and records `toggled` |
| GET, POST | `/data` | `permissions.manage` | Import; writes `imported` |
| GET | `/export/<resource>.<fmt>` | `permissions.manage`, plus the resource's own key (`audit_logs` needs `audit_logs.view` and `audit_logs.export`; `reports` needs `reports.view`) | `csv`, `xlsx`, `pdf`; an audit export is itself recorded |
| GET, POST | `/settings` | `settings.view` to read, `settings.edit` to write | |
| POST | `/settings/test-email` | `settings.edit` | Mock mode unless SMTP is configured |
| GET | `/reports`, `/analytics` | `reports.view` | Analytics is not a separate key; it reuses `reports.view`. `/reports` accepts `?date_from` and `?date_to` and shows the aggregate plus its export links |
| GET | `/audit-logs` | `audit_logs.view` | Scoped; see "Filtering" |
| GET | `/audit-logs/<id>` | `audit_logs.view` and in-scope | `404` when out of scope, so ids cannot be probed |
| GET | `/notifications/feed` | session | `{"unread_count", "notifications": [{"id", "message", "created_at", "url", "is_read"}]}` for the caller only |
| POST | `/notifications/read` | session | JSON, `notification_ids` |
| GET | `/notifications/<id>` | session | Marks it read; redirects when the row is not the caller's |

## Realtime events

The Socket.IO connection authenticates with the JWT from
`GET /api/realtime/token`; an absent or invalid token is refused. On connect the
server joins the `global`, `user:<id>`, and - when the user has any audit scope -
`audit:user:<id>` rooms, and the caller receives `connected`.

| Direction | Event | Payload |
| --- | --- | --- |
| server -> client | `connected` | `{userId, serverTime}` |
| server -> client | `presence` | `{eventType, userId, status, timestamp}` for every connected user |
| server -> client | `realtime_event` | `{sequence, eventId, eventType, timestamp, userId, entityType, entityId, payload}` |
| server -> client | `audit_log_event` | The full `audit_event_payload`: `sequence`, `eventId`, `eventType`, `timestamp`, `userId`, `actorName`, `entityType`, `entityId`, `action`, `message`, `changes`, `result`, `reason`, `oldValue`, `newValue`, `ipAddress` |
| client -> server | `heartbeat` | Refreshes presence; `{ok, timestamp}` |
| client -> server | `join_room` | `{"room": ...}` where the room is `global`, `user:<id>` (own id only), `task:<id>` (only if `can_access_task`), or `team:<id>` (member, or Admin/Manager). Anything else is `{"ok": false, "error": "Room access denied"}` |
| client -> server | `sync` | `{"lastEventId": n}`; returns `{ok, events, lastEventId}` with task and team access re-checked and at most 200 events |
| client -> server | `audit_sync` | `{"lastAuditLogId": n}`; replays audit rows through the same `ANY`/`TEAM`/`OWN` scope as the audit page. Refused with `{"ok": false, "error": "Unauthorized"}` without `audit_logs.view` |

`audit_log_event` is emitted after the transaction commits, to each connected
user for whom the row is in scope, so two browsers open on the same page both
receive the same event and a user outside the scope receives nothing.

## Audit events

The audit log uses the existing `audit_logs` columns. Current event catalog:

| Area | Actions | Entity | Result source |
| --- | --- | --- | --- |
| Authentication | `logged_in`, `logged_out`, `login_failed` | `user` | `new_value._audit.result` and `new_value._audit.reason` |
| Authorization | `access_denied` | requested entity or `request` | `new_value._audit.result` and `new_value._audit.reason` |
| Denied reason codes | `authentication_required`, `<permission>_forbidden` (for example `task_edit_forbidden`, `task_delete_forbidden`, `task_status_change_forbidden`, `comment_view_forbidden`, `comment_create_forbidden`, `attachment_upload_forbidden`, `attachment_download_forbidden`, `attachment_preview_forbidden`, `attachment_delete_forbidden`, `task_view_forbidden`, `task_create_forbidden`, `tasks_view_forbidden`, `task_dependency_manage_forbidden`, `users_view_forbidden`, `roles_view_forbidden`, `settings_view_forbidden`, `settings_edit_forbidden`, `team_management_forbidden`, `team_member_manage_forbidden`, `team_task_create_forbidden`, `team_task_assign_outside_team_forbidden`, `team_message_forbidden`, `team_permission_update_forbidden`, `meeting_start_forbidden`, `meeting_end_forbidden`, `reports_view_forbidden`, `analytics_view_forbidden`, `audit_logs_view_forbidden`, `audit_logs_scope_forbidden`, `permissions_manage_forbidden`) | entity of the refused request | Denied, never success |
| Users and roles | `created`, `updated`, `deleted`, `ROLE_CREATED`, `ROLE_DELETED`, `ROLE_PERMISSION_UPDATED` | `user` or `role` | Successful persisted change |
| Tasks | `TASK_VIEWED`, `created`, `TASK_ASSIGNED`, `TASK_REASSIGNED`, `updated`, `status_changed`, `deleted` | `task` | Successful persisted change |
| Attachments | `ATTACHMENT_UPLOADED`, `ATTACHMENT_DOWNLOADED`, `ATTACHMENT_DELETED`, `ATTACHMENT_UPLOAD_FAILED` | `attachment`, `task` | Success, failed, or denied outcome |
| Comments | `COMMENT_CREATED` | `task` | Successful persisted change; comment body is not copied into audit metadata |
| Notifications | `NOTIFICATION_CREATED`, `NOTIFICATION_OPENED`, `NOTIFICATIONS_MARKED_READ` | `notification` | Successful persisted change; message content is not copied |
| Other tracked changes | `created`, `updated`, `deleted`, `imported`, `toggled`, `automation_triggered` | entity name | Successful persisted change |

`AuditEventService` is the central writer; the existing `write_audit` helper
delegates to it for compatibility. New outcomes are stored under
`new_value._audit` to avoid an unapproved schema migration. Existing archive,
restore, comment-edit, and comment-delete routes are not present and therefore
are not synthesized by the audit layer.

Every permission gate that refuses a request calls `record_access_denial` with a
specific reason code and the entity it refused, so a denial is never silent and
is distinguishable from another denial of the same area. `admin_required`
records `permissions_manage_forbidden`, and the role and user screens record the
exact permission that was missing (`roles_create_forbidden`, `users_delete_forbidden`,
and so on) together with the target id.

The audit stream is delivered only to connected users with `audit_logs.view`.
The `audit_sync` cursor is scoped with the same `ANY`, `TEAM`, or `OWN` rules as
the audit page; event IDs are stable and clients de-duplicate replayed events
after reconnect. Audit details and resource links re-check the viewer's current
scope and resource permission.

### Reading an event

Every event renders a sentence instead of a raw action code, for example
`admin changed the status of task #42`, `admin was denied access to
/edit_task/5 - denied (task_edit_forbidden)`, or `admin uploaded an attachment
to task #42`. Field-level changes are diffed from the recorded old and new JSON
into `field / before / after` rows; the internal `_audit` metadata block is
excluded from that diff, and the untouched raw values stay available in a
collapsed "Raw recorded values" section on the detail page. The same `message`
and `changes` are part of the `audit_log_event` payload, so a row inserted live
reads exactly like a server-rendered one.

Resource links now cover `task`, `comment`, `attachment`, `team`, `user`,
`role` (needs `roles.view`), and `automation_rule` (needs `permissions.manage`,
the permission that guards `/automation`). Each link is produced only after the
same permission and resource-scope check the target route performs, so the link
is never shown to a viewer who would be denied on click.

`exported` / `audit_logs` is a new action, recorded when someone exports the
audit log. The catalog below lists the pre-existing outcomes; read the audit
page itself for the authoritative set.

When `/audit-logs` is open on the first page with no filters, active search, or
custom sorting, an arriving `audit_log_event` is inserted into the table
immediately. If filters, search, or a different page/sort are active, the page
keeps the "new activity, refresh" notice instead of inserting a row that would
not match the current view. When the visible page is already full, the oldest
row is shifted out so the newest event stays on screen, unless the logs fit on a
single page and there is no paging control to reach the shifted row. Rows are
keyed by audit log ID, and only IDs newer than the newest rendered row are
inserted, so replayed history after a reconnect cannot reorder the table.

### Filtering

`/audit-logs` accepts `search`, `action`, `entity`, `entity_id`, `user_id`,
`result`, `period`, `date_from`, `date_to`, `sort`, `order`, `page`, and
`per_page`. `search` matches the action, entity, old and new values, **or the
actor's username** (resolved through a `users` subquery so the scoped query is
unchanged). `entity_id` matches one resource id exactly. `period` accepts
`today` and `7d`, which are relative windows computed from the server's current
date; an explicit `date_from` takes precedence, and an unknown `period` value is
ignored. The quick-period links clear the custom date range, and every filter is
carried through the sort and pagination links.

### Exporting audit logs

`GET /export/audit_logs.<fmt>` exports the audit rows the viewer may see, in
`csv`, `xlsx`, or `pdf`. The endpoint still requires `permissions.manage` (the
existing `admin_required` guard on `/export`), and on top of that it requires
both `audit_logs.view` and `audit_logs.export`; a missing grant records
`audit_logs_export_forbidden` and returns `403`. The rows are produced by the
same `AuditScopeResolver.apply_to_query` used by the audit page, so an export
can never return a row the viewer could not read on screen. Each column is the
resolved value (`actor` is the username, not the id, and `message` is the
readable sentence), and the export itself is written to the audit log as
`exported` / `audit_logs` with the format and the row count. The export is not
filtered by the search or period currently applied on screen; it covers the
viewer's whole visible scope. The three links on the audit page are shown only
when `audit_logs.export` is granted, which is a display hint; the backend check
above is what enforces it.

### Retention

**Policy: keep audit history indefinitely. There is no automatic purge and no
deletion code path, by decision rather than by omission.** No retention period
will be implemented until a period, a table list, and a dry-run requirement are
approved; deleting audit history is irreversible. When that decision is taken,
export or archive the records required for investigations first (see the export
endpoint above) and rehearse the purge against a copy of the production
database, never against production itself.

### SQL Server verification

`tests/test_mssql_audit_integration.py` has two layers. The dialect layer always
runs: it compiles the audit page's pagination, search, period, and scope queries
against the T-SQL dialect and asserts the emitted form, including that
`offset`/`limit` becomes a `ROW_NUMBER()` window (SQLAlchemy rejects T-SQL
offset/limit without an `ORDER BY`, so this also guards the ordering that the
audit route relies on) and that `ilike` becomes `lower(...) LIKE lower(...)`
with the username lookup kept as a real subquery.

The integration layer only runs against a real server, and only writes when both
variables are set, so pointing it at a production database cannot happen by
accident:

```
$env:TEST_MSSQL_URL = "mssql+pyodbc://sa:<password>@localhost:1433/TaskHQ_test?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
$env:TEST_MSSQL_ALLOW_WRITE = "1"
.\.venv\Scripts\python.exe -m pytest tests/test_mssql_audit_integration.py -q
```

With a local Express instance and Windows Authentication, use the same URL
`.env.example` demonstrates, pointed at a throwaway database:

```
$env:TEST_MSSQL_URL = "mssql+pyodbc:///?odbc_connect=DRIVER%3D%7BODBC+Driver+18+for+SQL+Server%7D%3BSERVER%3D.%5CSQLEXPRESS%3BDATABASE%3DTaskHQ_test%3BTrusted_Connection%3Dyes%3BTrustServerCertificate%3Dyes%3B"
```

The integration layer has been run end to end against SQL Server 2025 (17.0.1)
on `.\SQLEXPRESS` with a dedicated `TaskHQ_test` database: 6 passed, twice in a
row with no rows left behind. It asserts the dialect is really `mssql` before it
writes, uses the app's own `create_all` for the schema (additive only), and
deletes exactly the ids it created, including the role ids it made, so repeated
runs stay clean.

When `TEST_MSSQL_URL` is set, `tests/conftest.py` points the whole application
at that server and deselects every other test module, so the SQLite suite and
the SQL Server suite never mix. The integration test asserts the dialect is
really `mssql` before it writes, uses the app's own `create_all` for the schema
(additive only), and deletes only the rows it created. Use a dedicated,
disposable database.

### Proposed schema change (approval required)

The current `AuditLog` model has no `result` or `reason` columns. For normalized
filtering and reporting, the proposed additive schema is nullable
`result VARCHAR(20)` and `reason VARCHAR(255)` columns, with values such as
`success`, `denied`, and a bounded reason code. Existing rows would remain NULL;
new events would populate the fields while retaining the JSON values for
backward compatibility. This is a proposal only: no migration or automatic
schema change should be run until the database owner approves the column names,
lengths, allowed values, and rollout/backfill policy.

The pagination query is verified in two ways. The always-on dialect layer
compiles it against the T-SQL dialect, where SQLAlchemy renders the offset and
limit as a `ROW_NUMBER()` window rather than a literal
`OFFSET ... ROWS FETCH FIRST ... ROWS ONLY` clause. The opt-in integration layer
(see "SQL Server verification" above) runs the audit flows end to end against a
real server, covering scope filtering, username search, `entity_id`, both
relative periods, paging across a page boundary, an out-of-scope detail returning
`404`, and a scoped export. The default suite still runs on an isolated temporary
SQLite database, because that is what keeps the fixtures safe; it does not
replace a run against the deployed SQL Server version and ODBC driver.

## Tests

`tests/conftest.py` points the session at a throwaway SQLite database in a temp
directory that is removed at the end, and moves `UPLOAD_FOLDER` there too, so no
run touches `.env` or a real database. Run everything with:

```
.\.venv\Scripts\python.exe -m pytest -q
```

| Module | Covers |
| --- | --- |
| `test_rbac.py`, `test_password_compatibility.py` | Role resolution, password hashing and upgrades |
| `test_realtime.py` | Socket.IO authentication, `sync`, and a refused `audit_sync` |
| `test_file_storage.py` | Upload validation, storage paths, and downloads |
| `test_audit_logs_scopes.py` | `ANY`/`TEAM`/`OWN` resolution, snapshot versus live lookups, fail-closed rows |
| `test_audit_logs_pagination.py` | Ordering, paging, and the counter line |
| `test_audit_logs_search_periods.py` | Search fields, `entity_id`, and the `today`/`7d` periods |
| `test_audit_logs_filters.py` | Filter combinations and the carried links |
| `test_audit_logs_readability.py` | Sentences, `before`/`after` diffs, and raw values |
| `test_audit_logs_denial_coverage.py` | Denied edit, delete, status, comment, attachment, and out-of-scope access |
| `test_audit_logs_live_stream.py` | Live insertion, replay protection, and the full-page case |
| `test_audit_logs_multi_client.py` | Two tabs of one user, two users with different scopes, a user with no audit scope, and one client replaying while another is live |
| `test_audit_logs_export.py` | CSV, xlsx, and pdf export, scope, and the export audit row |
| `test_tasks_regression.py` | Task create/edit/delete/status/dependency validation, permission failures, list filters, and the side tables each write touches |
| `test_workspace_regression.py` | Team membership and creation, automation, roles, users, notifications, the assistant API, the admin-only screens, and that every template compiles |
| `test_automation_reports.py` | Rule firing inside the status request, the assignee as recipient, the live push and its dedupe marker, a silent repeated sweep, `changes_to` versus `equals`, `overdue`, unsupported rule combinations, and the report aggregate, period, scoping, and three export formats |
| `test_mssql_audit_integration.py` | The always-on T-SQL dialect layer, plus the opt-in end-to-end run against a real server |

`test_workspace_regression.py` includes a test that compiles every template.
`templates/users.html` once held a Jinja set literal with a variable, `{user[7]}`,
which Jinja cannot parse, so the users screen returned HTTP 500 for everyone;
compiling all templates catches that class of defect without a signed-in request
per page.

## Quick start

1. Create and activate a virtual environment
2. Install dependencies:
   `pip install flask flask_sqlalchemy openpyxl reportlab`
3. Copy `.env.example` to `.env` and adjust values if needed
4. Start the app:
   `python main.py`
5. Open the app at: `http://127.0.0.1:5000`

## SQL Server connection

The project reads `DATABASE_URL` from `.env`. The default example uses Windows Authentication with the local `SQLEXPRESS` instance and the `Task Management System` database. Ensure SQL Server is running, the database exists, and ODBC Driver 18 for SQL Server is installed before starting Flask.

## Deploy to Render with PostgreSQL

1. Push the project to a GitHub repository, then create a Render Blueprint from that repository. Render reads `render.yaml` to create the web service and PostgreSQL database.
2. When prompted, provide unique values for `ADMIN_PASSWORD`, `USER_PASSWORD`, and `MANAGER_PASSWORD`. Render generates `SECRET_KEY`; keep all secrets in Render environment settings, not in Git.
3. Wait for the first deploy to finish, then open the service URL and sign in with the configured account passwords. The default usernames are `admin`, `user`, and `manager`.
4. To run scheduled automation, create a separate Render Background Worker using `python worker.py` and copy the web service's environment variables to it. The worker is optional; without it, scheduled automation checks do not run.

Render PostgreSQL is a separately billed service. Choose a database plan in Render that fits your budget and required data retention. Do not use SQLite for production on Render because its local filesystem is not persistent across service changes.

## Default login accounts

- Admin: `admin` / `Admin@12345`
- Manager: `manager` / `Manager@12345`
- User: `user` / `User@12345`

## Notes

- If no AI API key is configured, the app automatically falls back to mock AI responses.
- If SMTP is not configured, outgoing emails are recorded in mock mode instead of being sent.
