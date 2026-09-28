# TaskHQ

A Flask-based task management system with role-based access, notifications, team management, automation rules, and AI assistant support.

## Features

- User authentication and role-based access
- Task creation, assignment, status updates, and dependency tracking
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
| Other tracked changes | `created`, `updated`, `deleted`, `imported`, `toggled` | entity name | Successful persisted change |

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
real server. The default suite still runs on an isolated temporary SQLite
database, because that is what keeps the fixtures safe; it does not replace a
run against the deployed SQL Server version and ODBC driver.

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
