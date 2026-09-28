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

The audit stream is delivered only to connected users with `audit_logs.view`.
The `audit_sync` cursor is scoped with the same `ANY`, `TEAM`, or `OWN` rules as
the audit page; event IDs are stable and clients de-duplicate replayed events
after reconnect. Audit details and resource links re-check the viewer's current
scope and resource permission.

### Retention

Audit history is retained indefinitely by default; there is no automatic purge.
Before enabling deletion, administrators should set a retention period based
on legal and operational requirements, export or archive records required for
investigations, and test the purge procedure against the production database.
No export endpoint is currently implemented.

### Proposed schema change (approval required)

The current `AuditLog` model has no `result` or `reason` columns. For normalized
filtering and reporting, the proposed additive schema is nullable
`result VARCHAR(20)` and `reason VARCHAR(255)` columns, with values such as
`success`, `denied`, and a bounded reason code. Existing rows would remain NULL;
new events would populate the fields while retaining the JSON values for
backward compatibility. This is a proposal only: no migration or automatic
schema change should be run until the database owner approves the column names,
lengths, allowed values, and rollout/backfill policy.

The pagination query has been checked against SQL Server's
`OFFSET ... ROWS FETCH FIRST ... ROWS ONLY` syntax. The automated audit suite is
run against isolated SQLite for data-fixture safety; it does not replace an
integration run against the deployed SQL Server version and ODBC driver.

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
