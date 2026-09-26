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
