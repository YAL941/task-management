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

## Default login accounts

- Admin: `admin` / `Admin@12345`
- Manager: `manager` / `Manager@12345`
- User: `user` / `User@12345`

## Notes

- If no AI API key is configured, the app automatically falls back to mock AI responses.
- If SMTP is not configured, outgoing emails are recorded in mock mode instead of being sent.
