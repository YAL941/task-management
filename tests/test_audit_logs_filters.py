from werkzeug.security import generate_password_hash

from main import AuditLog, User, app, db


def test_audit_logs_route_filters_by_action_and_entity():
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        if admin is not None:
            admin.password_hash = generate_password_hash("Admin@12345")
            db.session.commit()

    with app.app_context():
        db.session.add(AuditLog(
            user_id=1,
            action="created",
            entity="task",
            entity_id=101,
            old_value=None,
            new_value='{"title":"Alpha"}',
            ip_address="127.0.0.1",
            created_at="2026-09-28T10:00:00"
        ))
        db.session.add(AuditLog(
            user_id=1,
            action="updated",
            entity="comment",
            entity_id=202,
            old_value=None,
            new_value='{"body":"Beta"}',
            ip_address="127.0.0.1",
            created_at="2026-09-28T10:05:00"
        ))
        db.session.commit()

    client = app.test_client()
    login = client.post("/login", data={"username": "admin", "password": "Admin@12345"}, follow_redirects=False)
    assert login.status_code in {302, 200}

    response = client.get("/audit-logs?action=created&entity=task")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Alpha" in html
    assert "Beta" not in html
