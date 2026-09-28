import json

from werkzeug.security import generate_password_hash

from main import AuditEventService, AuditLog, User, app, db


def test_audit_service_formats_outcome_without_schema_columns():
    with app.app_context():
        with app.test_request_context("/audit-probe"):
            log = AuditEventService.record(
                "ACCESS_DENIED",
                "task",
                404,
                new_value={"path": "/audit-probe"},
                result="denied",
                reason="missing_permission",
                actor_from_session=False,
            )
            stored = json.loads(log.new_value)
            assert stored["_audit"] == {"result": "denied", "reason": "missing_permission"}
            assert "password" not in log.new_value.lower()
            assert "token" not in log.new_value.lower()
            assert "result" not in {column.name for column in AuditLog.__table__.columns}
            assert "reason" not in {column.name for column in AuditLog.__table__.columns}
            db.session.rollback()


def test_audit_logs_route_filters_by_action_and_entity():
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        if admin is not None:
            admin.password_hash = generate_password_hash("Admin@12345")
            db.session.commit()

    with app.app_context():
        rows = [AuditLog(
            user_id=1,
            action="created",
            entity="task",
            entity_id=101,
            old_value=None,
            new_value='{"title":"Alpha"}',
            ip_address="127.0.0.1",
            created_at="2026-09-28T10:00:00"
        ), AuditLog(
            user_id=1,
            action="updated",
            entity="comment",
            entity_id=202,
            old_value=None,
            new_value='{"body":"Beta"}',
            ip_address="127.0.0.1",
            created_at="2026-09-28T10:05:00"
        ), AuditLog(
            user_id=1,
            action="access_denied",
            entity="request",
            old_value=None,
            new_value='{"result":"denied","reason":"filter-probe"}',
            ip_address="127.0.0.1",
            created_at="2026-09-28T10:10:00"
        ), AuditLog(
            user_id=1,
            action="ATTACHMENT_UPLOAD_FAILED",
            entity="task",
            entity_id=303,
            old_value=None,
            new_value='{"_audit":{"result":"failed","reason":"validation_failed"}}',
            ip_address="127.0.0.1",
            created_at="2026-09-28T10:15:00"
        )]
        db.session.add_all(rows)
        db.session.commit()
        row_ids = [row.id for row in rows]

    client = app.test_client()
    login = client.post("/login", data={"username": "admin", "password": "Admin@12345"}, follow_redirects=False)
    assert login.status_code in {302, 200}

    try:
        response = client.get("/audit-logs?action=created&entity=task")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Alpha" in html
        assert "Beta" not in html

        filtered = client.get("/audit-logs?user_id=1&result=success&date_from=2026-09-28&date_to=2026-09-28")
        filtered_html = filtered.get_data(as_text=True)
        assert "Alpha" in filtered_html and "Beta" in filtered_html
        assert "filter-probe" not in filtered_html

        denied = client.get("/audit-logs?result=denied")
        assert "filter-probe" in denied.get_data(as_text=True)

        failed = client.get("/audit-logs?result=failed")
        assert "ATTACHMENT_UPLOAD_FAILED" in failed.get_data(as_text=True)
        assert "filter-probe" not in failed.get_data(as_text=True)

        detail = client.get(f"/audit-logs/{row_ids[0]}")
        assert detail.status_code == 200
        assert "Alpha" in detail.get_data(as_text=True)
    finally:
        with app.app_context():
            AuditLog.query.filter(AuditLog.id.in_(row_ids)).delete(synchronize_session=False)
            db.session.commit()
