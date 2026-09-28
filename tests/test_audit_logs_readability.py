"""Coverage for the readable audit message, structured changes, and resource links."""

from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    Attachment,
    AuditEventService,
    AuditLog,
    Comment,
    Permission,
    Role,
    RolePermission,
    Task,
    User,
    UserRole,
    app,
    audit_changes,
    audit_message,
    audit_resource_url,
    db,
    url_for,
)


def _viewer(label, permissions=("audit_logs.view",), scope="ANY", role_names=()):
    user = User(
        first_name="Detail",
        last_name=label,
        username=f"detail_{label.lower()}_{uuid4().hex[:6]}",
        password_hash=generate_password_hash("temporary-test-password"),
        role="User",
        created_at="2026-09-28T12:00:00",
    )
    db.session.add(user)
    db.session.flush()
    for permission_key in permissions:
        permission = Permission.query.filter_by(key=permission_key).first()
        assert permission is not None, permission_key
        role_name = f"detail_{label}_{permission_key.replace('.', '_')}_{uuid4().hex[:6]}"
        role = Role(name=role_name, description="Audit detail test role", is_system=False, created_at="2026-09-28T12:00:00")
        db.session.add(role)
        db.session.flush()
        db.session.add(RolePermission(role_id=role.id, permission_id=permission.id, scope=scope))
        db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at="2026-09-28T12:00:00"))
    for role_name in role_names:
        role = Role(name=role_name, description="Audit detail system role", is_system=False, created_at="2026-09-28T12:00:00")
        db.session.add(role)
        db.session.flush()
        db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at="2026-09-28T12:00:00"))
    return user


@pytest.fixture
def detail_scenario():
    created = {"users": [], "roles": [], "logs": [], "tasks": [], "comments": [], "attachments": []}
    with app.app_context():
        viewer = _viewer("Owner", permissions=("audit_logs.view", "tasks.view", "comments.view", "attachments.view"), scope="ANY")
        limited = _viewer("Limited", permissions=("audit_logs.view",), scope="ANY")
        created["users"].extend([viewer.id, limited.id])

        task = Task(title="Detail task", status="Pending", priority="Medium", creator_id=viewer.id, user_id=viewer.id)
        db.session.add(task)
        db.session.flush()
        created["tasks"].append(task.id)

        comment = Comment(task_id=task.id, user_id=viewer.id, body="Detail comment", created_at="2026-09-28T12:00:00")
        db.session.add(comment)
        db.session.flush()
        created["comments"].append(comment.id)

        attachment = Attachment(
            task_id=task.id,
            uploaded_by=viewer.id,
            filename="detail.pdf",
            storage_name=f"detail/{uuid4().hex}.pdf",
            mime_type="application/pdf",
            file_size=1,
            created_at="2026-09-28T12:00:00",
        )
        db.session.add(attachment)
        db.session.flush()
        created["attachments"].append(attachment.id)

        with app.test_request_context("/audit-detail-probe"):
            status_log = AuditEventService.record(
                "status_changed",
                "task",
                task.id,
                old_value={"status": "Pending"},
                new_value={"status": "In Progress"},
                actor_user_id=viewer.id,
                actor_from_session=False,
            )
            created["logs"].append(status_log.id)
        db.session.commit()

        payload = {
            "viewer_id": viewer.id,
            "limited_id": limited.id,
            "task_id": task.id,
            "comment_id": comment.id,
            "attachment_id": attachment.id,
            "status_log_id": status_log.id,
        }

    try:
        yield payload
    finally:
        with app.app_context():
            AuditLog.query.filter(AuditLog.id.in_(created["logs"])).delete(synchronize_session=False)
            Attachment.query.filter(Attachment.id.in_(created["attachments"])).delete(synchronize_session=False)
            Comment.query.filter(Comment.id.in_(created["comments"])).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(created["tasks"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(created["users"])).delete(synchronize_session=False)
            for role in Role.query.filter(Role.name.like("detail_%")).all():
                RolePermission.query.filter(RolePermission.role_id == role.id).delete(synchronize_session=False)
                db.session.delete(role)
            User.query.filter(User.id.in_(created["users"])).delete(synchronize_session=False)
            db.session.commit()


def test_message_is_readable_and_hides_internal_metadata(detail_scenario):
    with app.app_context():
        log = db.session.get(AuditLog, detail_scenario["status_log_id"])
        message = audit_message(log, "admin")
        assert message == f"admin changed the status of task #{detail_scenario['task_id']}"
        assert "_audit" not in message
        changes = audit_changes(log)
        assert changes == [{"field": "status", "before": "Pending", "after": "In Progress"}]


def test_denied_message_reports_reason_and_path():
    with app.app_context():
        log = AuditLog(
            user_id=None,
            action="access_denied",
            entity="request",
            entity_id=None,
            new_value='{"path":"/edit_task/5","_audit":{"result":"denied","reason":"task_edit_forbidden"}}',
            created_at="2026-09-28T12:00:00",
        )
        db.session.add(log)
        db.session.flush()
        try:
            assert audit_message(log, "manager") == "manager was denied access to /edit_task/5"
            assert audit_changes(log) == [{"field": "path", "before": None, "after": "/edit_task/5"}]
        finally:
            db.session.delete(log)
            db.session.commit()


def test_resource_links_cover_more_entity_types(detail_scenario):
    with app.test_request_context("/audit-detail-probe"):
        viewer_id = detail_scenario["viewer_id"]
        task_log = AuditLog(action="updated", entity="task", entity_id=detail_scenario["task_id"], created_at="2026-09-28T12:00:00")
        comment_log = AuditLog(action="created", entity="comment", entity_id=detail_scenario["comment_id"], created_at="2026-09-28T12:00:00")
        attachment_log = AuditLog(action="ATTACHMENT_UPLOADED", entity="attachment", entity_id=detail_scenario["attachment_id"], created_at="2026-09-28T12:00:00")
        role_log = AuditLog(action="ROLE_UPDATED", entity="role", entity_id=7, created_at="2026-09-28T12:00:00")
        automation_log = AuditLog(action="toggled", entity="automation_rule", entity_id=3, created_at="2026-09-28T12:00:00")
        db.session.add_all([task_log, comment_log, attachment_log, role_log, automation_log])
        db.session.commit()

        assert audit_resource_url(task_log, viewer_id) == url_for("task_view", task_id=detail_scenario["task_id"])
        assert audit_resource_url(comment_log, viewer_id) == url_for("task_comments", id=detail_scenario["task_id"])
        assert audit_resource_url(attachment_log, viewer_id) == url_for("task_view", task_id=detail_scenario["task_id"])
        assert audit_resource_url(role_log, viewer_id) is None
        assert audit_resource_url(automation_log, viewer_id) is None

        role_viewer = _viewer("Roles", permissions=("audit_logs.view", "roles.view", "permissions.manage"), scope="ANY")
        assert audit_resource_url(role_log, role_viewer.id) == url_for("roles")
        assert audit_resource_url(automation_log, role_viewer.id) == url_for("automation")

        UserRole.query.filter(UserRole.user_id == role_viewer.id).delete(synchronize_session=False)
        db.session.delete(task_log)
        db.session.delete(comment_log)
        db.session.delete(attachment_log)
        db.session.delete(role_log)
        db.session.delete(automation_log)
        db.session.delete(role_viewer)
        db.session.commit()


def test_detail_page_renders_message_and_change_table(detail_scenario):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = detail_scenario["viewer_id"]
        session["username"] = "detail-viewer"
        session["role"] = "User"

    detail = client.get(f"/audit-logs/{detail_scenario['status_log_id']}")
    assert detail.status_code == 200
    html = detail.get_data(as_text=True)
    assert "What happened" in html
    assert f"changed the status of task #{detail_scenario['task_id']}" in html
    assert "<td class=\"strong-cell\">status</td>" in html
    assert "Pending" in html and "In Progress" in html
    assert "No field-level changes" not in html

    listing = client.get("/audit-logs?per_page=100")
    listing_html = listing.get_data(as_text=True)
    assert f"changed the status of task #{detail_scenario['task_id']}" in listing_html
    assert "<strong>status:</strong> Pending &rarr; In Progress" in listing_html
    assert '{"status":"In Progress"}' not in listing_html
