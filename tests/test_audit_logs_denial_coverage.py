"""Explicit coverage for denied write attempts and out-of-scope audit access.

Every test asserts the HTTP outcome *and* the specific reason code that must be
written to the audit log, so a silently dropped denial fails the test.
"""

import json
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import AuditLog, AuditLogScopeOwner, Permission, Role, RolePermission, Task, User, UserRole, app, db

CSRF = "coverage-csrf-token"


def _denial_reasons():
    with app.app_context():
        rows = AuditLog.query.filter(AuditLog.action == "access_denied").order_by(AuditLog.id.desc()).limit(200).all()
        reasons = {}
        for row in rows:
            payload = json.loads(row.new_value or "{}")
            metadata = payload.get("_audit", {}) if isinstance(payload, dict) else {}
            reason = metadata.get("reason")
            if reason and reason not in reasons:
                reasons[reason] = {"id": row.id, "entity": row.entity, "entity_id": row.entity_id, "path": payload.get("path")}
        return reasons


@pytest.fixture
def denial_scenario():
    created = {"users": [], "roles": [], "tasks": [], "logs": []}
    with app.app_context():
        permission = Permission.query.filter_by(key="audit_logs.view").first()
        assert permission is not None

        def make_user(label, permission_keys=("audit_logs.view",), scope="ANY"):
            user = User(
                first_name="Coverage",
                last_name=label,
                username=f"coverage_{label.lower()}_{uuid4().hex[:6]}",
                password_hash=generate_password_hash("temporary-test-password"),
                role="User",
                created_at="2026-09-28T12:00:00",
            )
            db.session.add(user)
            db.session.flush()
            created["users"].append(user.id)
            for key in permission_keys:
                grant = Permission.query.filter_by(key=key).first()
                assert grant is not None, key
                role = Role(
                    name=f"coverage_{label}_{key.replace('.', '_')}_{uuid4().hex[:6]}",
                    description="Audit denial coverage role",
                    is_system=False,
                    created_at="2026-09-28T12:00:00",
                )
                db.session.add(role)
                db.session.flush()
                created["roles"].append(role.id)
                db.session.add(RolePermission(role_id=role.id, permission_id=grant.id, scope=scope))
                db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at="2026-09-28T12:00:00"))
            return user

        owner = make_user("Owner", ("audit_logs.view", "tasks.view", "tasks.edit_own", "comments.view", "settings.view"), scope="OWN")
        outsider = make_user("Outsider", ("audit_logs.view", "tasks.view"), scope="ANY")

        owned_task = Task(title="Coverage owned task", status="Pending", priority="Medium", creator_id=owner.id, user_id=owner.id)
        foreign_task = Task(title="Coverage foreign task", status="Pending", priority="Medium", creator_id=outsider.id, user_id=outsider.id)
        db.session.add_all([owned_task, foreign_task])
        db.session.flush()
        created["tasks"].extend([owned_task.id, foreign_task.id])
        db.session.commit()

        payload = {
            "owner_id": owner.id,
            "outsider_id": outsider.id,
            "owned_task_id": owned_task.id,
            "foreign_task_id": foreign_task.id,
        }

    try:
        yield payload
    finally:
        with app.app_context():
            audit_ids = {
                audit_log_id for (audit_log_id,) in db.session.query(AuditLog.id)
                .filter(AuditLog.user_id.in_(created["users"])).all()
            }
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(created["tasks"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(created["users"])).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(created["users"])).delete(synchronize_session=False)
            db.session.commit()


def _client(user_id):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "coverage-user"
        session["role"] = "User"
        session["csrf_token"] = CSRF
    return client


def test_edit_attempt_on_foreign_task_is_denied_and_recorded(denial_scenario):
    client = _client(denial_scenario["owner_id"])
    response = client.post(
        f"/edit_task/{denial_scenario['foreign_task_id']}",
        data={"csrf_token": CSRF, "title": "Hijacked", "priority": "High", "due_date": "", "description": ""},
        follow_redirects=False,
    )
    assert response.status_code == 302

    with app.app_context():
        task = db.session.get(Task, denial_scenario["foreign_task_id"])
        assert task.title == "Coverage foreign task"
        assert not AuditLog.query.filter_by(
            entity="task", entity_id=denial_scenario["foreign_task_id"], action="updated"
        ).count()

    denial = _denial_reasons().get("task_edit_forbidden")
    assert denial is not None, "edit denial was not written to the audit log"
    assert denial["entity"] == "task"
    assert denial["entity_id"] == denial_scenario["foreign_task_id"]


def test_delete_attempt_on_foreign_task_is_denied_and_recorded(denial_scenario):
    client = _client(denial_scenario["owner_id"])
    response = client.post(
        f"/delete_task/{denial_scenario['foreign_task_id']}",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert response.status_code == 302

    with app.app_context():
        assert db.session.get(Task, denial_scenario["foreign_task_id"]) is not None
        assert not AuditLog.query.filter_by(
            entity="task", entity_id=denial_scenario["foreign_task_id"], action="deleted"
        ).count()

    denial = _denial_reasons().get("task_delete_forbidden")
    assert denial is not None, "delete denial was not written to the audit log"
    assert denial["entity_id"] == denial_scenario["foreign_task_id"]


def test_status_change_attempt_on_foreign_task_is_denied(denial_scenario):
    client = _client(denial_scenario["owner_id"])
    response = client.post(
        f"/update_task_status/{denial_scenario['foreign_task_id']}/Completed",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert response.status_code == 302

    with app.app_context():
        assert db.session.get(Task, denial_scenario["foreign_task_id"]).status == "Pending"
        assert not AuditLog.query.filter_by(entity="task", action="status_changed").count()

    assert _denial_reasons().get("task_status_change_forbidden") is not None


def test_comment_attempt_on_foreign_task_is_denied(denial_scenario):
    client = _client(denial_scenario["owner_id"])
    response = client.post(
        f"/tasks/{denial_scenario['foreign_task_id']}/comments",
        data={"csrf_token": CSRF, "body": "not allowed"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    with app.app_context():
        from main import Comment

        assert not Comment.query.filter_by(task_id=denial_scenario["foreign_task_id"]).count()
        assert not AuditLog.query.filter_by(action="COMMENT_CREATED").count()

    assert _denial_reasons().get("comment_view_forbidden") is not None


def test_attachment_access_attempt_on_foreign_task_is_denied(denial_scenario):
    client = _client(denial_scenario["owner_id"])
    response = client.post(
        f"/tasks/{denial_scenario['foreign_task_id']}/attachments",
        data={"csrf_token": CSRF, "attachments": (b"data", "probe.pdf")},
        content_type="multipart/form-data",
        follow_redirects=False,
    )
    assert response.status_code == 403

    assert _denial_reasons().get("attachment_upload_forbidden") is not None


def test_view_permission_denial_is_recorded_with_specific_reason(denial_scenario):
    client = _client(denial_scenario["outsider_id"])
    denied = client.get("/reports", follow_redirects=False)
    assert denied.status_code == 302

    denial = _denial_reasons().get("reports_view_forbidden")
    assert denial is not None, "reports denial was not recorded with its own reason code"


def test_audit_log_detail_outside_scope_is_not_readable(denial_scenario):
    with app.app_context():
        outsider_id = denial_scenario["outsider_id"]
        log = AuditLog(
            user_id=1,
            action="created",
            entity="task",
            entity_id=denial_scenario["foreign_task_id"],
            new_value='{"probe":"OUT_OF_SCOPE_LOG"}',
            created_at="2026-09-28T12:00:00",
        )
        db.session.add(log)
        db.session.flush()
        out_of_scope_id = log.id
        db.session.commit()

    client = _client(denial_scenario["owner_id"])
    detail = client.get(f"/audit-logs/{out_of_scope_id}")
    assert detail.status_code == 404
    assert "OUT_OF_SCOPE_LOG" not in detail.get_data(as_text=True)

    listing = client.get("/audit-logs")
    assert listing.status_code == 200
    assert "OUT_OF_SCOPE_LOG" not in listing.get_data(as_text=True)

    with app.app_context():
        db.session.delete(db.session.get(AuditLog, out_of_scope_id))
        db.session.commit()
