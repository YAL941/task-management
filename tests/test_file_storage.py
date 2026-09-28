import uuid
from io import BytesIO
from pathlib import Path

import pytest
from werkzeug.datastructures import FileStorage

from main import (
    Attachment,
    AuditLog,
    AuditLogScopeOwner,
    Detail,
    Notification,
    Task,
    User,
    UserPresence,
    UserRole,
    app,
    db,
    storage_path,
    validate_uploads,
    MAX_FILE_SIZE,
)


def test_storage_key_is_task_scoped_and_outside_database():
    key = "tasks/100/report-abc123.pdf"
    path = storage_path(key)
    assert path.name == "report-abc123.pdf"
    assert Path(app.config["UPLOAD_FOLDER"]).resolve() in path.parents
    assert "BLOB" not in {column.type.__class__.__name__.upper() for column in Attachment.__table__.columns}


def test_attachment_upload_requires_authenticated_task_access():
    client = app.test_client()
    response = client.post("/tasks/1/attachments", data={"attachments": (BytesIO(b"file"), "report.pdf")})
    assert response.status_code in {302, 401, 403, 404}


def test_validate_uploads_rejects_oversized_files():
    oversized = FileStorage(stream=BytesIO(b"x" * (MAX_FILE_SIZE + 1)), filename="report.pdf", content_type="application/pdf")
    with pytest.raises(ValueError, match="too large|MAX_FILE_SIZE|file size"):
        validate_uploads([oversized])


def test_validate_uploads_rejects_invalid_file_types():
    invalid = FileStorage(stream=BytesIO(b"<?php echo 1; ?>"), filename="evil.php", content_type="application/x-php")
    with pytest.raises(ValueError, match="Unsupported file type|not allowed|invalid"):
        validate_uploads([invalid])


def test_new_task_form_includes_attachment_input():
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["role"] = "Admin"
    response = client.get("/add_task")
    assert response.status_code == 200
    content = response.get_data(as_text=True)
    assert 'enctype="multipart/form-data"' in content
    assert 'name="attachments"' in content
    assert 'multiple' in content


@pytest.fixture
def protected_task():
    """One task with an attachment that only its owner may download.

    The rows are removed afterwards, so a run against a database that persists
    between runs - SQL Server - leaves nothing behind.
    """
    created = {"users": [], "tasks": [], "attachments": []}
    with app.app_context():
        owner = User(first_name="Owner", last_name="User", username=f"owner_{uuid.uuid4().hex[:8]}", password="secret", role="User")
        guest = User(first_name="Guest", last_name="User", username=f"guest_{uuid.uuid4().hex[:8]}", password="secret", role="User")
        db.session.add_all([owner, guest])
        db.session.flush()
        created["users"].extend([owner.id, guest.id])
        task = Task(title="Protected task", status="Pending", priority="Medium", user_id=owner.id, creator_id=owner.id)
        db.session.add(task)
        db.session.flush()
        created["tasks"].append(task.id)
        key = f"tasks/{task.id}/blocked-{uuid.uuid4().hex}.pdf"
        full_path = storage_path(key)
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_bytes(b"%PDF-1.4\n% test")
        attachment = Attachment(task_id=task.id, uploaded_by=owner.id, filename="blocked.pdf", storage_name=key, mime_type="application/pdf", file_size=full_path.stat().st_size, created_at="2026-01-01T00:00:00")
        db.session.add(attachment)
        db.session.flush()
        created["attachments"].append(attachment.id)
        context = {
            "owner_id": owner.id,
            "guest_id": guest.id,
            "task_id": task.id,
            "attachment_id": attachment.id,
            "storage_path": full_path,
        }
        db.session.commit()
    try:
        yield context
    finally:
        with app.app_context():
            audit_ids = {
                row[0]
                for row in db.session.query(AuditLog.id)
                .filter(AuditLog.user_id.in_(created["users"])).all()
            }
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_ids)).delete(synchronize_session=False)
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.owner_user_id.in_(created["users"])).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
            Notification.query.filter(Notification.user_id.in_(created["users"])).delete(synchronize_session=False)
            UserPresence.query.filter(UserPresence.user_id.in_(created["users"])).delete(synchronize_session=False)
            Attachment.query.filter(Attachment.id.in_(created["attachments"])).delete(synchronize_session=False)
            Detail.query.filter(Detail.task_id.in_(created["tasks"])).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(created["tasks"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(created["users"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(created["users"])).delete(synchronize_session=False)
            db.session.commit()
        context["storage_path"].unlink(missing_ok=True)


def test_unauthorized_download_returns_forbidden(protected_task):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["user_id"] = protected_task["guest_id"]
    response = client.get(f"/attachments/{protected_task['attachment_id']}/download")
    assert response.status_code == 403
