from io import BytesIO
from pathlib import Path

from main import Attachment, Task, User, app, db, storage_path


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
