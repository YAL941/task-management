"""Coverage for the audit-log export: scope, permission, content, and its own record."""

import csv
import io
import json
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import AuditLog, AuditLogScopeOwner, Permission, Role, RolePermission, User, UserRole, app, db


def _make_user(label, permission_keys, scope):
    user = User(
        first_name="Export",
        last_name=label,
        username=f"export_{label.lower()}_{uuid4().hex[:6]}",
        password_hash=generate_password_hash("temporary-test-password"),
        role="User",
        created_at="2026-09-28T12:00:00",
    )
    db.session.add(user)
    db.session.flush()
    for key in permission_keys:
        grant = Permission.query.filter_by(key=key).first()
        assert grant is not None, key
        role = Role(
            name=f"export_{label}_{key.replace('.', '_')}_{uuid4().hex[:6]}",
            description="Audit export test role",
            is_system=False,
            created_at="2026-09-28T12:00:00",
        )
        db.session.add(role)
        db.session.flush()
        db.session.add(RolePermission(role_id=role.id, permission_id=grant.id, scope=scope))
        db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at="2026-09-28T12:00:00"))
    return user


@pytest.fixture
def export_scenario():
    created = {"users": [], "roles": [], "logs": []}
    with app.app_context():
        exporter = _make_user("Exporter", ("audit_logs.view", "audit_logs.export", "permissions.manage"), "ANY")
        own_scope_exporter = _make_user("Scoped", ("audit_logs.view", "audit_logs.export", "permissions.manage"), "OWN")
        no_export = _make_user("NoExport", ("audit_logs.view", "permissions.manage"), "ANY")
        created["users"].extend([exporter.id, own_scope_exporter.id, no_export.id])

        visible = AuditLog(
            user_id=own_scope_exporter.id,
            action="status_changed",
            entity="task",
            entity_id=77,
            old_value='{"status": "Pending"}',
            new_value='{"status": "In Progress"}',
            ip_address="10.0.0.7",
            created_at="2026-09-28T11:00:00",
        )
        foreign = AuditLog(
            user_id=exporter.id,
            action="created",
            entity="team",
            entity_id=5,
            new_value='{"probe":"EXPORT_FOREIGN_ROW"}',
            created_at="2026-09-28T11:05:00",
        )
        db.session.add_all([visible, foreign])
        db.session.flush()
        created["logs"].extend([visible.id, foreign.id])
        # OWN scope visibility is driven by audit_log_scope_owners, so only the
        # first row is owned by the scoped exporter.
        db.session.add(AuditLogScopeOwner(audit_log_id=visible.id, owner_user_id=own_scope_exporter.id))
        db.session.commit()

        payload = {
            "exporter_id": exporter.id,
            "scoped_id": own_scope_exporter.id,
            "no_export_id": no_export.id,
            "visible_log_id": visible.id,
            "foreign_log_id": foreign.id,
        }

    try:
        yield payload
    finally:
        with app.app_context():
            log_ids = {
                log_id for (log_id,) in db.session.query(AuditLog.id)
                .filter(AuditLog.user_id.in_(created["users"])).all()
            }
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(log_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(log_ids | set(created["logs"]))).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(created["users"])).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(created["users"])).delete(synchronize_session=False)
            db.session.commit()


def _client(user_id):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "export-user"
        session["role"] = "User"
    return client


def test_csv_export_contains_readable_rows_and_is_recorded(export_scenario):
    client = _client(export_scenario["exporter_id"])
    response = client.get("/export/audit_logs.csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["Content-Type"]

    body = response.data.decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(body)))
    by_id = {int(row["id"]): row for row in rows}
    assert export_scenario["visible_log_id"] in by_id
    assert export_scenario["foreign_log_id"] in by_id

    changed = by_id[export_scenario["visible_log_id"]]
    assert changed["action"] == "status_changed"
    assert changed["entity"] == "task"
    assert changed["result"] == "success"
    assert "changed the status of task #77" in changed["message"]
    assert "_audit" not in changed["message"]

    with app.app_context():
        export_log = AuditLog.query.filter_by(action="exported", entity="audit_logs").order_by(AuditLog.id.desc()).first()
        assert export_log is not None, "the export itself was not recorded"
        payload = json.loads(export_log.new_value)
        assert payload["format"] == "csv"
        assert payload["row_count"] == len(rows)
        assert payload["_audit"]["result"] == "success"


def test_export_is_limited_to_the_viewer_scope(export_scenario):
    client = _client(export_scenario["scoped_id"])
    body = client.get("/export/audit_logs.csv").data.decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(body)))
    identifiers = {int(row["id"]) for row in rows}

    assert export_scenario["visible_log_id"] in identifiers
    assert export_scenario["foreign_log_id"] not in identifiers
    assert all("EXPORT_FOREIGN_ROW" not in row["new_value"] for row in rows)


def test_export_requires_the_export_permission(export_scenario):
    client = _client(export_scenario["no_export_id"])
    response = client.get("/export/audit_logs.csv")
    assert response.status_code == 403
    assert b"not authorized" in response.data

    with app.app_context():
        denial = AuditLog.query.filter(
            AuditLog.action == "access_denied",
            AuditLog.new_value.like("%audit_logs_export_forbidden%"),
        ).order_by(AuditLog.id.desc()).first()
        assert denial is not None, "the refused export was not recorded"
        assert denial.entity == "audit_logs"


def test_export_links_are_hidden_without_permission(export_scenario):
    with_permission = _client(export_scenario["exporter_id"]).get("/audit-logs").get_data(as_text=True)
    assert "/export/audit_logs.csv" in with_permission

    without_permission = _client(export_scenario["no_export_id"]).get("/audit-logs").get_data(as_text=True)
    assert "/export/audit_logs.csv" not in without_permission


def test_unsupported_format_still_rejected(export_scenario):
    client = _client(export_scenario["exporter_id"])
    assert client.get("/export/audit_logs.xml").status_code == 400


def test_xlsx_export_contains_the_readable_columns(export_scenario):
    openpyxl = pytest.importorskip("openpyxl")
    client = _client(export_scenario["exporter_id"])
    response = client.get("/export/audit_logs.xlsx")
    assert response.status_code == 200
    assert "spreadsheetml" in response.headers["Content-Type"]

    workbook = openpyxl.load_workbook(io.BytesIO(response.data))
    sheet = workbook.active
    headers = [cell.value for cell in next(sheet.iter_rows(min_row=1, max_row=1))]
    assert headers[:4] == ["id", "created_at", "actor", "action"]
    assert "message" in headers

    rows = {row[headers.index("id")]: dict(zip(headers, row)) for row in sheet.iter_rows(min_row=2, values_only=True)}
    changed = rows[export_scenario["visible_log_id"]]
    assert changed["entity"] == "task"
    assert "changed the status of task #77" in changed["message"]


def test_pdf_export_is_a_readable_document(export_scenario):
    pytest.importorskip("reportlab")
    client = _client(export_scenario["exporter_id"])
    response = client.get("/export/audit_logs.pdf")
    assert response.status_code == 200
    assert response.data.startswith(b"%PDF")


def test_every_supported_format_records_its_own_row_count(export_scenario):
    client = _client(export_scenario["exporter_id"])
    for file_format in ("csv", "xlsx", "pdf"):
        assert client.get(f"/export/audit_logs.{file_format}").status_code == 200

    with app.app_context():
        records = AuditLog.query.filter_by(action="exported", entity="audit_logs").order_by(AuditLog.id.asc()).all()
        formats = [json.loads(record.new_value)["format"] for record in records]
        assert formats == ["csv", "xlsx", "pdf"]
        for record in records:
            payload = json.loads(record.new_value)
            assert payload["row_count"] > 0
