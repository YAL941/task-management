r"""SQL Server coverage for the audit log.

Two layers:

1. Dialect checks that always run and need no server. They compile the exact
   query shapes the audit routes build, so a change that is valid on SQLite but
   rejected or mistranslated by T-SQL fails here.
2. End-to-end tests against a real SQL Server. They only run when
   `TEST_MSSQL_URL` is set (the conftest then points the whole app at that
   server) and only write when `TEST_MSSQL_ALLOW_WRITE=1` is also set, because
   they insert and delete rows. They never drop or truncate anything: the schema
   comes from the app's own `create_all` and teardown deletes only the rows these
   tests created.

Run them with a dedicated, disposable SQL Server database:

    $env:TEST_MSSQL_URL = "mssql+pyodbc://sa:<password>@localhost:1433/TaskHQ_test?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
    $env:TEST_MSSQL_ALLOW_WRITE = "1"
    .\.venv\Scripts\python.exe -m pytest tests/test_mssql_audit_integration.py -q
"""

import json
import os
import uuid
from datetime import date, timedelta

import pytest
from sqlalchemy import or_, select
from sqlalchemy.dialects import mssql
from sqlalchemy.exc import CompileError
from werkzeug.security import generate_password_hash

from main import (
    AuditLog,
    AuditLogScopeOwner,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
    app,
    db,
)

MSSQL_URL = (os.environ.get("TEST_MSSQL_URL") or "").strip()
WRITES_ALLOWED = (os.environ.get("TEST_MSSQL_ALLOW_WRITE") or "").strip() == "1"
TODAY = date.today()

# The order the audit list route always applies before offset/limit.
LIST_ORDER = (AuditLog.created_at.desc(), AuditLog.id.desc())


def _dialect():
    return mssql.dialect()


def _compiled(query, literal_binds=False):
    return str(query.statement.compile(dialect=_dialect(), compile_kwargs={"literal_binds": literal_binds}))


@pytest.fixture
def app_context():
    with app.app_context():
        yield


def test_audit_pagination_compiles_to_a_valid_tsql_window(app_context):
    sql = _compiled(AuditLog.query.order_by(*LIST_ORDER).offset(25).limit(25)).upper()
    # SQLAlchemy renders offset/limit on SQL Server with ROW_NUMBER, which is the
    # form SQL Server accepts without a top-level OFFSET/FETCH clause.
    assert "ROW_NUMBER() OVER (ORDER BY" in sql
    assert "MSSQL_RN >" in sql
    assert "LIMIT" not in sql


def test_first_page_pagination_compiles_to_a_valid_tsql_window(app_context):
    sql = _compiled(AuditLog.query.order_by(*LIST_ORDER).offset(0).limit(25)).upper()
    assert "ROW_NUMBER() OVER (ORDER BY" in sql
    assert "LIMIT" not in sql


def test_pagination_without_order_by_is_rejected_by_the_dialect(app_context):
    # Guard the rule that makes the audit route safe: T-SQL needs a deterministic
    # order, so a future change that drops order_by would fail on SQL Server.
    with pytest.raises(CompileError):
        _compiled(AuditLog.query.offset(25).limit(25))


def test_audit_filters_compile_to_portable_tsql(app_context):
    actor_ids = select(User.id).where(User.username.ilike("%admin%"))
    sql = _compiled(
        AuditLog.query.filter(
            or_(
                AuditLog.action.ilike("%created%"),
                AuditLog.entity.ilike("%task%"),
                AuditLog.new_value.ilike("%value%"),
                AuditLog.old_value.ilike("%value%"),
                AuditLog.user_id.in_(actor_ids),
            ),
            AuditLog.entity_id == 42,
            AuditLog.created_at >= "2026-01-01T00:00:00",
        ),
        literal_binds=True,
    )
    upper = sql.upper()
    # ilike must become LOWER(...) LIKE LOWER(...) rather than ILIKE.
    assert "ILIKE" not in upper
    assert upper.count("LOWER(") >= 6
    # The username search must stay a real subquery, not a joined cartesian scan.
    assert "IN (SELECT USERS.ID" in upper
    assert "FROM USERS" in upper
    # Date windows are compared as the stored ISO strings.
    assert "CREATED_AT >= '2026-01-01T00:00:00'" in upper


def test_scope_visibility_queries_compile_to_tsql(app_context):
    owner_log_ids = select(AuditLogScopeOwner.audit_log_id).where(AuditLogScopeOwner.owner_user_id == 7)
    sql = _compiled(
        AuditLog.query.filter(or_(AuditLog.id.in_(owner_log_ids), AuditLog.scope_team_id.in_([1, 2]))).order_by(*LIST_ORDER)
    ).upper()
    assert "IN (SELECT AUDIT_LOG_SCOPE_OWNERS.AUDIT_LOG_ID" in sql
    assert "ORDER BY" in sql


@pytest.mark.skipif(
    not MSSQL_URL or not WRITES_ALLOWED,
    reason="Set both TEST_MSSQL_URL (a dedicated, disposable SQL Server database) and TEST_MSSQL_ALLOW_WRITE=1 to run this end-to-end test.",
)
def test_audit_flow_against_a_real_sql_server():
    with app.app_context():
        assert db.engine.dialect.name == "mssql", "TEST_MSSQL_URL did not point the app at SQL Server"
        db.create_all()

        marker = f"MSSQL_{uuid.uuid4().hex[:8]}"

        def make_user(label, permission_keys, scope):
            user = User(
                first_name="MsSql",
                last_name=label,
                username=f"mssql_{label.lower()}_{uuid.uuid4().hex[:6]}",
                password_hash=generate_password_hash("temporary-test-password"),
                role="User",
                created_at=f"{TODAY.isoformat()}T00:00:00",
            )
            db.session.add(user)
            db.session.flush()
            for key in permission_keys:
                grant = Permission.query.filter_by(key=key).first()
                assert grant is not None, key
                role = Role(
                    name=f"mssql_{label}_{key.replace('.', '_')}_{uuid.uuid4().hex[:6]}",
                    description="MSSQL integration role",
                    is_system=False,
                    created_at=f"{TODAY.isoformat()}T00:00:00",
                )
                db.session.add(role)
                db.session.flush()
                db.session.add(RolePermission(role_id=role.id, permission_id=grant.id, scope=scope))
                db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at=f"{TODAY.isoformat()}T00:00:00"))
            return user

        any_viewer = make_user("Any", ("audit_logs.view", "audit_logs.export", "permissions.manage"), "ANY")
        own_viewer = make_user("Own", ("audit_logs.view",), "OWN")

        owned = AuditLog(
            user_id=own_viewer.id,
            action="status_changed",
            entity="task",
            entity_id=9001,
            old_value=f'{{"status": "Pending", "marker": "{marker}"}}',
            new_value=f'{{"status": "In Progress", "marker": "{marker}"}}',
            ip_address="10.0.0.9",
            created_at=f"{TODAY.isoformat()}T09:00:00",
        )
        foreign = AuditLog(
            user_id=any_viewer.id,
            action="created",
            entity="team",
            entity_id=9002,
            new_value=f'{{"marker": "{marker}", "who": "foreign"}}',
            created_at=f"{TODAY.isoformat()}T09:05:00",
        )
        older = AuditLog(
            user_id=any_viewer.id,
            action="created",
            entity="task",
            entity_id=9003,
            new_value=f'{{"marker": "{marker}", "who": "older"}}',
            created_at=f"{(TODAY - timedelta(days=10)).isoformat()}T09:00:00",
        )
        db.session.add_all([owned, foreign, older])
        db.session.flush()
        db.session.add(AuditLogScopeOwner(audit_log_id=owned.id, owner_user_id=own_viewer.id))
        db.session.commit()

        created = {
            "user_ids": [any_viewer.id, own_viewer.id],
            "any_username": any_viewer.username,
            "role_ids": [row.id for row in Role.query.filter(Role.name.like("mssql_%")).all()],
            "log_ids": [owned.id, foreign.id, older.id],
            "owned_id": owned.id,
            "foreign_id": foreign.id,
        }

    try:
        any_client = _client(created["user_ids"][0])
        own_client = _client(created["user_ids"][1])

        # Scope: ANY sees every marker, OWN sees only the row it owns.
        any_body = any_client.get(f"/audit-logs?per_page=100&search={marker}").get_data(as_text=True)
        assert marker in any_body
        assert all(str(entity_id) in any_body for entity_id in (9001, 9002, 9003))

        own_body = own_client.get(f"/audit-logs?per_page=100&search={marker}").get_data(as_text=True)
        assert "9001" in own_body
        assert "9002" not in own_body
        assert "9003" not in own_body

        # Username search through the users subquery.
        assert "9002" in any_client.get(f"/audit-logs?search={created['any_username']}").get_data(as_text=True)

        # Exact entity id filter.
        entity_body = any_client.get("/audit-logs?entity_id=9002&per_page=100").get_data(as_text=True)
        assert "9002" in entity_body
        assert "9001" not in entity_body

        # Ready-made relative period.
        today_body = any_client.get("/audit-logs?period=today&per_page=100").get_data(as_text=True)
        assert "9001" in today_body
        assert "9003" not in today_body
        seven_day_body = any_client.get("/audit-logs?period=7d&per_page=100").get_data(as_text=True)
        assert "9001" in seven_day_body
        assert "9003" not in seven_day_body

        # Pagination across page boundaries on the same dialect, restricted to
        # this test's own rows so the page contents are deterministic.
        first_page = any_client.get(f"/audit-logs?per_page=1&page=1&sort=id&order=asc&search={marker}").get_data(as_text=True)
        second_page = any_client.get(f"/audit-logs?per_page=1&page=2&sort=id&order=asc&search={marker}").get_data(as_text=True)
        assert "9001" in first_page
        assert "9001" not in second_page
        assert "9002" in second_page

        # Out-of-scope detail stays hidden.
        assert own_client.get(f"/audit-logs/{created['foreign_id']}").status_code == 404

        # Export respects the same scope and produces rows.
        csv_body = any_client.get("/export/audit_logs.csv")
        assert csv_body.status_code == 200
        assert marker.encode("utf-8") in csv_body.data
        scoped_csv = own_client.get("/export/audit_logs.csv")
        assert scoped_csv.status_code == 200
        assert b"9002" not in scoped_csv.data
    finally:
        with app.app_context():
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(created["log_ids"])).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(created["log_ids"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(created["user_ids"])).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["role_ids"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["role_ids"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(created["user_ids"])).delete(synchronize_session=False)
            db.session.commit()


def _client(user_id):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "mssql-user"
        session["role"] = "User"
    return client
