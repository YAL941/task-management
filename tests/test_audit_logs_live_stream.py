"""Coverage for the live audit stream delivered to an open /audit-logs page.

`publish_committed_audit_logs` runs synchronously after the commit on SQLite (the
conftest suite database) and from a background task on every other dialect, so on
SQL Server the packet arrives just after the request returns. The waits below
cover both, and the negative case drains for the full grace window so a late
arrival still fails the test.
"""

import time
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    AuditEventService,
    AuditLog,
    Permission,
    RealtimeEvent,
    Role,
    RolePermission,
    User,
    UserPresence,
    UserRole,
    app,
    db,
    realtime_token,
    socketio,
)

# Rows this module creates, so the autouse fixture can remove exactly those.
_CREATED = {"users": [], "roles": [], "logs": []}

# The app publishes a committed audit row inline on SQLite but from a background
# task on every other dialect, so on SQL Server the packet lands shortly after
# the request returns rather than inside it. The wait keeps the assertions about
# *who* the event reached valid on both backends.
PUBLISH_GRACE_SECONDS = 5.0


def wait_for_audit_packets(client, timeout=PUBLISH_GRACE_SECONDS):
    deadline = time.monotonic() + timeout
    while True:
        packets = [packet for packet in client.get_received() if packet["name"] == "audit_log_event"]
        if packets or time.monotonic() >= deadline:
            return packets
        time.sleep(0.05)


def wait_for_no_audit_packets(client, timeout=PUBLISH_GRACE_SECONDS):
    """Drain for the whole grace window, so a late arrival still fails the test."""
    deadline = time.monotonic() + timeout
    packets = []
    while time.monotonic() < deadline:
        packets.extend(packet for packet in client.get_received() if packet["name"] == "audit_log_event")
        time.sleep(0.05)
    return packets


def _session_client(user_id, username="live-test"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = username
        session["role"] = "User"
    return client


def _any_scope_viewer():
    """A user whose only audit grant is `audit_logs.view` at ANY scope."""
    with app.app_context():
        permission = Permission.query.filter_by(key="audit_logs.view").first()
        assert permission is not None
        user = User(
            first_name="Live",
            last_name="Viewer",
            username=f"live_viewer_{uuid4().hex[:8]}",
            password_hash=generate_password_hash("temporary-test-password"),
            role="User",
            created_at="2026-09-28T12:00:00",
        )
        db.session.add(user)
        db.session.flush()
        role = Role(
            name=f"live_viewer_role_{uuid4().hex[:8]}",
            description="Live audit stream test role",
            is_system=False,
            created_at="2026-09-28T12:00:00",
        )
        db.session.add(role)
        db.session.flush()
        db.session.add(RolePermission(role_id=role.id, permission_id=permission.id, scope="ANY"))
        db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at="2026-09-28T12:00:00"))
        db.session.commit()
        _CREATED["users"].append(user.id)
        _CREATED["roles"].append(role.id)
        return user.id


@pytest.fixture(autouse=True)
def _cleanup_created_rows():
    yield
    with app.app_context():
        db.session.rollback()
        log_ids = list(_CREATED["logs"])
        for log_id in log_ids:
            RealtimeEvent.query.filter(RealtimeEvent.event_id == f"audit-{log_id}").delete(synchronize_session=False)
        RealtimeEvent.query.filter(RealtimeEvent.actor_id.in_(_CREATED["users"])).delete(synchronize_session=False)
        UserPresence.query.filter(UserPresence.user_id.in_(_CREATED["users"])).delete(synchronize_session=False)
        AuditLog.query.filter(AuditLog.user_id.in_(_CREATED["users"])).delete(synchronize_session=False)
        AuditLog.query.filter(AuditLog.id.in_(log_ids)).delete(synchronize_session=False)
        UserRole.query.filter(UserRole.user_id.in_(_CREATED["users"])).delete(synchronize_session=False)
        RolePermission.query.filter(RolePermission.role_id.in_(_CREATED["roles"])).delete(synchronize_session=False)
        Role.query.filter(Role.id.in_(_CREATED["roles"])).delete(synchronize_session=False)
        User.query.filter(User.id.in_(_CREATED["users"])).delete(synchronize_session=False)
        db.session.commit()
        _CREATED["users"].clear()
        _CREATED["roles"].clear()
        _CREATED["logs"].clear()


def test_audit_page_enables_live_insert_only_without_filters_or_paging():
    viewer_id = _any_scope_viewer()
    client = _session_client(viewer_id)

    unfiltered = client.get("/audit-logs")
    assert unfiltered.status_code == 200
    body = unfiltered.get_data(as_text=True)
    assert 'data-audit-live-insert="true"' in body
    assert 'data-audit-rows' in body
    assert 'data-audit-detail-base="/audit-logs"' in body
    assert 'data-audit-row-limit="25"' in body
    assert 'data-audit-has-nav="false"' in body

    filtered = client.get("/audit-logs?result=denied").get_data(as_text=True)
    assert 'data-audit-live-insert="false"' in filtered

    resorted = client.get("/audit-logs?sort=action&order=asc").get_data(as_text=True)
    assert 'data-audit-live-insert="false"' in resorted


def test_second_page_disables_live_insert_without_other_differences():
    viewer_id = _any_scope_viewer()
    with app.app_context():
        for index in range(2):
            db.session.add(AuditLog(
                user_id=viewer_id,
                action="created",
                entity="task",
                entity_id=2000 + index,
                new_value=f'{{"seed":{index}}}',
                created_at=f"2026-09-28T12:0{index}:00",
            ))
        db.session.commit()

    client = _session_client(viewer_id)
    # Only the page differs between these two requests, so a failure here can
    # only come from the page condition in the `live_insert` decision.
    first_page = client.get("/audit-logs?page=1&per_page=1").get_data(as_text=True)
    second_page = client.get("/audit-logs?page=2&per_page=1").get_data(as_text=True)
    assert 'data-audit-live-insert="true"' in first_page
    assert 'data-audit-live-insert="false"' in second_page


def test_rendered_rows_expose_stable_ids_for_replay_deduplication():
    viewer_id = _any_scope_viewer()
    with app.app_context():
        log = AuditLog(
            user_id=viewer_id,
            action="created",
            entity="task",
            entity_id=4321,
            new_value='{"title":"Live row probe"}',
            created_at="2026-09-28T12:00:00",
        )
        db.session.add(log)
        db.session.commit()
        log_id = log.id

    body = _session_client(viewer_id).get("/audit-logs?per_page=100").get_data(as_text=True)
    assert f'data-audit-log-id="{log_id}"' in body
    assert f"/audit-logs/{log_id}" in body

    with app.app_context():
        db.session.delete(db.session.get(AuditLog, log_id))
        db.session.commit()


def test_live_audit_event_carries_every_field_the_client_row_renders():
    viewer_id = _any_scope_viewer()
    with app.app_context():
        token = realtime_token(viewer_id)

    client = socketio.test_client(app, auth={"token": token})
    assert client.is_connected() is True
    client.get_received()

    with app.app_context():
        AuditEventService.record(
            "ACCESS_DENIED",
            "task",
            987,
            old_value={"status": "Pending"},
            new_value={"status": "Pending"},
            actor_user_id=viewer_id,
            actor_from_session=False,
            result="denied",
            reason="task_view_forbidden",
        )
        db.session.commit()
        log_id = db.session.query(db.func.max(AuditLog.id)).scalar()

    audit_packets = wait_for_audit_packets(client)
    assert audit_packets, "expected a live audit_log_event for the scoped viewer"
    payload = audit_packets[-1]["args"][0]
    for field in ("sequence", "eventId", "timestamp", "actorName", "entityType", "entityId",
                  "action", "result", "reason", "oldValue", "newValue", "ipAddress"):
        assert field in payload, f"live payload missing {field}"
    assert payload["sequence"] == log_id
    assert payload["action"] == "ACCESS_DENIED"
    assert payload["result"] == "denied"
    assert payload["reason"] == "task_view_forbidden"
    client.disconnect()

    with app.app_context():
        db.session.delete(db.session.get(AuditLog, log_id))
        db.session.commit()


def test_live_audit_event_is_not_sent_to_user_without_audit_scope():
    with app.app_context():
        regular_user = User.query.filter_by(username="user").first()
        admin_user = User.query.filter_by(username="admin").first()
        assert regular_user is not None and admin_user is not None
        token = realtime_token(regular_user.id)
        control_token = realtime_token(admin_user.id)

    client = socketio.test_client(app, auth={"token": token})
    control_client = socketio.test_client(app, auth={"token": control_token})
    assert client.is_connected() is True
    assert control_client.is_connected() is True
    client.get_received()
    control_client.get_received()

    with app.app_context():
        AuditEventService.record(
            "created",
            "task",
            5555,
            new_value={"title": "Out of scope probe"},
            actor_user_id=1,
            actor_from_session=False,
        )
        db.session.commit()
        log_id = db.session.query(db.func.max(AuditLog.id)).scalar()

    control_packets = wait_for_audit_packets(control_client)
    packets = wait_for_no_audit_packets(client)
    # The scoped admin proves the event really was published, so the empty
    # result for the unprivileged user is a real scope rejection.
    assert control_packets
    assert not packets
    client.disconnect()
    control_client.disconnect()

    with app.app_context():
        assert db.session.get(AuditLog, log_id) is not None
        db.session.delete(db.session.get(AuditLog, log_id))
        db.session.commit()
