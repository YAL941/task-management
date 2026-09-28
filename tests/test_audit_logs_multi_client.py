"""Live audit streaming with more than one browser open at the same time.

The single-page tests in `test_audit_logs_live_stream.py` cover what one open
page does when an event arrives. These cover the multi-client part that a single
page cannot observe:

* two tabs of the same signed-in user both receive the event,
* a second signed-in user with a different scope receives it only when the row
  is inside that scope,
* a user without `audit_logs.view` never joins the audit room and is refused by
  the fallback sync endpoint,
* one client's replay position does not affect the other.

`publish_committed_audit_logs` runs synchronously after the commit on SQLite
(the conftest suite database), so an ordinary request through the test client is
enough to make the server emit; no sleeping or polling is needed.
"""

import json
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    AuditLog,
    AuditLogScopeOwner,
    Comment,
    Permission,
    RealtimeEvent,
    Role,
    RolePermission,
    Task,
    User,
    UserPresence,
    UserRole,
    app,
    db,
    realtime_token,
    socketio,
)

CREATED_AT = "2026-09-28T10:00:00"


def audit_packets(client):
    return [packet for packet in client.get_received() if packet["name"] == "audit_log_event"]


def drain(client):
    client.get_received()
    return client


@pytest.fixture
def live_clients():
    """Two signed-in viewers, one watcher without audit permission, one task."""
    created = {"users": [], "roles": [], "tasks": [], "audit_logs": []}
    with app.app_context():
        view_permission = Permission.query.filter_by(key="audit_logs.view").first()
        assert view_permission is not None

        def make_user(label, scopes=()):
            user = User(
                first_name="Live",
                last_name=label,
                username=f"live_{label.lower()}_{uuid4().hex[:8]}",
                password_hash=generate_password_hash("temporary-test-password"),
                role="User",
                created_at=CREATED_AT,
            )
            db.session.add(user)
            db.session.flush()
            created["users"].append(user.id)
            for scope in scopes:
                role = Role(
                    name=f"live_{label}_{scope}_{uuid4().hex[:8]}",
                    description="Live stream test role",
                    is_system=False,
                    created_at=CREATED_AT,
                )
                db.session.add(role)
                db.session.flush()
                created["roles"].append(role.id)
                db.session.add(RolePermission(role_id=role.id, permission_id=view_permission.id, scope=scope))
                db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at=CREATED_AT))
            return user

        any_viewer = make_user("Any", ("ANY",))
        other_viewer = make_user("Other", ("OWN",))
        watcher = make_user("Watcher")

        task = Task(
            title="Live stream task",
            status="Pending",
            priority="Medium",
            creator_id=any_viewer.id,
            user_id=any_viewer.id,
        )
        db.session.add(task)
        db.session.flush()
        created["tasks"].append(task.id)

        context = {
            "any_id": any_viewer.id,
            "any_username": any_viewer.username,
            "other_id": other_viewer.id,
            "watcher_id": watcher.id,
            "task_id": task.id,
            "tokens": {
                "any": realtime_token(any_viewer.id),
                "other": realtime_token(other_viewer.id),
                "watcher": realtime_token(watcher.id),
            },
        }
        # flush() alone is not enough: leaving the app context drops the session
        # and rolls the setup back, so the rows must be committed here.
        db.session.commit()

    connected = {}
    try:
        yield context, connected
    finally:
        for client in connected.values():
            try:
                client.disconnect()
            except Exception:
                pass
        with app.app_context():
            actor_audit_ids = [
                row[0]
                for row in db.session.query(AuditLog.id)
                .filter(AuditLog.user_id.in_(created["users"]))
                .all()
            ]
            audit_ids = set(created["audit_logs"]) | set(actor_audit_ids)
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_ids)).delete(synchronize_session=False)
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.owner_user_id.in_(created["users"])).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
            RealtimeEvent.query.filter(RealtimeEvent.actor_id.in_(created["users"])).delete(synchronize_session=False)
            # Completing a task writes a comment, which references the task.
            Comment.query.filter(Comment.task_id.in_(created["tasks"])).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(created["tasks"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(created["users"])).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            # The connect handler marks presence for every socket that joins.
            UserPresence.query.filter(UserPresence.user_id.in_(created["users"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(created["users"])).delete(synchronize_session=False)
            db.session.commit()


def http_client(user_id, csrf="live-stream-csrf"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "live-stream"
        session["role"] = "User"
        session["csrf_token"] = csrf
    return client


def test_two_tabs_of_the_same_user_both_receive_the_event(live_clients):
    context, connected = live_clients
    first_tab = socketio.test_client(app, auth={"token": context["tokens"]["any"]})
    second_tab = socketio.test_client(app, auth={"token": context["tokens"]["any"]})
    connected.update(first=first_tab, second=second_tab)
    assert first_tab.is_connected() and second_tab.is_connected()
    drain(first_tab)
    drain(second_tab)

    response = http_client(context["any_id"]).post(
        f"/update_task_status/{context['task_id']}/In%20Progress",
        data={"csrf_token": "live-stream-csrf"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    first_packets = audit_packets(first_tab)
    second_packets = audit_packets(second_tab)
    assert len(first_packets) == 1
    assert len(second_packets) == 1
    # The same event, byte for byte, so both tabs can render the same row.
    assert first_packets[0]["args"][0] == second_packets[0]["args"][0]
    payload = first_packets[0]["args"][0]
    assert payload["entityType"] == "task"
    assert payload["entityId"] == context["task_id"]
    assert payload["action"] == "status_changed"
    assert context["any_username"] in payload["message"]
    assert "changed the status" in payload["message"]
    assert payload["changes"] == [{"field": "status", "before": "Pending", "after": "In Progress"}]


def test_a_second_user_receives_only_events_inside_their_scope(live_clients):
    context, connected = live_clients
    any_tab = socketio.test_client(app, auth={"token": context["tokens"]["any"]})
    other_tab = socketio.test_client(app, auth={"token": context["tokens"]["other"]})
    connected.update(any_tab=any_tab, other_tab=other_tab)
    drain(any_tab)
    drain(other_tab)

    response = http_client(context["any_id"]).post(
        f"/update_task_status/{context['task_id']}/In%20Progress",
        data={"csrf_token": "live-stream-csrf"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/tasks" in response.headers["Location"]

    any_payloads = [packet["args"][0] for packet in audit_packets(any_tab)]
    other_payloads = [packet["args"][0] for packet in audit_packets(other_tab)]
    # ANY covers the new row; the unrelated OWN-scoped user must not see it.
    assert any(payload["action"] == "status_changed" for payload in any_payloads)
    assert [payload for payload in other_payloads if payload["entityId"] == context["task_id"]] == []


def test_a_user_without_audit_permission_never_receives_events(live_clients):
    context, connected = live_clients
    watcher = socketio.test_client(app, auth={"token": context["tokens"]["watcher"]})
    connected.update(watcher=watcher)
    drain(watcher)

    response = http_client(context["any_id"]).post(
        f"/update_task_status/{context['task_id']}/In%20Progress",
        data={"csrf_token": "live-stream-csrf"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    # The event really was produced; this client simply has no audit scope.
    with app.app_context():
        assert AuditLog.query.filter_by(action="status_changed").count() == 1
    assert audit_packets(watcher) == []
    # The fallback sync path is closed for the same user.
    assert watcher.emit("audit_sync", {"lastAuditLogId": 0}, callback=True) == {
        "ok": False,
        "error": "Unauthorized",
    }


def test_one_client_replaying_does_not_move_the_other_backward(live_clients):
    context, connected = live_clients
    lagging_tab = socketio.test_client(app, auth={"token": context["tokens"]["any"]})
    caught_up_tab = socketio.test_client(app, auth={"token": context["tokens"]["any"]})
    connected.update(lagging=lagging_tab, caught_up=caught_up_tab)
    drain(lagging_tab)
    drain(caught_up_tab)

    client = http_client(context["any_id"])
    first = client.post(
        f"/update_task_status/{context['task_id']}/In%20Progress",
        data={"csrf_token": "live-stream-csrf"},
        follow_redirects=False,
    )
    assert first.status_code == 302
    first_payloads = [packet["args"][0] for packet in audit_packets(lagging_tab)]
    assert len(first_payloads) == 1
    first_sequence = first_payloads[0]["sequence"]

    # Only one browser asks the server to replay the gap it may have missed.
    replayed = caught_up_tab.emit("audit_sync", {"lastAuditLogId": 0}, callback=True)
    assert replayed["ok"] is True
    replayed_task_events = [item for item in replayed["events"] if item["entityType"] == "task"]
    assert replayed_task_events, "the replay must return this run's task events"
    assert max(item["sequence"] for item in replayed_task_events) == first_sequence

    # Completing needs a comment, and it produces two events: the comment and the
    # status change. Both arrive in order, and the replay position cannot rewind.
    second = client.post(
        f"/update_task_status/{context['task_id']}/Completed",
        data={
            "csrf_token": "live-stream-csrf",
            "comment": "Live stream completion comment",
        },
        follow_redirects=False,
    )
    assert second.status_code == 302

    live_payloads = [packet["args"][0] for packet in audit_packets(lagging_tab)]
    sequences = [payload["sequence"] for payload in live_payloads]
    assert sequences == sorted(sequences)
    assert sequences == sorted(set(sequences))
    assert min(sequences) > first_sequence
    assert {payload["action"] for payload in live_payloads} == {"COMMENT_CREATED", "status_changed"}
