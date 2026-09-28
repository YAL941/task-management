from uuid import uuid4

from main import AuditLog, RealtimeEvent, User, app, db, realtime_token, socketio


def test_socketio_requires_jwt():
    client = socketio.test_client(app)
    assert client.is_connected() is False


def test_socketio_authenticates_and_syncs_events():
    with app.app_context():
        user = User.query.filter_by(username="admin").first()
        assert user is not None
        event_id = f"test-{uuid4().hex}"
        event = RealtimeEvent(
            event_id=event_id,
            event_type="TEST_EVENT",
            actor_id=user.id,
            entity_type="user",
            entity_id=user.id,
            payload='{"ok": true}',
            created_at="2099-01-01T00:00:00",
        )
        db.session.add(event)
        db.session.commit()
        token = realtime_token(user.id)

    client = socketio.test_client(app, auth={"token": token})
    assert client.is_connected() is True
    connected = client.get_received()
    assert any(packet["name"] == "connected" for packet in connected)

    responses = client.emit("sync", {"lastEventId": 0}, callback=True)
    assert responses["ok"] is True
    assert any(item["eventId"] == event_id for item in responses["events"])
    client.disconnect()


def test_audit_sync_requires_permission_and_returns_scoped_log():
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        regular_user = User.query.filter_by(username="user").first()
        assert admin is not None and regular_user is not None
        log = AuditLog(
            user_id=admin.id,
            action="realtime_probe",
            entity="task",
            entity_id=987654,
            new_value='{"probe":"audit-sync"}',
            created_at="2099-01-01T00:00:00",
        )
        db.session.add(log)
        db.session.commit()
        log_id = log.id
        admin_token = realtime_token(admin.id)
        regular_token = realtime_token(regular_user.id)

    admin_client = socketio.test_client(app, auth={"token": admin_token})
    synced = admin_client.emit("audit_sync", {"lastAuditLogId": log_id - 1}, callback=True)
    assert synced["ok"] is True
    assert any(item["sequence"] == log_id for item in synced["events"])
    matching_event = next(item for item in synced["events"] if item["sequence"] == log_id)
    assert matching_event["result"] == "success"
    admin_client.disconnect()

    regular_client = socketio.test_client(app, auth={"token": regular_token})
    denied = regular_client.emit("audit_sync", {"lastAuditLogId": 0}, callback=True)
    assert denied["ok"] is False
    regular_client.disconnect()

    with app.app_context():
        db.session.delete(db.session.get(AuditLog, log_id))
        db.session.commit()