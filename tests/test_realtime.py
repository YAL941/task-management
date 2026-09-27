from uuid import uuid4

from main import RealtimeEvent, User, app, db, realtime_token, socketio


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