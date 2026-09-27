from werkzeug.security import generate_password_hash

from main import User, app, db, verify_password


def test_verify_password_accepts_legacy_plaintext():
    assert verify_password("MyPlainPassword123", "MyPlainPassword123") is True


def test_verify_password_accepts_hashed_password():
    stored_hash = generate_password_hash("Admin@12345")
    assert verify_password(stored_hash, "Admin@12345") is True


def test_user_model_accepts_plain_password_column_name():
    columns = {column.name for column in User.__table__.columns}
    assert "password" in columns
    assert hasattr(User, "password_hash")


def test_settings_password_change_updates_hash():
    with app.app_context():
        user = User.query.filter_by(username="admin").first()
        original = user.password_hash
        user.password_hash = generate_password_hash("Admin@12345")
        db.session.commit()

    client = app.test_client()
    login = client.post("/login", data={"username": "admin", "password": "Admin@12345"}, follow_redirects=False)
    assert login.status_code == 302

    response = client.post(
        "/settings",
        data={
            "csrf_token": client.get("/settings").data.decode("utf-8", "ignore") or "",
            "current_password": "Admin@12345",
            "new_password": "NewPass123!",
            "confirm_password": "NewPass123!",
        },
        follow_redirects=False,
    )
    assert response.status_code in {302, 200}

    with app.app_context():
        updated = User.query.filter_by(username="admin").first()
        assert verify_password(updated.password_hash, "NewPass123!")
