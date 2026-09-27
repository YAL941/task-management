from werkzeug.security import generate_password_hash

from main import User, app, db, verify_password


def test_verify_password_accepts_legacy_plaintext():
    assert verify_password("MyPlainPassword123", "MyPlainPassword123") is True


def test_verify_password_accepts_hashed_password():
    stored_hash = generate_password_hash("Admin@12345")
    assert verify_password(stored_hash, "Admin@12345") is True


def test_user_model_uses_password_hash_column_name_for_current_architecture():
    columns = {column.name for column in User.__table__.columns}
    with app.app_context():
        dialect_name = db.engine.dialect.name
    expected_column = "password_hash" if dialect_name == "mssql" else "password"
    assert expected_column in columns
    assert hasattr(User, "password_hash")


def test_settings_password_change_updates_hash():
    with app.app_context():
        user = User.query.filter_by(username="admin").first()
        original_hash = user.password_hash
        user.password_hash = generate_password_hash("Admin@12345")
        db.session.commit()

    try:
        client = app.test_client()
        login = client.post("/login", data={"username": "admin", "password": "Admin@12345"}, follow_redirects=False)
        assert login.status_code == 302

        client.get("/settings")
        with client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token") or ""

        response = client.post(
            "/settings",
            data={
                "csrf_token": csrf_token,
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
    finally:
        with app.app_context():
            reset_user = User.query.filter_by(username="admin").first()
            if reset_user is not None:
                reset_user.password_hash = original_hash
                db.session.commit()
