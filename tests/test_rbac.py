from types import SimpleNamespace

from werkzeug.security import generate_password_hash

from main import User, app, db, has_permission


def test_legacy_user_gets_seeded_granular_permissions():
    with app.app_context():
        user = User.query.filter_by(username="user").first()
        assert has_permission(user, "tasks.view") is True
        assert has_permission(user, "users.delete") is False


def test_ownership_scope_allows_own_edit_only():
    with app.app_context():
        user = User.query.filter_by(username="user").first()
        own_task = SimpleNamespace(creator_id=user.id, user_id=999999, team_id=None)
        other_task = SimpleNamespace(creator_id=999999, user_id=999998, team_id=None)
        assert has_permission(user, "tasks.edit", own_task) is True
        assert has_permission(user, "tasks.edit", other_task) is False


def test_roles_page_requires_permission_and_admin_can_view():
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        if admin is not None:
            admin.password_hash = generate_password_hash("Admin@12345")
            db.session.commit()

    client = app.test_client()
    response = client.get("/roles")
    assert response.status_code == 302

    login = client.post("/login", data={"username": "admin", "password": "Admin@12345"}, follow_redirects=False)
    assert login.status_code == 302
    response = client.get("/roles")
    assert response.status_code == 200
