"""Coverage for audit-log filtering by actor username, entity id, and quick periods."""

from datetime import date, timedelta
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import AuditLog, Permission, Role, RolePermission, User, UserRole, app, db

TODAY = date.today()


@pytest.fixture
def filter_scenario():
    created = {"users": [], "roles": [], "logs": []}
    with app.app_context():
        permission = Permission.query.filter_by(key="audit_logs.view").first()
        assert permission is not None

        def make_user(label, scopes=("ANY",)):
            user = User(
                first_name="Filter",
                last_name=label,
                username=f"filter_{label.lower()}_{uuid4().hex[:6]}",
                password_hash=generate_password_hash("temporary-test-password"),
                role="User",
                created_at=f"{TODAY.isoformat()}T00:00:00",
            )
            db.session.add(user)
            db.session.flush()
            created["users"].append(user.id)
            for scope in scopes:
                role = Role(
                    name=f"filter_{label}_{scope}_{uuid4().hex[:6]}",
                    description="Audit filter test role",
                    is_system=False,
                    created_at=f"{TODAY.isoformat()}T00:00:00",
                )
                db.session.add(role)
                db.session.flush()
                created["roles"].append(role.id)
                db.session.add(RolePermission(role_id=role.id, permission_id=permission.id, scope=scope))
                db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at=f"{TODAY.isoformat()}T00:00:00"))
            return user

        viewer = make_user("Viewer")
        other_actor = make_user("Other")

        def add_log(marker, actor, entity, entity_id, created_at):
            log = AuditLog(
                user_id=actor.id if actor else None,
                action="created",
                entity=entity,
                entity_id=entity_id,
                new_value=marker,
                created_at=created_at,
            )
            db.session.add(log)
            db.session.flush()
            created["logs"].append(log.id)
            return log

        add_log("FILTER_TODAY_OTHER", other_actor, "task", 4242, f"{TODAY.isoformat()}T09:00:00")
        add_log("FILTER_TODAY_VIEWER", viewer, "task", 5151, f"{TODAY.isoformat()}T08:00:00")
        add_log("FILTER_THREE_DAYS", other_actor, "team", 6262, f"{(TODAY - timedelta(days=3)).isoformat()}T08:00:00")
        add_log("FILTER_TEN_DAYS", other_actor, "task", 7272, f"{(TODAY - timedelta(days=10)).isoformat()}T08:00:00")
        db.session.commit()

        payload = {
            "viewer_id": viewer.id,
            "other_username": other_actor.username,
            "ids": {
                "today_other": created["logs"][0],
                "today_viewer": created["logs"][1],
                "three_days": created["logs"][2],
                "ten_days": created["logs"][3],
            },
        }

    try:
        yield payload
    finally:
        with app.app_context():
            AuditLog.query.filter(AuditLog.id.in_(created["logs"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(created["users"])).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(created["users"])).delete(synchronize_session=False)
            db.session.commit()


def filter_client(user_id):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "filter-test"
        session["role"] = "User"
    return client


def visible_markers(client, query):
    html = client.get(f"/audit-logs{query}").get_data(as_text=True)
    return [marker for marker in (
        "FILTER_TODAY_OTHER", "FILTER_TODAY_VIEWER", "FILTER_THREE_DAYS", "FILTER_TEN_DAYS"
    ) if marker in html]


def test_search_matches_actor_username(filter_scenario):
    client = filter_client(filter_scenario["viewer_id"])
    assert visible_markers(client, f"?search={filter_scenario['other_username']}") == [
        "FILTER_TODAY_OTHER", "FILTER_THREE_DAYS", "FILTER_TEN_DAYS"
    ]
    assert visible_markers(client, "?search=filter_other") == [
        "FILTER_TODAY_OTHER", "FILTER_THREE_DAYS", "FILTER_TEN_DAYS"
    ]
    assert visible_markers(client, "?search=no_such_username_zzz") == []


def test_search_still_matches_action_entity_and_values(filter_scenario):
    client = filter_client(filter_scenario["viewer_id"])
    assert visible_markers(client, "?search=team") == ["FILTER_THREE_DAYS"]


def test_entity_id_filter_narrows_to_one_resource(filter_scenario):
    client = filter_client(filter_scenario["viewer_id"])
    assert visible_markers(client, "?entity_id=4242") == ["FILTER_TODAY_OTHER"]
    assert visible_markers(client, "?entity_id=7272") == ["FILTER_TEN_DAYS"]
    assert visible_markers(client, "?entity_id=999999") == []


def test_quick_period_filters_by_relative_window(filter_scenario):
    client = filter_client(filter_scenario["viewer_id"])

    today_markers = visible_markers(client, "?period=today")
    assert today_markers == ["FILTER_TODAY_OTHER", "FILTER_TODAY_VIEWER"]

    seven_day_markers = visible_markers(client, "?period=7d")
    assert seven_day_markers == ["FILTER_TODAY_OTHER", "FILTER_TODAY_VIEWER", "FILTER_THREE_DAYS"]

    assert visible_markers(client, "") == [
        "FILTER_TODAY_OTHER", "FILTER_TODAY_VIEWER", "FILTER_THREE_DAYS", "FILTER_TEN_DAYS"
    ]


def test_unknown_period_is_ignored_and_custom_range_wins(filter_scenario):
    client = filter_client(filter_scenario["viewer_id"])
    assert visible_markers(client, "?period=last-year") == [
        "FILTER_TODAY_OTHER", "FILTER_TODAY_VIEWER", "FILTER_THREE_DAYS", "FILTER_TEN_DAYS"
    ]
    ten_days_ago = (TODAY - timedelta(days=10)).isoformat()
    assert visible_markers(client, f"?period=today&date_from={ten_days_ago}") == [
        "FILTER_TODAY_OTHER", "FILTER_TODAY_VIEWER", "FILTER_THREE_DAYS", "FILTER_TEN_DAYS"
    ]


def test_new_filters_are_carried_by_pagination_and_sort_links(filter_scenario):
    client = filter_client(filter_scenario["viewer_id"])
    body = client.get("/audit-logs?period=7d&entity_id=4242&per_page=100").get_data(as_text=True)
    assert 'data-audit-live-insert="false"' in body
    assert 'value="4242"' in body
    assert 'data-audit-period="7d" aria-current="page"' in body
    assert 'data-audit-period="today"' in body
    assert "period=7d" in body
    assert "entity_id=4242" in body
