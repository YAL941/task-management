"""Regression tests for teams, users, roles, notifications, automation and the
assistant API.

The audit scope snapshot reads `TeamMember` rows, and the permission checks read
`UserRole`/`RolePermission`, so a change in the membership or role screens can
silently change who may see which audit rows. These tests pin the membership and
role behaviour, the admin-only guards, and the small JSON APIs the front end
depends on.
"""

from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    AIRequest,
    AuditLog,
    AuditLogScopeOwner,
    AutomationRule,
    EmailLog,
    Notification,
    Permission,
    RealtimeEvent,
    Role,
    RolePermission,
    Task,
    Team,
    TeamMember,
    TeamMessage,
    User,
    UserPresence,
    UserRole,
    app,
    db,
    has_permission,
    is_super_admin,
)

CSRF = "workspace-regression-csrf"
CREATED_AT = "2026-09-28T10:00:00"


def session_client(user_id, role="User"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "workspace-regression"
        session["role"] = role
        session["csrf_token"] = CSRF
    return client


@pytest.fixture
def workspace():
    created = {"users": [], "roles": [], "teams": [], "notifications": [], "automation_rules": []}
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        member = User.query.filter_by(username="user").first()
        assert admin is not None and member is not None

        outsider = User(
            first_name="Space",
            last_name="Outsider",
            username=f"space_{uuid4().hex[:8]}",
            password_hash=generate_password_hash("temporary-test-password"),
            role="Guest",
            created_at=CREATED_AT,
        )
        db.session.add(outsider)
        db.session.flush()
        created["users"].append(outsider.id)

        team = Team(name=f"Regression Team {uuid4().hex[:8]}", created_at=CREATED_AT)
        db.session.add(team)
        db.session.flush()
        created["teams"].append(team.id)
        db.session.add(
            TeamMember(team_id=team.id, user_id=member.id, created_at=CREATED_AT)
        )
        db.session.add(TeamMember(team_id=team.id, user_id=outsider.id, created_at=CREATED_AT))

        rule = AutomationRule(
            name=f"Regression rule {uuid4().hex[:8]}",
            event="status_changed",
            condition="equals",
            value="Completed",
            action="notify",
            created_by=admin.id,
            created_at=CREATED_AT,
        )
        db.session.add(rule)
        db.session.flush()
        created["automation_rules"].append(rule.id)
        db.session.commit()

        context = {
            "admin_id": admin.id,
            "member_id": member.id,
            "outsider_id": outsider.id,
            "team_id": team.id,
            "rule_id": rule.id,
            "created": created,
        }

    try:
        yield context
    finally:
        with app.app_context():
            user_ids = created["users"]
            audit_ids = {
                row[0]
                for row in db.session.query(AuditLog.id)
                .filter(AuditLog.user_id.in_(user_ids))
                .all()
            }
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_ids)).delete(synchronize_session=False)
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.owner_user_id.in_(user_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
            TeamMessage.query.filter(TeamMessage.team_id.in_(created["teams"])).delete(synchronize_session=False)
            TeamMember.query.filter(TeamMember.team_id.in_(created["teams"])).delete(synchronize_session=False)
            Task.query.filter(Task.team_id.in_(created["teams"])).update({"team_id": None}, synchronize_session=False)
            Notification.query.filter(Notification.user_id.in_(user_ids)).delete(synchronize_session=False)
            AutomationRule.query.filter(AutomationRule.id.in_(created["automation_rules"])).delete(synchronize_session=False)
            AIRequest.query.filter(AIRequest.user_id.in_(user_ids)).delete(synchronize_session=False)
            EmailLog.query.filter(EmailLog.user_id.in_(user_ids)).delete(synchronize_session=False)
            RealtimeEvent.query.filter(RealtimeEvent.actor_id.in_(user_ids)).delete(synchronize_session=False)
            UserPresence.query.filter(UserPresence.user_id.in_(user_ids)).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(user_ids)).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            Team.query.filter(Team.id.in_(created["teams"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(user_ids)).delete(synchronize_session=False)
            db.session.commit()


def test_membership_can_be_added_and_removed_by_an_admin(workspace):
    client = session_client(workspace["admin_id"], role="Admin")
    outsider_id = workspace["outsider_id"]
    team_id = workspace["team_id"]

    removed = client.post(
        f"/teams/{team_id}",
        data={"csrf_token": CSRF, "action": "remove_member", "member_id": outsider_id},
        follow_redirects=False,
    )
    assert removed.status_code == 302
    with app.app_context():
        assert TeamMember.query.filter_by(team_id=team_id, user_id=outsider_id).first() is None

    added = client.post(
        "/teams",
        data={"csrf_token": CSRF, "action": "member", "team_id": team_id, "user_id": outsider_id},
        follow_redirects=False,
    )
    assert added.status_code == 302
    with app.app_context():
        assert TeamMember.query.filter_by(team_id=team_id, user_id=outsider_id).first() is not None


def test_a_non_admin_cannot_change_the_team_roster(workspace):
    client = session_client(workspace["member_id"])
    with app.app_context():
        before = TeamMember.query.count()
    response = client.post(
        "/teams",
        data={"csrf_token": CSRF, "action": "member", "team_id": workspace["team_id"], "user_id": workspace["outsider_id"]},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        assert TeamMember.query.count() == before
        denial = AuditLog.query.filter_by(action="access_denied", entity="team").order_by(AuditLog.id.desc()).first()
        assert denial is not None
        assert "team_management_forbidden" in denial.new_value


def test_team_creation_requires_a_name_a_leader_and_a_unique_name(workspace):
    client = session_client(workspace["admin_id"], role="Admin")
    with app.app_context():
        existing_name = Team.query.get(workspace["team_id"]).name
        before = Team.query.count()

    # No leader: refused.
    no_leader = client.post(
        "/teams",
        data={"csrf_token": CSRF, "action": "create", "name": f"No leader {uuid4().hex[:8]}"},
        follow_redirects=False,
    )
    assert no_leader.status_code == 302
    # Duplicate name: refused by the unique constraint.
    duplicate = client.post(
        "/teams",
        data={
            "csrf_token": CSRF,
            "action": "create",
            "name": existing_name,
            "leader_id": workspace["admin_id"],
        },
        follow_redirects=False,
    )
    assert duplicate.status_code == 302
    with app.app_context():
        assert Team.query.count() == before

    unique_name = f"Regression Fresh {uuid4().hex[:8]}"
    created = client.post(
        "/teams",
        data={
            "csrf_token": CSRF,
            "action": "create",
            "name": unique_name,
            "leader_id": workspace["admin_id"],
        },
        follow_redirects=False,
    )
    assert created.status_code == 302
    with app.app_context():
        team = Team.query.filter_by(name=unique_name).first()
        assert team is not None
        # The leader is added to the team as a full-permission member.
        leader_membership = TeamMember.query.filter_by(team_id=team.id, user_id=workspace["admin_id"]).one()
        assert "manage_members" in leader_membership.permissions
        workspace["created"]["teams"].append(team.id)


def test_automation_is_admin_only_and_validates_its_input(workspace):
    non_admin = session_client(workspace["member_id"])
    forbidden = non_admin.get("/automation", follow_redirects=False)
    assert forbidden.status_code == 302

    admin_client = session_client(workspace["admin_id"], role="Admin")
    assert admin_client.get("/automation").status_code == 200

    with app.app_context():
        before = AutomationRule.query.count()

    # Missing name or value is refused.
    for form in ({"name": "", "value": "Completed"}, {"name": "No value", "value": ""}):
        refused = admin_client.post(
            "/automation",
            data={"csrf_token": CSRF, "event": "status_changed", "condition": "equals", "action": "notify", **form},
            follow_redirects=False,
        )
        assert refused.status_code == 302
    with app.app_context():
        assert AutomationRule.query.count() == before

    accepted = admin_client.post(
        "/automation",
        data={
            "csrf_token": CSRF,
            "name": f"Regression created rule {uuid4().hex[:8]}",
            "event": "status_changed",
            "condition": "changes_to",
            "value": "Completed",
            "action": "notify",
        },
        follow_redirects=False,
    )
    assert accepted.status_code == 302
    with app.app_context():
        assert AutomationRule.query.count() == before + 1
        newest = AutomationRule.query.order_by(AutomationRule.id.desc()).first()
        workspace["created"]["automation_rules"].append(newest.id)
        log = AuditLog.query.filter_by(entity="automation_rule", action="created").order_by(AuditLog.id.desc()).first()
        assert log is not None
        assert newest.name in log.new_value


def test_automation_toggle_requires_csrf_and_flips_the_flag(workspace):
    client = session_client(workspace["admin_id"], role="Admin")
    with app.app_context():
        # New rules are enabled; the toggle has to turn them off.
        assert db.session.get(AutomationRule, workspace["rule_id"]).enabled is True

    without_token = client.post(f"/automation/{workspace['rule_id']}/toggle", data={}, follow_redirects=False)
    assert without_token.status_code == 302
    with app.app_context():
        assert db.session.get(AutomationRule, workspace["rule_id"]).enabled is True

    toggled = client.post(
        f"/automation/{workspace['rule_id']}/toggle",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert toggled.status_code == 302
    with app.app_context():
        assert db.session.get(AutomationRule, workspace["rule_id"]).enabled is False
        log = AuditLog.query.filter_by(entity="automation_rule", action="toggled").order_by(AuditLog.id.desc()).first()
        assert log is not None
        assert "false" in log.new_value


def test_permission_endpoint_describes_the_caller(workspace):
    client = session_client(workspace["admin_id"], role="Admin")
    payload = client.get("/api/me/permissions").get_json()
    keys = {row["key"] for row in payload["permissions"]}
    assert "tasks.view" in keys
    assert "audit_logs.view" in keys
    assert {row["scope"] for row in payload["permissions"]} == {"ANY"}

    # A user with no grants gets an empty list rather than an error.
    outsider_client = session_client(workspace["outsider_id"])
    assert outsider_client.get("/api/me/permissions").get_json() == {"permissions": []}


def test_permission_endpoint_requires_a_session(workspace):
    anonymous = app.test_client()
    assert anonymous.get("/api/me/permissions", follow_redirects=False).status_code == 302


def test_notification_feed_only_returns_the_callers_own_rows(workspace):
    client = session_client(workspace["member_id"])
    with app.app_context():
        Notification.query.filter_by(user_id=workspace["member_id"]).delete()
        db.session.add(
            Notification(
                user_id=workspace["member_id"],
                message="Regression notification",
                is_read=False,
                created_at=CREATED_AT,
            )
        )
        db.session.commit()

    payload = client.get("/notifications/feed").get_json()
    assert payload["unread_count"] == 1
    assert [item["message"] for item in payload["notifications"]] == ["Regression notification"]
    assert payload["notifications"][0]["is_read"] is False
    notification_id = payload["notifications"][0]["id"]

    marked = client.post(
        "/notifications/read",
        data={"csrf_token": CSRF, "notification_ids": [notification_id]},
        content_type="application/x-www-form-urlencoded",
    )
    assert marked.status_code == 200
    assert marked.get_json()["ok"] is True
    with app.app_context():
        assert db.session.get(Notification, notification_id).is_read is True

    # The outsider has no `notifications.view`, so the feed is closed and the
    # refusal is recorded rather than returning an empty list.
    outsider_client = session_client(workspace["outsider_id"])
    refused = outsider_client.get("/notifications/feed")
    assert refused.status_code == 403
    assert refused.get_json() == {"ok": False, "error": "Forbidden"}
    assert outsider_client.post(
        "/notifications/read",
        data={"csrf_token": CSRF, "notification_ids": [notification_id]},
        content_type="application/x-www-form-urlencoded",
    ).status_code == 403
    assert outsider_client.get(f"/notifications/{notification_id}", follow_redirects=False).status_code == 302
    with app.app_context():
        denial = AuditLog.query.filter_by(action="access_denied", entity="notification").order_by(AuditLog.id.desc()).first()
        assert denial is not None
        assert "notifications_view_forbidden" in denial.new_value
        assert db.session.get(Notification, notification_id).is_read is True


def test_marking_notifications_read_needs_a_csrf_token(workspace):
    client = session_client(workspace["member_id"])
    response = client.post("/notifications/read", data={}, content_type="application/x-www-form-urlencoded")
    assert response.status_code == 400
    assert response.get_json() == {"ok": False, "error": "Invalid request"}


def test_opening_someone_elses_notification_redirects_without_reading_it(workspace):
    client = session_client(workspace["member_id"])
    with app.app_context():
        notification = Notification(
            user_id=workspace["outsider_id"],
            message="Not yours",
            is_read=False,
            created_at=CREATED_AT,
        )
        db.session.add(notification)
        db.session.commit()
        notification_id = notification.id

    response = client.get(f"/notifications/{notification_id}", follow_redirects=False)
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Notification, notification_id).is_read is False


def test_ai_ask_validates_the_prompt_and_records_the_request(workspace):
    client = session_client(workspace["member_id"])

    no_csrf = client.post("/api/ai/ask", json={"prompt": "hello"})
    assert no_csrf.status_code == 400
    assert no_csrf.get_json() == {"ok": False, "error": "Invalid request"}

    empty = client.post("/api/ai/ask", data={"csrf_token": CSRF, "prompt": "   "}, content_type="application/x-www-form-urlencoded")
    assert empty.status_code == 400
    assert empty.get_json()["error"] == "Prompt is required"

    too_long = client.post(
        "/api/ai/ask",
        data={"csrf_token": CSRF, "prompt": "x" * 2001},
        content_type="application/x-www-form-urlencoded",
    )
    assert too_long.status_code == 400

    with app.app_context():
        before = AIRequest.query.filter_by(user_id=workspace["member_id"]).count()

    answered = client.post(
        "/api/ai/ask",
        data={"csrf_token": CSRF, "prompt": "How many tasks are pending?"},
        content_type="application/x-www-form-urlencoded",
    )
    assert answered.status_code == 200
    body = answered.get_json()
    assert body["ok"] is True
    assert body["answer"]
    assert body["mode"] in {"mock", "live"}

    with app.app_context():
        assert AIRequest.query.filter_by(user_id=workspace["member_id"]).count() == before + 1
        audit = AuditLog.query.filter_by(action="AI_REQUEST", entity="assistant").order_by(AuditLog.id.desc()).first()
        assert audit is None or audit.user_id == workspace["member_id"]


def test_admin_only_screens_are_closed_to_the_ordinary_roles(workspace):
    for user_id, role in ((workspace["member_id"], "User"), (workspace["outsider_id"], "Guest")):
        client = session_client(user_id, role=role)
        for path in ("/automation", "/data", "/export/tasks.csv"):
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 302, f"{path} for {role}"

    admin_client = session_client(workspace["admin_id"], role="Admin")
    assert admin_client.get("/data").status_code == 200
    exported = admin_client.get("/export/tasks.csv")
    assert exported.status_code == 200
    assert exported.mimetype == "text/csv"


def test_roles_screen_lists_the_seeded_roles(workspace):
    client = session_client(workspace["admin_id"], role="Admin")
    html = client.get("/roles").get_data(as_text=True)
    for name in ("Super Admin", "Admin", "Manager", "User"):
        assert name in html


def test_every_template_compiles():
    """A template that cannot compile is a 500 on the page that renders it.

    `templates/users.html` once contained a Jinja set literal with a variable,
    `{user[7]}`, which Jinja cannot parse, so the whole users screen returned 500
    for every user. Compiling every template catches that class of defect
    without needing a signed-in request per page.
    """
    with app.app_context():
        loader = app.jinja_loader
        names = sorted(loader.list_templates())
        assert names, "no templates were found"
        failures = []
        for name in names:
            try:
                app.jinja_env.get_template(name)
            except Exception as error:  # noqa: BLE001 - report every broken template
                failures.append(f"{name}: {error}")
        assert not failures, "templates failed to compile: " + "; ".join(failures)


def test_user_screens_and_seeded_accounts(workspace):
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        plain = User.query.filter_by(username="user").first()
        # is_super_admin takes an id and asks for the "Super Admin" role, which
        # no seeded account holds: admin is an Admin, not a Super Admin.
        assert is_super_admin(admin.id) is False
        assert is_super_admin(plain.id) is False
        assert is_super_admin(workspace["outsider_id"]) is False
        # Deleting a user must not be possible for an ordinary account.
        assert not has_permission(plain.id, "users.delete")
        assert has_permission(admin.id, "users.delete")

    client = session_client(workspace["admin_id"], role="Admin")
    html = client.get("/users").get_data(as_text=True)
    assert "admin" in html
    assert "manager" in html
