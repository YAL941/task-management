"""Field-level and per-route permission enforcement.

Sixteen catalog keys were granted through `ROLE_DEFAULTS` and shown as granted on
the role screen, but no route ever checked them, so the screen promised controls
the code did not have. This file pins the enforcement that closed that gap:

* `tasks.change_priority` and `tasks.change_due_date` gate those two fields of
  `edit_task`, and a refused field leaves the whole task untouched, so a title
  edit cannot carry a priority change past the check,
* `tasks.assign` and `tasks.assign_own` gate the assignee on task creation,
* `tasks.export` and `reports.export` gate the matching export resources,
* `notifications.view` gates the three notification routes,
* `users.reset_password` gates a password reset on the user screen,
* `permissions.view` gates the permission matrix on the role screen.

The keys that still have no screen behind them - `tasks.reassign`,
`tasks.cancel`, `tasks.restore`, `tasks.archive`, `comments.edit`,
`comments.delete`, `notifications.manage`, `reports.create`, `users.activate`,
`users.deactivate` - are asserted here to be grantable, so the documented list
of reserved keys cannot drift away from the catalog without a failing test.
"""

from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    AuditLog,
    AuditLogScopeOwner,
    Detail,
    Notification,
    Permission,
    RealtimeEvent,
    Role,
    RolePermission,
    Task,
    Team,
    TeamMember,
    User,
    UserPresence,
    UserRole,
    app,
    db,
    has_permission,
)

CSRF = "permission-enforcement-csrf"
CREATED_AT = "2026-09-28T10:00:00"

RESERVED_KEYS = (
    "tasks.reassign",
    "tasks.cancel",
    "tasks.restore",
    "tasks.archive",
    "comments.edit",
    "comments.delete",
    "notifications.manage",
    "reports.create",
    "users.activate",
    "users.deactivate",
)


def client_for(user_id, role="User"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "permission-test"
        session["role"] = role
        session["csrf_token"] = CSRF
    return client


@pytest.fixture
def enforcement():
    created = {"users": [], "roles": [], "tasks": [], "teams": [], "audit_logs": [], "seeded": []}

    def make_user(label, legacy_role="Guest", grants=()):
        with app.app_context():
            user = User(
                first_name="Perm",
                last_name=label,
                username=f"perm_{label.lower()}_{uuid4().hex[:8]}",
                password_hash=generate_password_hash("temporary-test-password"),
                role=legacy_role,
                created_at=CREATED_AT,
            )
            db.session.add(user)
            db.session.flush()
            created["users"].append(user.id)
            for key, scope in grants:
                permission = Permission.query.filter_by(key=key).first()
                assert permission is not None, key
                role = Role(
                    name=f"perm_{label}_{key.replace('.', '_')}_{uuid4().hex[:8]}",
                    description="Permission enforcement test role",
                    is_system=False,
                    created_at=CREATED_AT,
                )
                db.session.add(role)
                db.session.flush()
                created["roles"].append(role.id)
                db.session.add(RolePermission(role_id=role.id, permission_id=permission.id, scope=scope))
                db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at=CREATED_AT))
            db.session.commit()
            return user.id

    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        assert admin is not None
        # The seeded admin is a reference, never something the test created.
        created["seeded"].append(admin.id)

    # The seeded "User" role is the interesting case: it can edit its own task
    # but never held the priority or due-date grants.
    plain = make_user("Plain", legacy_role="User", grants=(("tasks.view", "OWN"),))
    editor = make_user(
        "Editor",
        legacy_role="User",
        grants=(("tasks.view", "ANY"), ("tasks.edit", "ANY")),
    )
    assigner = make_user(
        "Assigner",
        legacy_role="User",
        grants=(("tasks.view", "ANY"), ("tasks.create", "ANY"), ("tasks.assign", "ANY")),
    )
    target = make_user("Target", legacy_role="User", grants=(("tasks.view", "OWN"),))
    resettable = make_user("Resettable", legacy_role="Guest")

    with app.app_context():
        task = Task(
            title="Enforcement task",
            status="Pending",
            priority="Medium",
            creator_id=editor,
            user_id=target,
        )
        db.session.add(task)
        db.session.flush()
        created["tasks"].append(task.id)
        db.session.add(Detail(task_id=task.id, description="original description", updated_at=CREATED_AT))
        db.session.commit()
        task_id = task.id

    context = {
        "admin_id": admin.id,
        "plain_id": plain,
        "editor_id": editor,
        "assigner_id": assigner,
        "target_id": target,
        "resettable_id": resettable,
        "task_id": task_id,
        "created": created,
    }
    try:
        yield context
    finally:
        with app.app_context():
            user_ids = created["users"]
            task_ids = created["tasks"]
            audit_ids = {
                row[0]
                for row in db.session.query(AuditLog.id)
                .filter((AuditLog.user_id.in_(user_ids)) | (AuditLog.entity_id.in_(task_ids)))
                .all()
            }
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_ids)).delete(synchronize_session=False)
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.owner_user_id.in_(user_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
            Notification.query.filter(Notification.user_id.in_(user_ids)).delete(synchronize_session=False)
            RealtimeEvent.query.filter(RealtimeEvent.actor_id.in_(user_ids)).delete(synchronize_session=False)
            UserPresence.query.filter(UserPresence.user_id.in_(user_ids)).delete(synchronize_session=False)
            Detail.query.filter(Detail.task_id.in_(task_ids)).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(task_ids)).delete(synchronize_session=False)
            TeamMember.query.filter(TeamMember.team_id.in_(created["teams"])).delete(synchronize_session=False)
            Team.query.filter(Team.id.in_(created["teams"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(user_ids)).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(user_ids)).delete(synchronize_session=False)
            db.session.commit()


def test_priority_and_due_date_need_their_own_grant(enforcement):
    # The editor holds tasks.edit but neither field grant.
    with app.app_context():
        assert has_permission(enforcement["editor_id"], "tasks.edit") is True
        assert has_permission(enforcement["editor_id"], "tasks.change_priority") is False
        assert has_permission(enforcement["editor_id"], "tasks.change_due_date") is False

    client = client_for(enforcement["editor_id"])
    response = client.post(
        f"/edit_task/{enforcement['task_id']}",
        data={
            "csrf_token": CSRF,
            "title": "Enforcement task renamed",
            "priority": "High",
            "due_date": "2026-10-01",
            "description": "original description",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    with app.app_context():
        task = db.session.get(Task, enforcement["task_id"])
        # Nothing changed: a refused field blocks the whole submit, so the title
        # edit cannot smuggle the priority change through.
        assert task.title == "Enforcement task"
        assert task.priority == "Medium"
        assert task.due_date is None
        assert Detail.query.filter_by(task_id=task.id).one().description == "original description"
        assert AuditLog.query.filter_by(entity="task", entity_id=task.id, action="updated").count() == 0
        denial = AuditLog.query.filter_by(action="access_denied", entity="task").order_by(AuditLog.id.desc()).first()
        assert denial is not None
        assert "tasks_change_priority_forbidden" in denial.new_value


def test_a_granted_field_level_permission_lets_the_edit_through(enforcement):
    with app.app_context():
        grant(enforcement["editor_id"], ("tasks.change_priority", "tasks.change_due_date"), enforcement["created"])
    client = client_for(enforcement["editor_id"])
    response = client.post(
        f"/edit_task/{enforcement['task_id']}",
        data={
            "csrf_token": CSRF,
            "title": "Enforcement task renamed",
            "priority": "High",
            "due_date": "2026-10-01",
            "description": "updated description",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        task = db.session.get(Task, enforcement["task_id"])
        assert task.title == "Enforcement task renamed"
        assert task.priority == "High"
        assert task.due_date == "2026-10-01"
        assert Detail.query.filter_by(task_id=task.id).one().description == "updated description"
        assert AuditLog.query.filter_by(entity="task", entity_id=task.id, action="updated").count() == 1


def test_an_unchanged_priority_needs_no_grant(enforcement):
    # Re-submitting the same priority is not a change, so it is not refused.
    client = client_for(enforcement["editor_id"])
    response = client.post(
        f"/edit_task/{enforcement['task_id']}",
        data={
            "csrf_token": CSRF,
            "title": "Enforcement task renamed",
            "priority": "Medium",
            "due_date": "",
            "description": "original description",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        task = db.session.get(Task, enforcement["task_id"])
        assert task.title == "Enforcement task renamed"
        assert task.priority == "Medium"


def test_assigning_a_task_to_someone_else_needs_the_assign_grant(enforcement):
    # The plain user can create tasks but not hand them to another person.
    with app.app_context():
        assert has_permission(enforcement["plain_id"], "tasks.create") is True
        assert has_permission(enforcement["plain_id"], "tasks.assign") is False

    client = client_for(enforcement["plain_id"])
    response = client.post(
        "/add_task",
        data={
            "csrf_token": CSRF,
            "title": "Assigned away without permission",
            "priority": "Medium",
            "user_id": str(enforcement["target_id"]),
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        assert Task.query.filter_by(title="Assigned away without permission").first() is None
        denial = AuditLog.query.filter_by(action="access_denied", entity="task").order_by(AuditLog.id.desc()).first()
        assert denial is not None
        assert "task_assign_forbidden" in denial.new_value

    # A user holding tasks.assign may do it.
    with app.app_context():
        grant(enforcement["plain_id"], ("tasks.assign",), enforcement["created"])
    allowed = client.post(
        "/add_task",
        data={
            "csrf_token": CSRF,
            "title": "Assigned away with permission",
            "priority": "Medium",
            "user_id": str(enforcement["target_id"]),
        },
        follow_redirects=False,
    )
    assert allowed.status_code == 302
    with app.app_context():
        created = Task.query.filter_by(title="Assigned away with permission").one()
        assert created.user_id == enforcement["target_id"]
        enforcement["created"]["tasks"].append(created.id)
        db.session.commit()


def test_assigning_a_task_to_yourself_uses_the_own_grant(enforcement):
    # The seeded User role holds tasks.assign_own and must keep working.
    with app.app_context():
        assert has_permission(enforcement["plain_id"], "tasks.assign_own") is True
    client = client_for(enforcement["plain_id"])
    response = client.post(
        "/add_task",
        data={
            "csrf_token": CSRF,
            "title": "Self assigned task",
            "priority": "Low",
            "user_id": str(enforcement["plain_id"]),
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        created = Task.query.filter_by(title="Self assigned task").one()
        assert created.user_id == enforcement["plain_id"]
        enforcement["created"]["tasks"].append(created.id)
        db.session.commit()


def test_task_and_report_exports_need_their_export_grant(enforcement):
    # A user with permissions.manage but neither export grant.
    with app.app_context():
        grant(
            enforcement["plain_id"],
            ("permissions.manage", "reports.view"),
            enforcement["created"],
        )
    client = client_for(enforcement["plain_id"], role="Admin")

    tasks_refused = client.get("/export/tasks.csv")
    assert tasks_refused.status_code == 403
    reports_refused = client.get("/export/reports.csv")
    assert reports_refused.status_code == 403
    with app.app_context():
        reasons = [
            row.new_value
            for row in AuditLog.query.filter_by(action="access_denied").order_by(AuditLog.id.desc()).limit(2).all()
        ]
        assert any("tasks_export_forbidden" in value for value in reasons)
        assert any("reports_export_forbidden" in value for value in reasons)

    with app.app_context():
        grant(enforcement["plain_id"], ("tasks.export", "reports.export"), enforcement["created"])
    assert client.get("/export/tasks.csv").status_code == 200
    assert client.get("/export/reports.csv").status_code == 200


def test_notifications_view_gates_the_three_notification_routes(enforcement):
    with app.app_context():
        db.session.add(
            Notification(
                user_id=enforcement["plain_id"],
                message="Enforcement notification",
                is_read=False,
                created_at=CREATED_AT,
            )
        )
        db.session.commit()

    # The seeded User role holds notifications.view, so the feed works.
    allowed = client_for(enforcement["plain_id"])
    assert allowed.get("/notifications/feed").status_code == 200

    # The resettable user holds nothing.
    refused = client_for(enforcement["resettable_id"])
    assert refused.get("/notifications/feed").status_code == 403
    assert refused.post(
        "/notifications/read",
        data={"csrf_token": CSRF, "notification_ids": [1]},
        content_type="application/x-www-form-urlencoded",
    ).status_code == 403
    assert refused.get("/notifications/1", follow_redirects=False).status_code == 302


def test_password_reset_needs_its_own_grant(enforcement):
    with app.app_context():
        # `roles.assign` is needed anyway: saving a user re-syncs their roles and
        # the route rolls the whole submit back without it.
        grant(
            enforcement["resettable_id"],
            ("users.view", "users.edit", "roles.assign"),
            enforcement["created"],
        )
    client = client_for(enforcement["resettable_id"], role="Admin")

    refused = client.post(
        "/users",
        data={
            "csrf_token": CSRF,
            "user_id": str(enforcement["target_id"]),
            "first_name": "Perm",
            "last_name": "Target",
            "new_password": "a-long-enough-password",
        },
        follow_redirects=False,
    )
    assert refused.status_code == 302
    with app.app_context():
        from werkzeug.security import check_password_hash

        target = db.session.get(User, enforcement["target_id"])
        assert check_password_hash(target.password_hash, "a-long-enough-password") is False
        denial = AuditLog.query.filter_by(action="access_denied", entity="user").order_by(AuditLog.id.desc()).first()
        assert denial is not None
        assert "users_reset_password_forbidden" in denial.new_value

    with app.app_context():
        grant(enforcement["resettable_id"], ("users.reset_password",), enforcement["created"])
    allowed = client.post(
        "/users",
        data={
            "csrf_token": CSRF,
            "user_id": str(enforcement["target_id"]),
            "first_name": "Perm",
            "last_name": "Target",
            "new_password": "a-long-enough-password",
        },
        follow_redirects=False,
    )
    assert allowed.status_code == 302
    with app.app_context():
        from werkzeug.security import check_password_hash

        assert check_password_hash(db.session.get(User, enforcement["target_id"]).password_hash, "a-long-enough-password") is True


def test_the_permission_matrix_needs_permissions_view(enforcement):
    with app.app_context():
        grant(enforcement["resettable_id"], ("roles.view",), enforcement["created"])
    client = client_for(enforcement["resettable_id"], role="Admin")
    html = client.get("/roles").get_data(as_text=True)
    assert "Roles &amp; permissions" in html or "Roles & permissions" in html
    # The matrix is withheld, and the reason is stated rather than left blank.
    assert "permissions.view" in html
    assert "data-permission-group" not in html

    with app.app_context():
        grant(enforcement["resettable_id"], ("permissions.view",), enforcement["created"])
    full_html = client_for(enforcement["resettable_id"], role="Admin").get("/roles").get_data(as_text=True)
    assert "data-permission-group" in full_html


def test_the_reserved_keys_are_still_in_the_catalog(enforcement):
    """The documented list of keys with no screen behind them must be real."""
    with app.app_context():
        for key in RESERVED_KEYS:
            assert Permission.query.filter_by(key=key).first() is not None, key
        # And each one is grantable, so a role can still be built around it.
        role = Role(
            name=f"perm_reserved_{uuid4().hex[:8]}",
            description="Reserved keys",
            is_system=False,
            created_at=CREATED_AT,
        )
        db.session.add(role)
        db.session.flush()
        enforcement["created"]["roles"].append(role.id)
        for key in RESERVED_KEYS:
            db.session.add(
                RolePermission(
                    role_id=role.id,
                    permission_id=Permission.query.filter_by(key=key).first().id,
                    scope="ANY",
                )
            )
        db.session.add(
            UserRole(
                user_id=enforcement["resettable_id"],
                role_id=role.id,
                assigned_by=enforcement["admin_id"],
                created_at=CREATED_AT,
            )
        )
        db.session.commit()
        for key in RESERVED_KEYS:
            assert has_permission(enforcement["resettable_id"], key) is True, key


def grant(user_id, keys, created, scope="ANY"):
    """Give a user extra grants through a throwaway role."""
    role = Role(
        name=f"perm_extra_{uuid4().hex[:8]}",
        description="Extra grants for the enforcement test",
        is_system=False,
        created_at=CREATED_AT,
    )
    db.session.add(role)
    db.session.flush()
    created["roles"].append(role.id)
    for key in keys:
        permission = Permission.query.filter_by(key=key).first()
        assert permission is not None, key
        db.session.add(RolePermission(role_id=role.id, permission_id=permission.id, scope=scope))
    db.session.add(UserRole(user_id=user_id, role_id=role.id, assigned_by=user_id, created_at=CREATED_AT))
    db.session.commit()
    return role.id
