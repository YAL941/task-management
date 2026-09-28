"""Task module regression tests.

The audit work touched task writes from several angles (the status route, the
edit route, scope snapshots, live publication), so this file pins the behaviour
those changes depend on:

* the validation each write route performs, and what it does when validation
  fails (a redirect with a danger flash, never a 500),
* who may create, edit, change the status of, and delete a task,
* the status rules, including the comment required before completing and the
  prerequisite rule that blocks completion,
* the list filters (`status`, `priority`, `q`, `view`),
* the audit rows and side tables each successful write leaves behind.
"""

from datetime import date, timedelta
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    AuditLog,
    AuditLogScopeOwner,
    Comment,
    Detail,
    EmailLog,
    Notification,
    Permission,
    RealtimeEvent,
    Role,
    RolePermission,
    Task,
    TaskDependency,
    User,
    UserPresence,
    UserRole,
    app,
    db,
    has_permission,
)

CSRF = "tasks-regression-csrf"
CREATED_AT = "2026-09-28T10:00:00"


def session_client(user_id, role="User"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "tasks-regression"
        session["role"] = role
        session["csrf_token"] = CSRF
    return client


def audit_rows(action, entity_id):
    return AuditLog.query.filter_by(action=action, entity="task", entity_id=entity_id).all()


@pytest.fixture
def task_scenario():
    created = {"users": [], "roles": [], "tasks": [], "dependencies": [], "audit_logs": []}
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        plain = User.query.filter_by(username="user").first()
        assert admin is not None and plain is not None

        # A member of the public User role, with the password the seed gives it.
        member = User(
            first_name="Task",
            last_name="Member",
            username=f"taskmember_{uuid4().hex[:8]}",
            password_hash=generate_password_hash("temporary-test-password"),
            role="User",
            created_at=CREATED_AT,
        )
        db.session.add(member)
        db.session.flush()
        created["users"].append(member.id)

        # A user with no grants at all, to exercise the permission failures. The
        # legacy `role` field is not a seeded role name on purpose: `user_roles`
        # falls back to it, so a plain "User" here would silently inherit the
        # seeded User role and its tasks.create grant.
        powerless = User(
            first_name="Task",
            last_name="NoPerm",
            username=f"tasknoperm_{uuid4().hex[:8]}",
            password_hash=generate_password_hash("temporary-test-password"),
            role="Guest",
            created_at=CREATED_AT,
        )
        db.session.add(powerless)
        db.session.flush()
        created["users"].append(powerless.id)

        user_role = Role.query.filter_by(name="User").first()
        assert user_role is not None
        view_permission = Permission.query.filter_by(key="tasks.view").first()
        assert view_permission is not None
        # Give the powerless user the read permission only, so the failures come
        # from the missing write grant rather than from being unable to sign in.
        view_role = Role(
            name=f"tasks_view_only_{uuid4().hex[:8]}",
            description="Task regression read-only role",
            is_system=False,
            created_at=CREATED_AT,
        )
        db.session.add(view_role)
        db.session.flush()
        created["roles"].append(view_role.id)
        db.session.add(RolePermission(role_id=view_role.id, permission_id=view_permission.id, scope="ANY"))
        db.session.add(UserRole(user_id=powerless.id, role_id=view_role.id, assigned_by=admin.id, created_at=CREATED_AT))
        del user_role

        owned = Task(
            title="Regression owned task",
            status="Pending",
            priority="Medium",
            creator_id=admin.id,
            user_id=member.id,
        )
        unassigned = Task(
            title="Regression unassigned task",
            status="Pending",
            priority="Low",
            creator_id=admin.id,
            user_id=None,
        )
        blocker = Task(
            title="Regression blocker",
            status="Pending",
            priority="High",
            creator_id=admin.id,
            user_id=member.id,
        )
        # Assigned to the member with no prerequisite, so completing it is only
        # about the comment rule and the assignee rule.
        free = Task(
            title="Regression free task",
            status="Pending",
            priority="Medium",
            creator_id=admin.id,
            user_id=member.id,
        )
        db.session.add_all([owned, unassigned, blocker, free])
        db.session.flush()
        created["tasks"].extend([owned.id, unassigned.id, blocker.id, free.id])

        # "Blocked By": owned depends on blocker, so the blocker is its predecessor.
        dependency = TaskDependency(
            predecessor_id=blocker.id,
            successor_id=owned.id,
            dependency_type="Blocked By",
            created_by=admin.id,
            created_at=CREATED_AT,
        )
        db.session.add(dependency)
        db.session.flush()
        created["dependencies"].append(dependency.id)
        db.session.commit()

        context = {
            "admin_id": admin.id,
            "member_id": member.id,
            "powerless_id": powerless.id,
            "member_username": member.username,
            "owned_id": owned.id,
            "unassigned_id": unassigned.id,
            "blocker_id": blocker.id,
            "free_id": free.id,
            "dependency_id": dependency.id,
        }

    try:
        yield context
    finally:
        with app.app_context():
            user_ids = created["users"]
            # Tasks the tests created themselves, on top of the fixture ones.
            task_ids = set(created["tasks"]) | {
                row[0]
                for row in db.session.query(Task.id)
                .filter((Task.creator_id.in_(user_ids)) | (Task.user_id.in_(user_ids)))
                .all()
            }
            audit_ids = set(created["audit_logs"])
            audit_ids.update(
                row[0]
                for row in db.session.query(AuditLog.id)
                .filter((AuditLog.entity == "task") & (AuditLog.entity_id.in_(task_ids)))
                .all()
            )
            audit_ids.update(
                row[0]
                for row in db.session.query(AuditLog.id)
                .filter(AuditLog.user_id.in_(user_ids))
                .all()
            )
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_ids)).delete(synchronize_session=False)
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.owner_user_id.in_(user_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
            Comment.query.filter(
                (Comment.task_id.in_(task_ids)) | (Comment.user_id.in_(user_ids))
            ).delete(synchronize_session=False)
            TaskDependency.query.filter(
                (TaskDependency.successor_id.in_(task_ids))
                | (TaskDependency.predecessor_id.in_(task_ids))
                | (TaskDependency.created_by.in_(user_ids))
            ).delete(synchronize_session=False)
            Detail.query.filter(Detail.task_id.in_(task_ids)).delete(synchronize_session=False)
            Notification.query.filter(Notification.user_id.in_(user_ids)).delete(synchronize_session=False)
            RealtimeEvent.query.filter(RealtimeEvent.actor_id.in_(user_ids)).delete(synchronize_session=False)
            EmailLog.query.filter(EmailLog.user_id.in_(user_ids)).delete(synchronize_session=False)
            UserPresence.query.filter(UserPresence.user_id.in_(user_ids)).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(task_ids)).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(user_ids)).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(user_ids)).delete(synchronize_session=False)
            db.session.commit()


def test_task_create_validation_rejects_bad_input_without_writing(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")
    with app.app_context():
        before = Task.query.count()

    cases = [
        ({"title": "", "priority": "Medium", "user_id": task_scenario["member_id"]}, "empty title"),
        ({"title": "x" * 101, "priority": "Medium", "user_id": task_scenario["member_id"]}, "over-long title"),
        ({"title": "Valid", "priority": "Urgent", "user_id": task_scenario["member_id"]}, "unknown priority"),
        ({"title": "Valid", "priority": "Medium", "user_id": task_scenario["member_id"], "due_date": "31-12-2026"}, "malformed date"),
        ({"title": "Valid", "priority": "Medium", "user_id": 999999}, "unknown assignee"),
    ]
    for form, label in cases:
        response = client.post(
            "/add_task",
            data={"csrf_token": CSRF, **form},
            follow_redirects=False,
        )
        assert response.status_code == 302, label
        with app.app_context():
            assert Task.query.count() == before, label


def test_task_create_writes_the_task_detail_and_audit_rows(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")
    response = client.post(
        "/add_task",
        data={
            "csrf_token": CSRF,
            "title": "Regression created task",
            "priority": "High",
            "user_id": task_scenario["member_id"],
            "description": "Created by the regression test",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302

    with app.app_context():
        created_task = Task.query.filter_by(title="Regression created task").one()
        assert created_task.status == "Pending"
        assert created_task.priority == "High"
        assert created_task.user_id == task_scenario["member_id"]
        assert Detail.query.filter_by(task_id=created_task.id).one().description == "Created by the regression test"
        logs = audit_rows("created", created_task.id)
        assert len(logs) == 1
        assert {owner.owner_user_id for owner in AuditLogScopeOwner.query.filter_by(audit_log_id=logs[0].id)} == {
            task_scenario["admin_id"],
            task_scenario["member_id"],
        }
        task_scenario.setdefault("cleanup_tasks", []).append(created_task.id)


def test_task_create_requires_the_create_permission(task_scenario):
    client = session_client(task_scenario["powerless_id"])
    with app.app_context():
        assert has_permission(task_scenario["powerless_id"], "tasks.view") is True
        assert has_permission(task_scenario["powerless_id"], "tasks.create") is False
        before = Task.query.count()
    response = client.post(
        "/add_task",
        data={"csrf_token": CSRF, "title": "Forbidden task", "priority": "Medium", "user_id": task_scenario["member_id"]},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        assert Task.query.count() == before
        denial = AuditLog.query.filter_by(action="access_denied", entity="task").order_by(AuditLog.id.desc()).first()
        assert denial is not None
        assert "task_create_forbidden" in denial.new_value


def test_csrf_is_required_on_every_task_write_route(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")
    task_id = task_scenario["owned_id"]

    without_token = client.post(f"/update_task_status/{task_id}/In%20Progress", data={}, follow_redirects=False)
    assert without_token.status_code == 302

    with app.app_context():
        assert db.session.get(Task, task_id).status == "Pending"

    wrong_token = client.post(
        f"/update_task_status/{task_id}/In%20Progress",
        data={"csrf_token": "not-the-session-token"},
        follow_redirects=False,
    )
    assert wrong_token.status_code == 302
    with app.app_context():
        assert db.session.get(Task, task_id).status == "Pending"


def test_status_change_rejects_unknown_status_and_keeps_the_old_one(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")
    response = client.post(
        f"/update_task_status/{task_scenario['owned_id']}/Frozen",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Task, task_scenario["owned_id"]).status == "Pending"
        assert audit_rows("status_changed", task_scenario["owned_id"]) == []


def test_completing_requires_a_comment_and_keeps_the_status(task_scenario):
    client = session_client(task_scenario["member_id"])
    task_id = task_scenario["free_id"]
    without_comment = client.post(
        f"/update_task_status/{task_id}/Completed",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert without_comment.status_code == 302
    with app.app_context():
        assert db.session.get(Task, task_id).status == "Pending"
        assert Comment.query.filter_by(task_id=task_id).count() == 0

    with_comment = client.post(
        f"/update_task_status/{task_id}/Completed",
        data={"csrf_token": CSRF, "comment": "Finished by the regression test"},
        follow_redirects=False,
    )
    assert with_comment.status_code == 302
    with app.app_context():
        task = db.session.get(Task, task_id)
        assert task.status == "Completed"
        assert task.completed_at is not None
        assert Comment.query.filter_by(task_id=task_id).count() == 1
        assert [row.action for row in audit_rows("status_changed", task_id)] == ["status_changed"]


def test_the_sender_cannot_change_the_status_of_a_task_they_sent(task_scenario):
    """The rule is absolute: the assignee decides, the sender only follows.

    The admin sent this task and is assigned to nobody, and an admin who cannot
    change it proves the check is not a permission lookup: it is the assignment
    that decides. A crafted POST has to be refused exactly like the button being
    hidden, and nothing may be written.
    """
    task_id = task_scenario["owned_id"]
    for user_id, role in ((task_scenario["admin_id"], "Admin"), (task_scenario["powerless_id"], "User")):
        client = session_client(user_id, role=role)
        refused = client.post(
            f"/update_task_status/{task_id}/In Progress",
            data={"csrf_token": CSRF, "comment": "The sender is trying to close their own task"},
            follow_redirects=False,
        )
        assert refused.status_code == 302
    with app.app_context():
        task = db.session.get(Task, task_id)
        assert task.status == "Pending"
        assert task.completed_at is None
        # The comment is not written either: the refusal happens before the body
        # is read, so a refused status change leaves no trace on the task.
        assert Comment.query.filter_by(task_id=task_id).count() == 0
        assert audit_rows("status_changed", task_id) == []
        denial = (
            AuditLog.query.filter_by(action="access_denied", entity="task", entity_id=task_id)
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert denial is not None
        assert "task_status_change_forbidden" in denial.new_value


def test_an_unassigned_task_has_nobody_who_can_change_its_status(task_scenario):
    """A task with no assignee cannot be moved until it is assigned.

    The rule names the assignee as the only person who may change the status, so
    a task that has none is not the sender's to move either. This is the strict
    reading of the rule; `add_task` always requires an assignee, so only legacy
    and imported rows reach this state.
    """
    task_id = task_scenario["unassigned_id"]
    for user_id, role in ((task_scenario["admin_id"], "Admin"), (task_scenario["member_id"], "User")):
        client = session_client(user_id, role=role)
        assert client.post(
            f"/update_task_status/{task_id}/In Progress",
            data={"csrf_token": CSRF, "comment": "Moving a task nobody owns"},
            follow_redirects=False,
        ).status_code == 302
    with app.app_context():
        assert db.session.get(Task, task_id).status == "Pending"
        assert Comment.query.filter_by(task_id=task_id).count() == 0
        assert audit_rows("status_changed", task_id) == []


def test_the_sender_who_is_also_the_assignee_may_change_the_status(task_scenario):
    """Sender and assignee in one person is the one case the rule allows."""
    task_id = task_scenario["blocker_id"]
    with app.app_context():
        task = db.session.get(Task, task_id)
        assert task.creator_id == task_scenario["admin_id"]
        assert task.user_id == task_scenario["member_id"]
        task.creator_id = task_scenario["member_id"]
        db.session.commit()
    try:
        client = session_client(task_scenario["member_id"])
        assert client.post(
            f"/update_task_status/{task_id}/In Progress",
            data={"csrf_token": CSRF},
            follow_redirects=False,
        ).status_code == 302
        with app.app_context():
            assert db.session.get(Task, task_id).status == "In Progress"
    finally:
        with app.app_context():
            db.session.get(Task, task_id).creator_id = task_scenario["admin_id"]
            db.session.commit()


def test_completion_is_blocked_while_a_prerequisite_is_open(task_scenario):
    # A non-admin assignee cannot complete a task that depends on an open one.
    client = session_client(task_scenario["member_id"])
    response = client.post(
        f"/update_task_status/{task_scenario['owned_id']}/Completed",
        data={"csrf_token": CSRF, "comment": "Trying to finish a blocked task"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Task, task_scenario["owned_id"]).status == "Pending"


def test_dependency_can_be_added_and_removed(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")
    added = client.post(
        f"/tasks/{task_scenario['unassigned_id']}/dependencies",
        data={
            "csrf_token": CSRF,
            "predecessor_id": task_scenario["blocker_id"],
            "dependency_type": "Blocks",
        },
        follow_redirects=False,
    )
    assert added.status_code == 302
    with app.app_context():
        rows = TaskDependency.query.filter_by(
            successor_id=task_scenario["unassigned_id"], predecessor_id=task_scenario["blocker_id"]
        ).all()
        assert len(rows) == 1
        dependency_id = rows[0].id
        removed = client.post(
            f"/tasks/{task_scenario['unassigned_id']}/dependencies/{dependency_id}/delete",
            data={"csrf_token": CSRF},
            follow_redirects=False,
        )
        assert removed.status_code == 302
        assert TaskDependency.query.filter_by(id=dependency_id).first() is None


def test_dependency_rejects_an_unknown_task_and_a_self_reference(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")
    with app.app_context():
        before = TaskDependency.query.count()

    unknown = client.post(
        f"/tasks/{task_scenario['unassigned_id']}/dependencies",
        data={"csrf_token": CSRF, "predecessor_id": 999999, "dependency_type": "Blocks"},
        follow_redirects=False,
    )
    assert unknown.status_code == 302

    self_reference = client.post(
        f"/tasks/{task_scenario['unassigned_id']}/dependencies",
        data={
            "csrf_token": CSRF,
            "predecessor_id": task_scenario["unassigned_id"],
            "dependency_type": "Blocks",
        },
        follow_redirects=False,
    )
    assert self_reference.status_code == 302

    bad_type = client.post(
        f"/tasks/{task_scenario['unassigned_id']}/dependencies",
        data={
            "csrf_token": CSRF,
            "predecessor_id": task_scenario["blocker_id"],
            "dependency_type": "Sideways",
        },
        follow_redirects=False,
    )
    assert bad_type.status_code == 302

    with app.app_context():
        assert TaskDependency.query.count() == before


def test_task_list_filters_search_and_tabs(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")

    def page_text(**params):
        query = "&".join(f"{key}={value}" for key, value in params.items())
        return client.get(f"/tasks?{query}").get_data(as_text=True)

    all_text = page_text(view="all")
    assert "Regression owned task" in all_text
    assert "Regression unassigned task" in all_text

    assert "Regression owned task" in page_text(view="all", q="owned")
    assert "Regression owned task" not in page_text(view="all", q="no-such-title")

    pending_only = page_text(view="all", status="Pending")
    assert "Regression owned task" in pending_only
    low_only = page_text(view="all", priority="Low")
    assert "Regression unassigned task" in low_only
    assert "Regression owned task" not in low_only

    # Received shows what the signed-in user was given.
    assert "Regression owned task" in page_text(view="received")
    assert "Regression owned task" in page_text(view="sent")


def test_task_view_and_list_are_limited_to_what_the_user_may_see(task_scenario):
    member_client = session_client(task_scenario["member_id"])
    html = member_client.get("/tasks?view=all").get_data(as_text=True)
    # Assigned to the member: visible.
    assert "Regression owned task" in html
    # Nobody's task: not part of the member's list.
    assert "Regression unassigned task" not in html


def test_editing_a_task_writes_only_real_changes(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")
    task_id = task_scenario["unassigned_id"]

    with app.app_context():
        before = Detail.query.filter_by(task_id=task_id).first()
        before_description = before.description if before else None

    no_op = client.post(
        f"/edit_task/{task_id}",
        data={
            "csrf_token": CSRF,
            "title": "Regression unassigned task",
            "priority": "Low",
            "description": before_description or "",
        },
        follow_redirects=False,
    )
    assert no_op.status_code == 302
    with app.app_context():
        assert audit_rows("updated", task_id) == []

    changed = client.post(
        f"/edit_task/{task_id}",
        data={
            "csrf_token": CSRF,
            "title": "Regression unassigned task renamed",
            "priority": "High",
            "description": "Renamed by the regression test",
        },
        follow_redirects=False,
    )
    assert changed.status_code == 302
    with app.app_context():
        task = db.session.get(Task, task_id)
        assert task.title == "Regression unassigned task renamed"
        assert task.priority == "High"
        assert Detail.query.filter_by(task_id=task_id).one().description == "Renamed by the regression test"
        assert len(audit_rows("updated", task_id)) == 1


def test_deleting_a_task_removes_its_details_and_records_the_reason(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")
    task_id = task_scenario["unassigned_id"]
    with app.app_context():
        db.session.add(Detail(task_id=task_id, description="detail to be removed"))
        db.session.commit()

    response = client.post(f"/delete_task/{task_id}", data={"csrf_token": CSRF, "comment": "Removed by the regression test"}, follow_redirects=False)
    assert response.status_code == 302

    with app.app_context():
        assert db.session.get(Task, task_id) is None
        assert Detail.query.filter_by(task_id=task_id).count() == 0
        deleted = audit_rows("deleted", task_id)
        assert len(deleted) == 1
        assert "Removed by the regression test" in deleted[0].new_value
        assert "success" in deleted[0].new_value


def test_deleting_a_task_without_a_reason_keeps_it(task_scenario):
    client = session_client(task_scenario["admin_id"], role="Admin")
    task_id = task_scenario["unassigned_id"]
    response = client.post(f"/delete_task/{task_id}", data={"csrf_token": CSRF}, follow_redirects=False)
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Task, task_id) is not None
        assert audit_rows("deleted", task_id) == []


def test_permission_helper_matches_the_seeded_roles():
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        member = User.query.filter_by(username="user").first()
        manager = User.query.filter_by(username="manager").first()
        assert has_permission(admin.id, "tasks.delete")
        assert has_permission(admin.id, "audit_logs.view")
        # The User role only has the _own variants.
        assert has_permission(member.id, "tasks.edit_own")
        assert not has_permission(member.id, "tasks.delete")
        assert not has_permission(member.id, "permissions.manage")
        # The Manager role is team-scoped and has no permission management.
        assert not has_permission(manager.id, "permissions.manage")
        assert not has_permission(manager.id, "audit_logs.view")
