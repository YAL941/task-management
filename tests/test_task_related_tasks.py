"""Related tasks: what a task waits for, and what waits for it.

The dependencies screen used to list one direction only, showed every task in the
workspace as a candidate — naming titles the caller could not open anywhere else —
drew its add and remove controls from a role name that the POST did not consult,
and the whole page had no access check at all. Each of those is pinned here.
"""

from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    AuditLog,
    Detail,
    Permission,
    Role,
    RolePermission,
    Task,
    TaskDependency,
    User,
    UserRole,
    app,
    db,
    has_permission,
)

CSRF = "related-csrf"
CREATED_AT = "2026-09-28T17:00:00"


def session_client(user_id, role="User"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "related-test"
        session["role"] = role
        session["csrf_token"] = CSRF
    return client


def grant(user_id, key, scope, created):
    permission = Permission.query.filter_by(key=key).first()
    assert permission is not None, key
    role = Role(
        name=f"related_{key.replace('.', '_')}_{uuid4().hex[:8]}",
        description="Related tasks test role",
        is_system=False,
        created_at=CREATED_AT,
    )
    db.session.add(role)
    db.session.flush()
    created["roles"].append(role.id)
    db.session.add(RolePermission(role_id=role.id, permission_id=permission.id, scope=scope))
    db.session.add(UserRole(user_id=user_id, role_id=role.id, assigned_by=user_id, created_at=CREATED_AT))
    db.session.commit()
    return role.id


@pytest.fixture
def scenario():
    created = {"users": [], "roles": [], "tasks": [], "dependencies": []}

    def make_user(label, legacy_role="Guest", grants=()):
        with app.app_context():
            user = User(
                first_name="Re",
                last_name=label,
                username=f"related_{label.lower()}_{uuid4().hex[:8]}",
                password_hash=generate_password_hash("temporary-test-password"),
                role=legacy_role,
                created_at=CREATED_AT,
            )
            db.session.add(user)
            db.session.flush()
            created["users"].append(user.id)
            for key, scope in grants:
                grant(user.id, key, scope, created)
            db.session.commit()
            return user.id

    sender = make_user("Sender", legacy_role="User")
    editor = make_user("Editor", grants=(("tasks.view", "ANY"), ("tasks.edit", "ANY")))
    viewer = make_user("Viewer", grants=(("tasks.view", "ANY"),))
    stranger = make_user("Stranger")

    with app.app_context():
        downstream_task = Task(
            title="Waiting for the upstream work",
            status="Pending",
            priority="Medium",
            creator_id=sender,
            user_id=editor,
        )
        upstream_task = Task(
            title="The work that has to move first",
            status="In Progress",
            priority="High",
            creator_id=sender,
            user_id=editor,
        )
        db.session.add_all([downstream_task, upstream_task])
        db.session.flush()
        for task in (downstream_task, upstream_task):
            created["tasks"].append(task.id)
            db.session.add(Detail(task_id=task.id, description="Related tasks scenario", updated_at=CREATED_AT))
        db.session.commit()
        downstream_id, upstream_id = downstream_task.id, upstream_task.id

    context = {
        "sender_id": sender,
        "editor_id": editor,
        "viewer_id": viewer,
        "stranger_id": stranger,
        "downstream_id": downstream_id,
        "upstream_id": upstream_id,
        "created": created,
    }
    try:
        yield context
    finally:
        with app.app_context():
            from main import AuditLogScopeOwner

            task_ids = created["tasks"]
            user_ids = created["users"]
            audit_ids = {
                row[0]
                for row in db.session.query(AuditLog.id)
                .filter(
                    (AuditLog.entity == "task") & (AuditLog.entity_id.in_(task_ids))
                    | (AuditLog.user_id.in_(user_ids))
                )
                .all()
            }
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_ids)).delete(synchronize_session=False)
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.owner_user_id.in_(user_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
            TaskDependency.query.filter(
                (TaskDependency.predecessor_id.in_(task_ids)) | (TaskDependency.successor_id.in_(task_ids))
            ).delete(synchronize_session=False)
            Detail.query.filter(Detail.task_id.in_(task_ids)).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(task_ids)).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(user_ids)).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(user_ids)).delete(synchronize_session=False)
            db.session.commit()


def link(scenario, predecessor_id, successor_id, dependency_type="Blocks"):
    with app.app_context():
        dependency = TaskDependency(
            predecessor_id=predecessor_id,
            successor_id=successor_id,
            dependency_type=dependency_type,
            created_by=scenario["sender_id"],
            created_at=CREATED_AT,
        )
        db.session.add(dependency)
        db.session.commit()
        scenario["created"]["dependencies"].append(dependency.id)
        return dependency.id


def test_a_dependency_reads_from_both_sides(scenario):
    """The row is stored once, and both tasks have to say what it means."""
    link(scenario, scenario["upstream_id"], scenario["downstream_id"])

    waiting = session_client(scenario["editor_id"]).get(
        f"/tasks/{scenario['downstream_id']}/dependencies"
    ).get_data(as_text=True)
    assert "Blocked by" in waiting
    assert "The work that has to move first" in waiting

    blocking = session_client(scenario["editor_id"]).get(
        f"/tasks/{scenario['upstream_id']}/dependencies"
    ).get_data(as_text=True)
    assert "Waiting on this task" in blocking
    assert "Waiting for the upstream work" in blocking


def test_an_open_blocker_is_stated_on_the_task_page(scenario):
    link(scenario, scenario["upstream_id"], scenario["downstream_id"])
    html = session_client(scenario["editor_id"]).get(
        f"/tasks/{scenario['downstream_id']}/view"
    ).get_data(as_text=True)
    assert "cannot be completed yet" in html
    assert "The work that has to move first" in html

    # Once the blocking task is done, the task page stops saying it is stuck.
    with app.app_context():
        task = db.session.get(Task, scenario["upstream_id"])
        task.status = "Completed"
        db.session.commit()
    done = session_client(scenario["editor_id"]).get(
        f"/tasks/{scenario['downstream_id']}/view"
    ).get_data(as_text=True)
    assert "cannot be completed yet" not in done
    # The link itself is still listed; only the warning is gone.
    assert "The work that has to move first" in done


def test_a_related_task_the_caller_cannot_open_is_not_listed(scenario):
    """Naming a task here must not be a way to read its title."""
    with app.app_context():
        private = Task(
            title="PRIVATE_TITLE_SOMEONE_ELSES_WORK",
            status="Pending",
            priority="Low",
            creator_id=scenario["stranger_id"],
            user_id=scenario["stranger_id"],
        )
        db.session.add(private)
        db.session.commit()
        scenario["created"]["tasks"].append(private.id)
        private_id = private.id

    page = session_client(scenario["editor_id"]).get(
        f"/tasks/{scenario['downstream_id']}/dependencies"
    ).get_data(as_text=True)
    assert "PRIVATE_TITLE_SOMEONE_ELSES_WORK" not in page
    assert f'value="{private_id}"' not in page


def test_the_screen_follows_the_edit_grant(scenario):
    """Visibility is decided by `tasks.edit`, not by the role name in the session."""
    with app.app_context():
        assert has_permission(scenario["viewer_id"], "tasks.edit", db.session.get(Task, scenario["downstream_id"])) is False

    refused_page = session_client(scenario["viewer_id"]).get(
        f"/tasks/{scenario['downstream_id']}/dependencies"
    ).get_data(as_text=True)
    assert f"/tasks/{scenario['downstream_id']}/dependencies" not in refused_page

    refused_post = session_client(scenario["viewer_id"]).post(
        f"/tasks/{scenario['downstream_id']}/dependencies",
        data={"csrf_token": CSRF, "predecessor_id": scenario["upstream_id"], "dependency_type": "Blocks"},
        follow_redirects=False,
    )
    assert refused_post.status_code == 302
    with app.app_context():
        assert TaskDependency.query.filter_by(successor_id=scenario["downstream_id"]).count() == 0

    allowed_page = session_client(scenario["editor_id"]).get(
        f"/tasks/{scenario['downstream_id']}/dependencies"
    ).get_data(as_text=True)
    assert f"/tasks/{scenario['downstream_id']}/dependencies" in allowed_page


def test_removing_a_link_follows_the_same_grant(scenario):
    dependency_id = link(scenario, scenario["upstream_id"], scenario["downstream_id"])

    refused = session_client(scenario["viewer_id"]).post(
        f"/tasks/{scenario['downstream_id']}/dependencies/{dependency_id}/delete",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert refused.status_code == 302
    with app.app_context():
        assert db.session.get(TaskDependency, dependency_id) is not None
        denial = (
            AuditLog.query.filter_by(action="access_denied", entity="task", entity_id=scenario["downstream_id"])
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert denial is not None
        assert "task_dependency_manage_forbidden" in denial.new_value

    allowed = session_client(scenario["editor_id"]).post(
        f"/tasks/{scenario['downstream_id']}/dependencies/{dependency_id}/delete",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert allowed.status_code == 302
    with app.app_context():
        assert db.session.get(TaskDependency, dependency_id) is None


def test_the_screen_is_closed_to_someone_who_cannot_open_the_task(scenario):
    """A dependency page is about more than the task in the address bar."""
    page = session_client(scenario["stranger_id"]).get(
        f"/tasks/{scenario['downstream_id']}/dependencies"
    )
    assert page.status_code == 302
    assert b"The work that has to move first" not in page.get_data()
    with app.app_context():
        denial = (
            AuditLog.query.filter_by(action="access_denied", entity="task", entity_id=scenario["downstream_id"])
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert denial is not None
        assert "task_dependencies_forbidden" in denial.new_value


def test_a_link_can_be_added_and_removed_from_the_screen(scenario):
    with app.app_context():
        assert TaskDependency.query.filter_by(successor_id=scenario["downstream_id"]).count() == 0

    added = session_client(scenario["editor_id"]).post(
        f"/tasks/{scenario['downstream_id']}/dependencies",
        data={"csrf_token": CSRF, "predecessor_id": scenario["upstream_id"], "dependency_type": "Blocks"},
        follow_redirects=False,
    )
    assert added.status_code == 302
    with app.app_context():
        rows = TaskDependency.query.filter_by(
            successor_id=scenario["downstream_id"], predecessor_id=scenario["upstream_id"]
        ).all()
        assert len(rows) == 1
        dependency_id = rows[0].id

    # The task it already waits for is not offered a second time as a candidate.
    page = session_client(scenario["editor_id"]).get(
        f"/tasks/{scenario['downstream_id']}/dependencies"
    ).get_data(as_text=True)
    assert f'<option value="{scenario["upstream_id"]}"' not in page
    assert "Blocked by" in page

    removed = session_client(scenario["editor_id"]).post(
        f"/tasks/{scenario['downstream_id']}/dependencies/{dependency_id}/delete",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert removed.status_code == 302
    with app.app_context():
        assert db.session.get(TaskDependency, dependency_id) is None


def test_a_link_to_a_task_the_caller_cannot_see_is_still_refused(scenario):
    """A crafted POST cannot use a link to smuggle in a hidden task."""
    with app.app_context():
        private = Task(
            title="PRIVATE_TITLE_SOMEONE_ELSES_WORK",
            status="Pending",
            priority="Low",
            creator_id=scenario["stranger_id"],
            user_id=scenario["stranger_id"],
        )
        db.session.add(private)
        db.session.commit()
        scenario["created"]["tasks"].append(private.id)
        private_id = private.id

    # The editor holds the edit grant on their own task, and the route refuses a
    # predecessor the caller cannot open.
    response = session_client(scenario["editor_id"]).post(
        f"/tasks/{scenario['downstream_id']}/dependencies",
        data={"csrf_token": CSRF, "predecessor_id": private_id, "dependency_type": "Blocks"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        rows = TaskDependency.query.filter_by(successor_id=scenario["downstream_id"]).all()
        assert [row.predecessor_id for row in rows] == []
