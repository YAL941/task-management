"""Reassignment and the per-task history.

`tasks.reassign` was a key an admin could tick on the role screen with no screen
behind it, and the task page showed only the audit rows filed under the task, so
a comment that was edited and an attachment that was removed were invisible in
the place a reader looks for them. Both are now real, and this file pins the
behaviour including every refusal.
"""

import json
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    Attachment,
    AuditLog,
    Comment,
    Detail,
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

CSRF = "reassign-csrf"
CREATED_AT = "2026-09-28T17:00:00"


def session_client(user_id, role="User"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "reassign-test"
        session["role"] = role
        session["csrf_token"] = CSRF
    return client


@pytest.fixture
def scenario():
    created = {"users": [], "roles": [], "tasks": []}

    def make_user(label, legacy_role="Guest", grants=()):
        with app.app_context():
            user = User(
                first_name="Re",
                last_name=label,
                username=f"reassign_{label.lower()}_{uuid4().hex[:8]}",
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

    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        assert admin is not None
        admin_id = admin.id

    sender = make_user("Sender", legacy_role="User")
    first_assignee = make_user("First", legacy_role="User", grants=(("tasks.view", "OWN"),))
    second_assignee = make_user("Second", legacy_role="User", grants=(("tasks.view", "OWN"),))
    manager = make_user("Manager", grants=(("tasks.view", "ANY"), ("tasks.reassign", "ANY")))
    outsider = make_user("Outsider")

    with app.app_context():
        task = Task(
            title="Task to reassign",
            status="Pending",
            priority="Medium",
            creator_id=sender,
            user_id=first_assignee,
        )
        db.session.add(task)
        db.session.flush()
        created["tasks"].append(task.id)
        db.session.add(Detail(task_id=task.id, description="Reassign me", updated_at=CREATED_AT))
        comment = Comment(task_id=task.id, user_id=first_assignee, body="A comment to edit", created_at=CREATED_AT)
        db.session.add(comment)
        db.session.flush()
        attachment = Attachment(
            task_id=task.id,
            uploaded_by=first_assignee,
            filename="note.pdf",
            storage_name=f"tasks/{task.id}/note.pdf",
            mime_type="application/pdf",
            file_size=4,
            created_at=CREATED_AT,
        )
        db.session.add(attachment)
        db.session.commit()
        task_id, comment_id, attachment_id = task.id, comment.id, attachment.id

    context = {
        "admin_id": admin_id,
        "sender_id": sender,
        "first_id": first_assignee,
        "second_id": second_assignee,
        "manager_id": manager,
        "outsider_id": outsider,
        "task_id": task_id,
        "comment_id": comment_id,
        "attachment_id": attachment_id,
        "created": created,
    }
    try:
        yield context
    finally:
        with app.app_context():
            from main import AuditLogScopeOwner

            user_ids = created["users"]
            task_ids = created["tasks"]
            audit_ids = {
                row[0]
                for row in db.session.query(AuditLog.id)
                .filter(
                    (AuditLog.user_id.in_(user_ids))
                    | (AuditLog.entity_id.in_(task_ids))
                    | (AuditLog.entity_id.in_([context["comment_id"], context["attachment_id"]]))
                ).all()
            }
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_ids)).delete(synchronize_session=False)
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.owner_user_id.in_(user_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
            Notification.query.filter(Notification.user_id.in_(user_ids)).delete(synchronize_session=False)
            RealtimeEvent.query.filter(RealtimeEvent.actor_id.in_(user_ids)).delete(synchronize_session=False)
            UserPresence.query.filter(UserPresence.user_id.in_(user_ids)).delete(synchronize_session=False)
            Attachment.query.filter(Attachment.task_id.in_(task_ids)).delete(synchronize_session=False)
            Comment.query.filter(Comment.task_id.in_(task_ids)).delete(synchronize_session=False)
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


def grant(user_id, key, scope, created):
    permission = Permission.query.filter_by(key=key).first()
    assert permission is not None, key
    role = Role(
        name=f"reassign_{key.replace('.', '_')}_{uuid4().hex[:8]}",
        description="Reassign test role",
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


def test_reassignment_needs_the_grant(scenario):
    client = session_client(scenario["outsider_id"])
    response = client.post(
        f"/tasks/{scenario['task_id']}/reassign",
        data={"csrf_token": CSRF, "assigned_user_id": scenario["second_id"]},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Task, scenario["task_id"]).user_id == scenario["first_id"]
        denial = (
            AuditLog.query.filter_by(action="access_denied", entity="task", entity_id=scenario["task_id"])
            .order_by(AuditLog.id.desc())
            .first()
        )
        assert denial is not None
        assert "task_reassign_forbidden" in denial.new_value


def test_the_sender_cannot_reassign_without_the_grant(scenario):
    """The person who sent a task does not get to move it between people."""
    with app.app_context():
        assert has_permission(scenario["sender_id"], "tasks.reassign") is False
    client = session_client(scenario["sender_id"])
    assert client.post(
        f"/tasks/{scenario['task_id']}/reassign",
        data={"csrf_token": CSRF, "assigned_user_id": scenario["second_id"]},
        follow_redirects=False,
    ).status_code == 302
    with app.app_context():
        assert db.session.get(Task, scenario["task_id"]).user_id == scenario["first_id"]


def test_reassignment_moves_the_task_and_tells_eone_involved(scenario):
    client = session_client(scenario["manager_id"], role="Manager")
    response = client.post(
        f"/tasks/{scenario['task_id']}/reassign",
        data={"csrf_token": CSRF, "assigned_user_id": scenario["second_id"]},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        task = db.session.get(Task, scenario["task_id"])
        assert task.user_id == scenario["second_id"]
        log = AuditLog.query.filter_by(action="task_reassigned", entity="task", entity_id=task.id).one()
        old_values = json.loads(log.old_value)
        new_values = json.loads(log.new_value)
        assert old_values["assignee_id"] == scenario["first_id"]
        assert new_values["assignee_id"] == scenario["second_id"]
        # The event is visible to the new assignee, the old one, and the sender.
        from main import AuditScopeResolver

        assert {scenario["first_id"], scenario["second_id"], scenario["sender_id"]} <= AuditScopeResolver.resolve_owners(log)
        # The three who need to know are told, and the manager is not.
        recipients = {row.user_id for row in Notification.query.filter(Notification.message.contains("Task")).all()}
        assert {scenario["second_id"], scenario["sender_id"], scenario["first_id"]} <= recipients
        assert scenario["manager_id"] not in recipients
        event = RealtimeEvent.query.filter_by(event_type="TASK_REASSIGNED").order_by(RealtimeEvent.id.desc()).first()
        assert event is not None
        assert json.loads(event.payload)["newAssigneeId"] == scenario["second_id"]


def test_reassignment_refuses_the_same_person_and_an_unknown_one(scenario):
    client = session_client(scenario["manager_id"], role="Manager")
    same = client.post(
        f"/tasks/{scenario['task_id']}/reassign",
        data={"csrf_token": CSRF, "assigned_user_id": scenario["first_id"]},
        follow_redirects=False,
    )
    assert same.status_code == 302
    unknown = client.post(
        f"/tasks/{scenario['task_id']}/reassign",
        data={"csrf_token": CSRF, "assigned_user_id": 99999999},
        follow_redirects=False,
    )
    assert unknown.status_code == 302
    with app.app_context():
        assert db.session.get(Task, scenario["task_id"]).user_id == scenario["first_id"]
        assert AuditLog.query.filter_by(action="task_reassigned", entity="task").count() == 0


def test_reassignment_needs_the_csrf_token(scenario):
    client = session_client(scenario["manager_id"], role="Manager")
    response = client.post(
        f"/tasks/{scenario['task_id']}/reassign",
        data={"assigned_user_id": scenario["second_id"]},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Task, scenario["task_id"]).user_id == scenario["first_id"]


def test_the_reassign_form_only_appears_with_the_grant(scenario):
    """The viewer is the task's own assignee; the grant decides the form.

    Visibility is a separate rule: `can_access_task` lets the assignee, the
    sender, an admin, and a team member open a task, so the page is read as the
    person already working on it.
    """
    without = session_client(scenario["first_id"]).get(
        f"/tasks/{scenario['task_id']}/view"
    ).get_data(as_text=True)
    assert "/reassign" not in without

    with app.app_context():
        grant(scenario["first_id"], "tasks.reassign", "OWN", scenario["created"])
    with_grant = session_client(scenario["first_id"]).get(
        f"/tasks/{scenario['task_id']}/view"
    ).get_data(as_text=True)
    assert f"/tasks/{scenario['task_id']}/reassign" in with_grant
    # The current assignee is not offered as a choice.
    assert f'<option value="{scenario["first_id"]}"' not in with_grant


def test_the_task_history_includes_its_comments_and_attachments(scenario):
    """Editing a comment or removing a file belongs in the task's story."""
    # A comment edit and an attachment removal, both filed under their own entity.
    with app.app_context():
        session_client(scenario["first_id"]).post(
            f"/tasks/{scenario['task_id']}/comments/{scenario['comment_id']}/edit",
            data={"csrf_token": CSRF, "body": "A comment, corrected"},
            follow_redirects=False,
        )
        grant(scenario["first_id"], "attachments.delete", "OWN", scenario["created"])
        session_client(scenario["first_id"]).post(
            f"/attachments/{scenario['attachment_id']}/delete",
            data={"csrf_token": CSRF},
            follow_redirects=False,
        )
        session_client(scenario["manager_id"], role="Manager").post(
            f"/tasks/{scenario['task_id']}/reassign",
            data={"csrf_token": CSRF, "assigned_user_id": scenario["second_id"]},
            follow_redirects=False,
        )

    # The person who now holds the task reads its page: the reassignment, the
    # comment edit, and the attachment removal all read as sentences here, not
    # only on the audit screen.
    html = session_client(scenario["second_id"]).get(
        f"/tasks/{scenario['task_id']}/view"
    ).get_data(as_text=True)
    assert "reassigned" in html.lower()
    assert "comment" in html.lower()
    assert "attachment" in html.lower()


def test_a_task_history_only_shows_events_of_that_task(scenario):
    with app.app_context():
        other = Task(
            title="Somebody else's history",
            status="Pending",
            priority="Low",
            creator_id=scenario["first_id"],
            user_id=scenario["first_id"],
        )
        db.session.add(other)
        db.session.flush()
        scenario["created"]["tasks"].append(other.id)
        other_id = other.id
        log = AuditLog(
            user_id=scenario["first_id"],
            action="TASK_CREATED",
            entity="task",
            entity_id=other_id,
            new_value=json.dumps({"title": "SECRET_OTHER_TASK_TITLE"}),
            created_at=CREATED_AT,
        )
        db.session.add(log)
        db.session.commit()

    html = session_client(scenario["first_id"]).get(
        f"/tasks/{scenario['task_id']}/view"
    ).get_data(as_text=True)
    assert "SECRET_OTHER_TASK_TITLE" not in html
    # And the other task's page does show its own.
    other_html = session_client(scenario["first_id"]).get(
        f"/tasks/{other_id}/view"
    ).get_data(as_text=True)
    assert "SECRET_OTHER_TASK_TITLE" in other_html


def test_the_history_states_when_it_is_truncated(scenario):
    with app.app_context():
        rows = [
            AuditLog(
                user_id=scenario["first_id"],
                action="TASK_UPDATED",
                entity="task",
                entity_id=scenario["task_id"],
                new_value=json.dumps({"title": f"Revision {index}"}),
                created_at=CREATED_AT,
            )
            for index in range(105)
        ]
        db.session.add_all(rows)
        db.session.commit()
        assert db.session.get(Task, scenario["task_id"]) is not None

    html = session_client(scenario["first_id"]).get(
        f"/tasks/{scenario['task_id']}/view"
    ).get_data(as_text=True)
    assert "of 10" in html  # "the most recent 100 of 1xx recorded events"
    assert "audit log page" in html
