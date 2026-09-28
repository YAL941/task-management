"""Permission-based authorization where a role name used to decide.

Four routes read `session["role"]` and asked "are you an Admin or a Manager?",
and two permission keys - `comments.edit` and `comments.delete` - could be
granted from the role screen while no route looked at them. Both are now
permission-based, and this file pins the result, including every refusal.

Behaviour is preserved deliberately: a manager could create and delete teams and
run meetings before, so the seeded `Manager` role is given the matching grants
rather than losing the ability. The difference a test can see is that a custom
role can now hold the team keys, and a user with only the `Admin` *name* in the
session no longer passes.
"""

from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    AuditLog,
    Comment,
    Permission,
    Role,
    RolePermission,
    Task,
    Team,
    TeamMember,
    User,
    UserRole,
    app,
    db,
    has_permission,
)

CSRF = "permission-model-csrf"
CREATED_AT = "2026-09-28T16:00:00"


def session_client(user_id, role="User"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "permission-model"
        session["role"] = role
        session["csrf_token"] = CSRF
    return client


@pytest.fixture
def workspace():
    created = {"users": [], "roles": [], "tasks": [], "teams": [], "members": []}

    def make_user(label, legacy_role="Guest", grants=()):
        with app.app_context():
            user = User(
                first_name="Perm",
                last_name=label,
                username=f"perm_model_{label.lower()}_{uuid4().hex[:8]}",
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

    team_leader = make_user("Leader", legacy_role="User")
    team_manager = make_user(
        "Manager",
        grants=(("teams.view", "ANY"), ("teams.create", "ANY"), ("teams.delete", "ANY"),
                ("teams.manage_members", "ANY"), ("teams.manage_meetings", "ANY")),
    )
    outsider = make_user("Outsider")

    with app.app_context():
        team = Team(
            name=f"Permission Model Team {uuid4().hex[:8]}",
            description="Team used by the permission model test",
            leader_id=team_leader,
            status="Active",
            meeting_status="Scheduled",
            meeting_url="https://meet.example.test/room",
            created_at=CREATED_AT,
        )
        db.session.add(team)
        db.session.flush()
        created["teams"].append(team.id)
        member = TeamMember(
            team_id=team.id,
            user_id=team_leader,
            permissions="view_tasks,create_tasks,post_messages,manage_meetings",
            created_at=CREATED_AT,
        )
        db.session.add(member)
        db.session.flush()
        created["members"].append(member.id)
        task = Task(
            title="Permission model task",
            status="Pending",
            priority="Medium",
            creator_id=admin.id,
            user_id=team_leader,
            team_id=team.id,
        )
        db.session.add(task)
        db.session.flush()
        created["tasks"].append(task.id)
        db.session.commit()
        task_id = task.id
        team_id = team.id
        admin_id = admin.id

    context = {
        "admin_id": admin_id,
        "leader_id": team_leader,
        "manager_id": team_manager,
        "outsider_id": outsider,
        # Plain ids: the ORM objects are detached once the fixture's context
        # exits, and the tests below run in their own contexts.
        "team_id": team_id,
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
                .filter((AuditLog.user_id.in_(user_ids)) | (AuditLog.entity_id.in_(task_ids))).all()
            }
            from main import AuditLogScopeOwner, Notification, UserPresence

            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_ids)).delete(synchronize_session=False)
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.owner_user_id.in_(user_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_ids)).delete(synchronize_session=False)
            Notification.query.filter(Notification.user_id.in_(user_ids)).delete(synchronize_session=False)
            UserPresence.query.filter(UserPresence.user_id.in_(user_ids)).delete(synchronize_session=False)
            Comment.query.filter(Comment.task_id.in_(task_ids)).delete(synchronize_session=False)
            from main import Detail, TaskDependency

            TaskDependency.query.filter(
                (TaskDependency.predecessor_id.in_(task_ids)) | (TaskDependency.successor_id.in_(task_ids))
            ).delete(synchronize_session=False)
            Detail.query.filter(Detail.task_id.in_(task_ids)).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(task_ids)).delete(synchronize_session=False)
            TeamMember.query.filter(TeamMember.team_id.in_(created["teams"])).delete(synchronize_session=False)
            from main import TeamMeeting, TeamMessage

            # Starting and ending a meeting writes rows that reference the team.
            TeamMeeting.query.filter(TeamMeeting.team_id.in_(created["teams"])).delete(synchronize_session=False)
            TeamMessage.query.filter(TeamMessage.team_id.in_(created["teams"])).delete(synchronize_session=False)
            Team.query.filter(Team.id.in_(created["teams"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(user_ids)).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(user_ids)).delete(synchronize_session=False)
            db.session.commit()


def grant(user_id, key, scope, created):
    permission = Permission.query.filter_by(key=key).first()
    assert permission is not None, key
    role = Role(
        name=f"perm_model_{key.replace('.', '_')}_{uuid4().hex[:8]}",
        description="Permission model test role",
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


def denial_reasons(limit=3):
    with app.app_context():
        return [
            row.new_value
            for row in AuditLog.query.filter_by(action="access_denied").order_by(AuditLog.id.desc()).limit(limit).all()
        ]


def test_the_team_keys_are_in_the_catalog_and_seeded(workspace):
    with app.app_context():
        for key in ("teams.view", "teams.create", "teams.edit", "teams.delete", "teams.manage_members", "teams.manage_meetings"):
            assert Permission.query.filter_by(key=key).first() is not None, key
        # The seeded roles keep the abilities they had when the check was a role
        # name: an admin and a manager could create and delete teams.
        for role_name in ("Admin", "Super Admin", "Manager"):
            role = Role.query.filter_by(name=role_name).first()
            keys = {
                permission_key
                for (permission_key,) in db.session.query(Permission.key)
                .join(RolePermission, RolePermission.permission_id == Permission.id)
                .filter_by(role_id=role.id)
                .all()
            }
            assert {"teams.view", "teams.create", "teams.delete", "teams.manage_members", "teams.manage_meetings"} <= keys, role_name
        # A plain user can see the teams they are in, and holds no team grant.
        user_role = Role.query.filter_by(name="User").first()
        user_keys = {
            permission_key
            for (permission_key,) in db.session.query(Permission.key)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .filter_by(role_id=user_role.id)
            .all()
        }
        assert "teams.view" in user_keys
        assert "teams.create" not in user_keys
        assert "teams.delete" not in user_keys


def test_creating_a_team_needs_teams_create(workspace):
    outsider = session_client(workspace["outsider_id"])
    with app.app_context():
        before = Team.query.count()
    refused = outsider.post(
        "/teams",
        data={"csrf_token": CSRF, "name": f"Refused {uuid4().hex[:6]}", "leader_id": workspace["leader_id"]},
        follow_redirects=False,
    )
    assert refused.status_code == 302
    with app.app_context():
        assert Team.query.count() == before
        assert any("team_create_forbidden" in value for value in denial_reasons())

    manager = session_client(workspace["manager_id"], role="Manager")
    allowed = manager.post(
        "/teams",
        data={"csrf_token": CSRF, "name": f"Allowed {uuid4().hex[:6]}", "leader_id": workspace["leader_id"]},
        follow_redirects=False,
    )
    assert allowed.status_code == 302
    with app.app_context():
        created = Team.query.filter(Team.name.like("Allowed %")).one()
        workspace["created"]["teams"].append(created.id)
        TeamMember.query.filter_by(team_id=created.id).delete()
        db.session.commit()


def test_adding_a_member_needs_its_own_grant(workspace):
    outsider = session_client(workspace["outsider_id"])
    with app.app_context():
        before = TeamMember.query.count()
    refused = outsider.post(
        "/teams",
        data={"csrf_token": CSRF, "action": "member", "team_id": workspace["team_id"], "user_id": workspace["outsider_id"]},
        follow_redirects=False,
    )
    assert refused.status_code == 302
    with app.app_context():
        assert TeamMember.query.count() == before
        assert any("team_member_forbidden" in value for value in denial_reasons())

    # A grant for creating a team is not a grant for changing its roster.
    with app.app_context():
        grant(workspace["outsider_id"], "teams.create", "ANY", workspace["created"])
    still_refused = outsider.post(
        "/teams",
        data={"csrf_token": CSRF, "action": "member", "team_id": workspace["team_id"], "user_id": workspace["outsider_id"]},
        follow_redirects=False,
    )
    assert still_refused.status_code == 302
    with app.app_context():
        assert TeamMember.query.count() == before

    with app.app_context():
        grant(workspace["outsider_id"], "teams.manage_members", "ANY", workspace["created"])
    allowed = outsider.post(
        "/teams",
        data={"csrf_token": CSRF, "action": "member", "team_id": workspace["team_id"], "user_id": workspace["outsider_id"]},
        follow_redirects=False,
    )
    assert allowed.status_code == 302
    with app.app_context():
        assert TeamMember.query.count() == before + 1
        added = TeamMember.query.filter_by(team_id=workspace["team_id"], user_id=workspace["outsider_id"]).one()
        workspace["created"]["members"].append(added.id)
        db.session.commit()


def test_deleting_a_team_needs_teams_delete(workspace):
    outsider = session_client(workspace["outsider_id"])
    with app.app_context():
        keep = Team(
            name=f"Keep {uuid4().hex[:6]}",
            leader_id=workspace["leader_id"],
            created_at=CREATED_AT,
        )
        db.session.add(keep)
        db.session.commit()
        keep_id = keep.id
    refused = outsider.post(
        "/teams",
        data={"csrf_token": CSRF, "action": "delete", "team_id": keep_id},
        follow_redirects=False,
    )
    assert refused.status_code == 302
    with app.app_context():
        assert db.session.get(Team, keep_id) is not None
        assert any("team_delete_forbidden" in value for value in denial_reasons())

    with app.app_context():
        grant(workspace["outsider_id"], "teams.delete", "ANY", workspace["created"])
    allowed = outsider.post(
        "/teams",
        data={"csrf_token": CSRF, "action": "delete", "team_id": keep_id},
        follow_redirects=False,
    )
    assert allowed.status_code == 302
    with app.app_context():
        assert db.session.get(Team, keep_id) is None


def test_meetings_need_teams_manage_meetings_or_the_team_grant(workspace):
    # The leader holds the team-level `manage_meetings` permission, so the team
    # grant alone lets the meeting run.
    leader = session_client(workspace["leader_id"])
    started = leader.post(
        f"/teams/{workspace['team_id']}/meeting/start",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert started.status_code == 302
    with app.app_context():
        assert db.session.get(Team, workspace["team_id"]).meeting_status == "Live"
    ended = leader.post(
        f"/teams/{workspace['team_id']}/meeting/end",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert ended.status_code == 302
    with app.app_context():
        assert db.session.get(Team, workspace["team_id"]).meeting_status != "Live"

    outsider = session_client(workspace["outsider_id"])
    refused = outsider.post(
        f"/teams/{workspace['team_id']}/meeting/start",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert refused.status_code == 302
    with app.app_context():
        assert db.session.get(Team, workspace["team_id"]).meeting_status != "Live"
        assert any("meeting_start_forbidden" in value for value in denial_reasons())

    with app.app_context():
        grant(workspace["outsider_id"], "teams.manage_meetings", "ANY", workspace["created"])
    allowed = outsider.post(
        f"/teams/{workspace['team_id']}/meeting/start",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert allowed.status_code == 302
    with app.app_context():
        assert db.session.get(Team, workspace["team_id"]).meeting_status == "Live"
    outsider.post(f"/teams/{workspace['team_id']}/meeting/end", data={"csrf_token": CSRF}, follow_redirects=False)


def test_the_role_name_alone_no_longer_opens_a_team(workspace):
    """A session claiming to be an Admin is not the same as holding the grant.

    The old check read `session["role"]`, which is written at login and could be
    any value a caller put in a cookie-backed session. Now the database decides.
    """
    impostor = app.test_client()
    with impostor.session_transaction() as session:
        session["user_id"] = workspace["outsider_id"]
        session["username"] = "impostor"
        session["role"] = "Admin"
        session["csrf_token"] = CSRF
    response = impostor.post(
        "/teams",
        data={"csrf_token": CSRF, "name": f"Impostor {uuid4().hex[:6]}", "leader_id": workspace["leader_id"]},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        assert Team.query.filter(Team.name.like("Impostor %")).first() is None
        assert any("team_create_forbidden" in value for value in denial_reasons())


def test_dependencies_follow_the_edit_grant(workspace):
    with app.app_context():
        blocker = Task(
            title="Blocker for the dependency test",
            status="Pending",
            priority="Medium",
            creator_id=workspace["admin_id"],
            user_id=workspace["leader_id"],
        )
        db.session.add(blocker)
        db.session.commit()
        workspace["created"]["tasks"].append(blocker.id)
        blocker_id = blocker.id

    outsider = session_client(workspace["outsider_id"])
    refused = outsider.post(
        f"/tasks/{workspace['task_id']}/dependencies",
        data={"csrf_token": CSRF, "predecessor_id": blocker_id, "dependency_type": "Blocks"},
        follow_redirects=False,
    )
    assert refused.status_code == 302
    with app.app_context():
        from main import TaskDependency

        assert TaskDependency.query.filter_by(successor_id=workspace["task_id"]).count() == 0
        assert any("task_dependency_manage_forbidden" in value for value in denial_reasons())

    # The task's sender may manage its dependencies through the own edit grant.
    sender = session_client(workspace["admin_id"], role="Admin")
    allowed = sender.post(
        f"/tasks/{workspace['task_id']}/dependencies",
        data={"csrf_token": CSRF, "predecessor_id": blocker_id, "dependency_type": "Blocks"},
        follow_redirects=False,
    )
    assert allowed.status_code == 302
    with app.app_context():
        from main import TaskDependency

        assert TaskDependency.query.filter_by(successor_id=workspace["task_id"]).count() == 1


def test_a_comment_author_can_edit_and_delete_their_own(workspace):
    author = session_client(workspace["leader_id"])
    with app.app_context():
        comment = Comment(
            task_id=workspace["task_id"],
            user_id=workspace["leader_id"],
            body="First version",
            created_at=CREATED_AT,
        )
        db.session.add(comment)
        db.session.commit()
        comment_id = comment.id

    assert author.post(
        f"/tasks/{workspace['task_id']}/comments/{comment_id}/edit",
        data={"csrf_token": CSRF, "body": "Corrected version"},
        follow_redirects=False,
    ).status_code == 302
    with app.app_context():
        assert db.session.get(Comment, comment_id).body == "Corrected version"
        edit_log = AuditLog.query.filter_by(action="comment_edited", entity="comment", entity_id=comment_id).one()
        assert '"First version"' in edit_log.old_value
        assert '"Corrected version"' in edit_log.new_value

    assert author.post(
        f"/tasks/{workspace['task_id']}/comments/{comment_id}/delete",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    ).status_code == 302
    with app.app_context():
        assert db.session.get(Comment, comment_id) is None
        assert AuditLog.query.filter_by(action="comment_deleted", entity="comment", entity_id=comment_id).count() == 1


def test_nobody_else_can_touch_someone_elses_comment(workspace):
    with app.app_context():
        comment = Comment(
            task_id=workspace["task_id"],
            user_id=workspace["leader_id"],
            body="Not yours",
            created_at=CREATED_AT,
        )
        db.session.add(comment)
        db.session.commit()
        comment_id = comment.id

    outsider = session_client(workspace["outsider_id"])
    assert outsider.post(
        f"/tasks/{workspace['task_id']}/comments/{comment_id}/edit",
        data={"csrf_token": CSRF, "body": "Rewritten"},
        follow_redirects=False,
    ).status_code == 302
    assert outsider.post(
        f"/tasks/{workspace['task_id']}/comments/{comment_id}/delete",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    ).status_code == 302
    with app.app_context():
        assert db.session.get(Comment, comment_id).body == "Not yours"
        reasons = denial_reasons(limit=2)
        assert any("comment_edit_forbidden" in value for value in reasons)
        assert any("comment_delete_forbidden" in value for value in reasons)


def test_the_moderation_grants_reach_other_peoples_comments(workspace):
    with app.app_context():
        comment = Comment(
            task_id=workspace["task_id"],
            user_id=workspace["leader_id"],
            body="Moderated",
            created_at=CREATED_AT,
        )
        db.session.add(comment)
        db.session.commit()
        comment_id = comment.id
        grant(workspace["outsider_id"], "comments.edit", "ANY", workspace["created"])
        grant(workspace["outsider_id"], "comments.delete", "ANY", workspace["created"])

    moderator = session_client(workspace["outsider_id"])
    assert moderator.post(
        f"/tasks/{workspace['task_id']}/comments/{comment_id}/edit",
        data={"csrf_token": CSRF, "body": "Moderated edit"},
        follow_redirects=False,
    ).status_code == 302
    with app.app_context():
        assert db.session.get(Comment, comment_id).body == "Moderated edit"
    assert moderator.post(
        f"/tasks/{workspace['task_id']}/comments/{comment_id}/delete",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    ).status_code == 302
    with app.app_context():
        assert db.session.get(Comment, comment_id) is None


def test_the_comment_actions_follow_the_grants_on_the_page(workspace):
    """The buttons on the page come from the same decision as the routes."""
    with app.app_context():
        own = Comment(task_id=workspace["task_id"], user_id=workspace["leader_id"], body="Mine", created_at=CREATED_AT)
        other = Comment(task_id=workspace["task_id"], user_id=workspace["admin_id"], body="Theirs", created_at=CREATED_AT)
        db.session.add_all([own, other])
        db.session.commit()
        own_id, other_id = own.id, other.id

    leader_html = session_client(workspace["leader_id"]).get(
        f"/tasks/{workspace['task_id']}/comments"
    ).get_data(as_text=True)
    assert f"/comments/{own_id}/edit" in leader_html
    assert f"/comments/{other_id}/edit" not in leader_html
    assert f"/comments/{own_id}/delete" in leader_html
    assert f"/comments/{other_id}/delete" not in leader_html

    with app.app_context():
        grant(workspace["leader_id"], "comments.edit", "ANY", workspace["created"])
    moderator_html = session_client(workspace["leader_id"]).get(
        f"/tasks/{workspace['task_id']}/comments"
    ).get_data(as_text=True)
    assert f"/comments/{other_id}/edit" in moderator_html


def test_a_comment_from_another_task_cannot_be_reached(workspace):
    with app.app_context():
        other_task = Task(
            title="Somebody else's task",
            status="Pending",
            priority="Medium",
            creator_id=workspace["admin_id"],
            user_id=workspace["admin_id"],
        )
        db.session.add(other_task)
        db.session.flush()
        workspace["created"]["tasks"].append(other_task.id)
        comment = Comment(task_id=other_task.id, user_id=workspace["leader_id"], body="Wrong task", created_at=CREATED_AT)
        db.session.add(comment)
        db.session.commit()
        comment_id = comment.id
        other_task_id = other_task.id

    response = session_client(workspace["leader_id"]).post(
        f"/tasks/{workspace['task_id']}/comments/{comment_id}/delete",
        data={"csrf_token": CSRF},
        follow_redirects=False,
    )
    assert response.status_code == 302
    with app.app_context():
        assert db.session.get(Comment, comment_id) is not None
