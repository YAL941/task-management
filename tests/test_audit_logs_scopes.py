import json
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    Attachment,
    AuditLog,
    AuditLogScopeOwner,
    AuditScopeResolver,
    AutomationRule,
    Comment,
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
    UserRole,
    app,
    db,
    write_audit,
)


@pytest.fixture
def audit_scope_scenario():
    created_ids = {
        "audit_logs": [],
        "users": [],
        "roles": [],
        "teams": [],
        "tasks": [],
        "comments": [],
        "attachments": [],
        "automation_rules": [],
    }

    with app.app_context():
        permission = Permission.query.filter_by(key="audit_logs.view").first()
        assert permission is not None
        created_at = "2026-09-28T10:00:00"

        def make_user(label, scopes=()):
            user = User(
                first_name="Scope",
                last_name=label,
                username=f"scope_{label.lower()}_{uuid4().hex[:8]}",
                password_hash=generate_password_hash("temporary-test-password"),
                role="User",
                created_at=created_at,
            )
            db.session.add(user)
            db.session.flush()
            created_ids["users"].append(user.id)
            for scope in scopes:
                role = Role(
                    name=f"scope_{label}_{scope}_{uuid4().hex[:8]}",
                    description="Audit scope test role",
                    is_system=False,
                    created_at=created_at,
                )
                db.session.add(role)
                db.session.flush()
                created_ids["roles"].append(role.id)
                db.session.add(RolePermission(role_id=role.id, permission_id=permission.id, scope=scope))
                db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=user.id, created_at=created_at))
            return user

        creator = make_user("Creator", ("OWN",))
        assignee = make_user("Assignee", ("OWN",))
        commenter = make_user("Commenter", ("OWN",))
        automation_owner = make_user("Automation", ("OWN",))
        team_viewer = make_user("TeamViewer", ("TEAM",))
        other_team_viewer = make_user("OtherTeam", ("TEAM",))
        combined_viewer = make_user("Combined", ("OWN", "TEAM"))
        any_viewer = make_user("AnyViewer", ("ANY",))
        no_permission = make_user("NoPermission")
        invalid_scope = make_user("InvalidScope", ("INVALID",))
        outsider = make_user("Outsider")

        team_a = Team(name=f"Scope Team A {uuid4().hex[:8]}", created_at=created_at)
        team_b = Team(name=f"Scope Team B {uuid4().hex[:8]}", created_at=created_at)
        db.session.add_all([team_a, team_b])
        db.session.flush()
        created_ids["teams"].extend([team_a.id, team_b.id])
        db.session.add_all([
            TeamMember(team_id=team_a.id, user_id=team_viewer.id, created_at=created_at),
            TeamMember(team_id=team_a.id, user_id=combined_viewer.id, created_at=created_at),
            TeamMember(team_id=team_b.id, user_id=other_team_viewer.id, created_at=created_at),
        ])

        owned_task = Task(
            title="Scope owned task",
            status="Pending",
            priority="Medium",
            creator_id=creator.id,
            user_id=assignee.id,
            team_id=team_a.id,
        )
        unrelated_task = Task(
            title="Scope unrelated task",
            status="Pending",
            priority="Medium",
            creator_id=outsider.id,
            user_id=outsider.id,
            team_id=team_b.id,
        )
        deleted_snapshot_task = Task(
            title="Scope deleted snapshot task",
            status="Pending",
            priority="Medium",
            creator_id=creator.id,
            user_id=assignee.id,
            team_id=team_a.id,
        )
        deleted_unscoped_task = Task(
            title="Scope deleted historical task",
            status="Pending",
            priority="Medium",
            creator_id=creator.id,
            user_id=assignee.id,
            team_id=team_a.id,
        )
        db.session.add_all([owned_task, unrelated_task, deleted_snapshot_task, deleted_unscoped_task])
        db.session.flush()
        created_ids["tasks"].extend([owned_task.id, unrelated_task.id, deleted_snapshot_task.id, deleted_unscoped_task.id])

        comment = Comment(
            task_id=owned_task.id,
            user_id=commenter.id,
            body="Scope comment",
            created_at=created_at,
        )
        attachment = Attachment(
            task_id=owned_task.id,
            uploaded_by=commenter.id,
            filename="scope-test.txt",
            storage_name=f"scope-tests/{uuid4().hex}.txt",
            mime_type="text/plain",
            file_size=1,
            created_at=created_at,
        )
        automation_rule = AutomationRule(
            name=f"Scope automation {uuid4().hex[:8]}",
            event="status_changed",
            condition="equals",
            value="Completed",
            action="notify",
            created_by=automation_owner.id,
            created_at=created_at,
        )
        db.session.add_all([comment, attachment, automation_rule])
        db.session.flush()
        created_ids["comments"].append(comment.id)
        created_ids["attachments"].append(attachment.id)
        created_ids["automation_rules"].append(automation_rule.id)

        markers = {}

        def add_log(marker, action, entity, entity_id=None, owners=(), team_id=None, actor=None):
            log = AuditLog(
                user_id=actor.id if actor else None,
                action=action,
                entity=entity,
                entity_id=entity_id,
                new_value=marker,
                created_at=created_at,
                scope_team_id=team_id,
            )
            db.session.add(log)
            db.session.flush()
            owner_ids = {owner_id for owner_id in owners if owner_id is not None}
            db.session.add_all(
                AuditLogScopeOwner(audit_log_id=log.id, owner_user_id=owner_id)
                for owner_id in owner_ids
            )
            created_ids["audit_logs"].append(log.id)
            markers[marker] = log.id
            return log

        add_log(
            "SCOPE_TASK_SNAPSHOT", "created", "task", owned_task.id,
            {creator.id, assignee.id}, team_a.id, creator,
        )
        add_log(
            "SCOPE_OTHER_TEAM_TASK", "created", "task", unrelated_task.id,
            {outsider.id}, team_b.id, outsider,
        )
        add_log(
            "SCOPE_COMMENT_SNAPSHOT", "created", "comment", comment.id,
            {commenter.id, creator.id, assignee.id}, team_a.id, commenter,
        )
        add_log(
            "SCOPE_ATTACHMENT_SNAPSHOT", "created", "attachment", attachment.id,
            {creator.id, assignee.id}, team_a.id, commenter,
        )
        add_log(
            "SCOPE_AUTOMATION_SNAPSHOT", "created", "automation_rule", automation_rule.id,
            {automation_owner.id}, actor=automation_owner,
        )

        # Old rows with a live, explicitly identified resource can resolve OWN.
        add_log("SCOPE_LEGACY_TASK_LIVE", "status_changed", "task", owned_task.id, actor=creator)
        add_log("SCOPE_LEGACY_COMMENT_LIVE", "created", "comment", comment.id, actor=commenter)
        add_log("SCOPE_LEGACY_ATTACHMENT_LIVE", "created", "attachment", attachment.id, actor=commenter)
        add_log("SCOPE_LEGACY_AUTOMATION_LIVE", "toggled", "automation_rule", automation_rule.id, actor=automation_owner)

        # Historical team visibility must use the snapshot, not the live task's team.
        add_log("SCOPE_LEGACY_TEAM_MISSING", "status_changed", "task", owned_task.id, actor=creator)
        add_log("SCOPE_UNRESOLVED_ATTACHMENT", "created", "attachment", None, actor=commenter)
        add_log("SCOPE_UNRESOLVED_AUTOMATION", "created", "automation_rule", None, actor=automation_owner)
        add_log("SCOPE_ROLE_ANY_ONLY", "ROLE_PERMISSION_UPDATED", "role", 901, actor=creator)
        add_log("SCOPE_SECURITY_ANY_ONLY", "PASSWORD_CHANGED", "user", creator.id, actor=creator)
        add_log(
            "SCOPE_DELETED_RESOURCE_SNAPSHOT", "deleted", "task", deleted_snapshot_task.id,
            {creator.id, assignee.id}, team_a.id, creator,
        )
        add_log("SCOPE_DELETED_RESOURCE_LEGACY", "deleted", "task", deleted_unscoped_task.id, actor=creator)

        deleted_snapshot_id = deleted_snapshot_task.id
        deleted_unscoped_id = deleted_unscoped_task.id
        db.session.delete(deleted_snapshot_task)
        db.session.delete(deleted_unscoped_task)
        db.session.commit()

        users = {
            "creator": creator.id,
            "assignee": assignee.id,
            "commenter": commenter.id,
            "automation_owner": automation_owner.id,
            "team_viewer": team_viewer.id,
            "other_team_viewer": other_team_viewer.id,
            "combined_viewer": combined_viewer.id,
            "any_viewer": any_viewer.id,
            "no_permission": no_permission.id,
            "invalid_scope": invalid_scope.id,
        }
        task_ids = {"owned": owned_task.id, "deleted_snapshot": deleted_snapshot_id, "deleted_legacy": deleted_unscoped_id}
        team_ids = {"a": team_a.id, "b": team_b.id}

    try:
        yield {
            "users": users,
            "markers": markers,
            "task_ids": task_ids,
            "team_ids": team_ids,
            "cleanup_ids": created_ids,
        }
    finally:
        with app.app_context():
            task_audit_ids = {
                audit_log_id
                for (audit_log_id,) in db.session.query(AuditLog.id).filter(
                    AuditLog.entity == "task",
                    AuditLog.entity_id.in_(created_ids["tasks"]),
                    AuditLog.action.in_({"updated", "status_changed"}),
                ).all()
            }
            actor_audit_ids = {
                audit_log_id
                for (audit_log_id,) in db.session.query(AuditLog.id).filter(
                    AuditLog.user_id.in_(created_ids["users"])
                ).all()
            }
            audit_log_ids = set(created_ids["audit_logs"]) | task_audit_ids | actor_audit_ids
            AuditLogScopeOwner.query.filter(AuditLogScopeOwner.audit_log_id.in_(audit_log_ids)).delete(synchronize_session=False)
            AuditLog.query.filter(AuditLog.id.in_(audit_log_ids)).delete(synchronize_session=False)
            Comment.query.filter(Comment.id.in_(created_ids["comments"])).delete(synchronize_session=False)
            Attachment.query.filter(Attachment.id.in_(created_ids["attachments"])).delete(synchronize_session=False)
            AutomationRule.query.filter(AutomationRule.id.in_(created_ids["automation_rules"])).delete(synchronize_session=False)
            Notification.query.filter(Notification.user_id.in_(created_ids["users"])).delete(synchronize_session=False)
            RealtimeEvent.query.filter(RealtimeEvent.actor_id.in_(created_ids["users"])).delete(synchronize_session=False)
            TeamMember.query.filter(TeamMember.team_id.in_(created_ids["teams"])).delete(synchronize_session=False)
            Detail.query.filter(Detail.task_id.in_(created_ids["tasks"])).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(created_ids["tasks"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(created_ids["users"])).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created_ids["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created_ids["roles"])).delete(synchronize_session=False)
            Team.query.filter(Team.id.in_(created_ids["teams"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(created_ids["users"])).delete(synchronize_session=False)
            db.session.commit()


def scoped_client(user_id):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "scope-test"
        session["role"] = "User"
    return client


def test_own_scope_uses_owner_snapshots_and_fails_closed_for_historical_rows(audit_scope_scenario):
    users = audit_scope_scenario["users"]
    markers = audit_scope_scenario["markers"]

    creator_html = scoped_client(users["creator"]).get("/audit-logs").get_data(as_text=True)
    assert "SCOPE_TASK_SNAPSHOT" in creator_html
    assert "SCOPE_COMMENT_SNAPSHOT" in creator_html
    assert "SCOPE_ATTACHMENT_SNAPSHOT" in creator_html
    assert "SCOPE_LEGACY_TASK_LIVE" not in creator_html
    assert "SCOPE_LEGACY_COMMENT_LIVE" not in creator_html
    assert "SCOPE_LEGACY_ATTACHMENT_LIVE" not in creator_html
    assert "SCOPE_LEGACY_AUTOMATION_LIVE" not in creator_html
    assert "SCOPE_DELETED_RESOURCE_SNAPSHOT" in creator_html
    assert "SCOPE_OTHER_TEAM_TASK" not in creator_html
    assert "SCOPE_ROLE_ANY_ONLY" not in creator_html
    assert "SCOPE_SECURITY_ANY_ONLY" not in creator_html
    assert "SCOPE_DELETED_RESOURCE_LEGACY" not in creator_html

    assignee_html = scoped_client(users["assignee"]).get("/audit-logs").get_data(as_text=True)
    assert "SCOPE_TASK_SNAPSHOT" in assignee_html
    assert "SCOPE_COMMENT_SNAPSHOT" in assignee_html
    assert "SCOPE_ATTACHMENT_SNAPSHOT" in assignee_html

    commenter_html = scoped_client(users["commenter"]).get("/audit-logs").get_data(as_text=True)
    assert "SCOPE_COMMENT_SNAPSHOT" in commenter_html
    assert "SCOPE_LEGACY_COMMENT_LIVE" not in commenter_html
    assert "SCOPE_TASK_SNAPSHOT" not in commenter_html
    assert "SCOPE_ATTACHMENT_SNAPSHOT" not in commenter_html

    automation_html = scoped_client(users["automation_owner"]).get("/audit-logs").get_data(as_text=True)
    assert "SCOPE_AUTOMATION_SNAPSHOT" in automation_html
    assert "SCOPE_LEGACY_AUTOMATION_LIVE" not in automation_html
    assert "SCOPE_ROLE_ANY_ONLY" not in automation_html
    assert markers["SCOPE_AUTOMATION_SNAPSHOT"]


def test_team_scope_requires_snapshot_and_current_membership(audit_scope_scenario):
    users = audit_scope_scenario["users"]
    team_html = scoped_client(users["team_viewer"]).get("/audit-logs").get_data(as_text=True)
    assert "SCOPE_TASK_SNAPSHOT" in team_html
    assert "SCOPE_COMMENT_SNAPSHOT" in team_html
    assert "SCOPE_ATTACHMENT_SNAPSHOT" in team_html
    assert "SCOPE_DELETED_RESOURCE_SNAPSHOT" in team_html
    assert "SCOPE_OTHER_TEAM_TASK" not in team_html
    assert "SCOPE_LEGACY_TEAM_MISSING" not in team_html
    assert "SCOPE_LEGACY_TASK_LIVE" not in team_html
    assert "SCOPE_ROLE_ANY_ONLY" not in team_html
    assert "SCOPE_SECURITY_ANY_ONLY" not in team_html
    assert "SCOPE_UNRESOLVED_ATTACHMENT" not in team_html

    other_team_html = scoped_client(users["other_team_viewer"]).get("/audit-logs").get_data(as_text=True)
    assert "SCOPE_OTHER_TEAM_TASK" in other_team_html
    assert "SCOPE_TASK_SNAPSHOT" not in other_team_html

    combined_html = scoped_client(users["combined_viewer"]).get("/audit-logs").get_data(as_text=True)
    assert "SCOPE_TASK_SNAPSHOT" in combined_html
    assert "SCOPE_OTHER_TEAM_TASK" not in combined_html


def test_any_scope_and_permission_fail_closed(audit_scope_scenario):
    users = audit_scope_scenario["users"]
    any_html = scoped_client(users["any_viewer"]).get("/audit-logs").get_data(as_text=True)
    for marker in audit_scope_scenario["markers"]:
        assert marker in any_html

    denied = scoped_client(users["no_permission"]).get("/audit-logs", follow_redirects=False)
    assert denied.status_code == 302

    invalid = scoped_client(users["invalid_scope"]).get("/audit-logs")
    assert invalid.status_code == 403


def test_write_audit_persists_scope_snapshot_without_repurposing_actor(audit_scope_scenario):
    users = audit_scope_scenario["users"]
    with app.app_context():
        with app.test_request_context("/scope-test"):
            from flask import session

            session["user_id"] = users["commenter"]
            audit_log = write_audit(
                "created",
                "task",
                entity_id=audit_scope_scenario["task_ids"]["owned"],
                scope_owner_ids={users["creator"], users["assignee"]},
                scope_team_id=audit_scope_scenario["team_ids"]["a"],
            )
            db.session.commit()
            audit_log_id = audit_log.id
            assert audit_log.user_id == users["commenter"]
            assert AuditScopeResolver.resolve_owners(audit_log) == {
                users["creator"], users["assignee"]
            }
            assert users["commenter"] not in AuditScopeResolver.resolve_owners(audit_log)
            assert AuditScopeResolver.resolve_team(audit_log) == audit_scope_scenario["team_ids"]["a"]

        AuditLogScopeOwner.query.filter_by(audit_log_id=audit_log_id).delete()
        db.session.delete(db.session.get(AuditLog, audit_log_id))
        db.session.commit()


def test_task_edit_audits_real_changes_and_skips_noops(audit_scope_scenario):
    users = audit_scope_scenario["users"]
    task_id = audit_scope_scenario["task_ids"]["owned"]
    cleanup_ids = audit_scope_scenario["cleanup_ids"]
    client = scoped_client(users["creator"])
    with client.session_transaction() as session:
        session["csrf_token"] = "scope-task-edit-csrf"

    form_data = {
        "csrf_token": "scope-task-edit-csrf",
        "title": "Scope owned task updated",
        "priority": "High",
        "due_date": "2026-10-15",
        "description": "Updated task description",
    }
    response = client.post(f"/edit_task/{task_id}", data=form_data, follow_redirects=False)
    assert response.status_code == 302

    with app.app_context():
        edit_logs = AuditLog.query.filter_by(entity="task", entity_id=task_id, action="updated").all()
        assert len(edit_logs) == 1
        edit_log = edit_logs[0]
        cleanup_ids["audit_logs"].append(edit_log.id)
        assert json.loads(edit_log.old_value) == {
            "title": "Scope owned task",
            "priority": "Medium",
            "due_date": None,
            "description": None,
        }
        edited_values = json.loads(edit_log.new_value)
        assert edited_values.pop("_audit") == {"result": "success"}
        assert edited_values == {
            "title": "Scope owned task updated",
            "priority": "High",
            "due_date": "2026-10-15",
            "description": "Updated task description",
        }
        assert AuditScopeResolver.resolve_owners(edit_log) == {users["creator"], users["assignee"]}
        assert AuditScopeResolver.resolve_team(edit_log) == audit_scope_scenario["team_ids"]["a"]

    repeated = client.post(f"/edit_task/{task_id}", data=form_data, follow_redirects=False)
    assert repeated.status_code == 302
    with app.app_context():
        assert AuditLog.query.filter_by(entity="task", entity_id=task_id, action="updated").count() == 1

    with app.app_context():
        status_before = AuditLog.query.filter_by(
            entity="task", entity_id=task_id, action="status_changed"
        ).count()
    unchanged_status = client.post(
        f"/update_task_status/{task_id}/Pending",
        data={"csrf_token": "scope-task-edit-csrf"},
        follow_redirects=False,
    )
    assert unchanged_status.status_code == 302
    with app.app_context():
        assert AuditLog.query.filter_by(entity="task", entity_id=task_id, action="status_changed").count() == status_before

    changed_status = client.post(
        f"/update_task_status/{task_id}/In%20Progress",
        data={"csrf_token": "scope-task-edit-csrf"},
        follow_redirects=False,
    )
    assert changed_status.status_code == 302
    with app.app_context():
        status_logs = AuditLog.query.filter_by(entity="task", entity_id=task_id, action="status_changed").all()
        assert len(status_logs) == status_before + 1
        status_log = status_logs[-1]
        cleanup_ids["audit_logs"].append(status_log.id)
        assert json.loads(status_log.old_value) == {"status": "Pending"}
        status_values = json.loads(status_log.new_value)
        assert status_values.pop("_audit") == {"result": "success"}
        assert status_values == {"status": "In Progress"}
        assert AuditScopeResolver.resolve_owners(status_log) == {users["creator"], users["assignee"]}


def test_scope_is_applied_before_filters_and_pagination(audit_scope_scenario):
    client = scoped_client(audit_scope_scenario["users"]["team_viewer"])
    hidden_filter = client.get("/audit-logs?action=ROLE_PERMISSION_UPDATED")
    assert "SCOPE_ROLE_ANY_ONLY" not in hidden_filter.get_data(as_text=True)
    assert "Showing 0-0 of 0" in hidden_filter.get_data(as_text=True)

    response = client.get("/audit-logs?page=2&per_page=1&sort=id&order=asc")
    html = response.get_data(as_text=True)
    assert "Showing 2-2 of 4" in html
    assert "SCOPE_ROLE_ANY_ONLY" not in html
    assert "SCOPE_SECURITY_ANY_ONLY" not in html


def test_team_membership_routes_immediately_change_team_log_visibility(audit_scope_scenario):
    users = audit_scope_scenario["users"]
    team_id = audit_scope_scenario["team_ids"]["a"]
    member_id = users["team_viewer"]

    manager_client = app.test_client()
    with manager_client.session_transaction() as session:
        session["user_id"] = users["creator"]
        session["username"] = "scope-manager"
        session["role"] = "Admin"
        session["csrf_token"] = "scope-membership-csrf"

    removed = manager_client.post(
        f"/teams/{team_id}",
        data={
            "csrf_token": "scope-membership-csrf",
            "action": "remove_member",
            "member_id": member_id,
        },
        follow_redirects=False,
    )
    assert removed.status_code == 302
    hidden = scoped_client(member_id).get("/audit-logs").get_data(as_text=True)
    assert "SCOPE_TASK_SNAPSHOT" not in hidden

    added = manager_client.post(
        "/teams",
        data={
            "csrf_token": "scope-membership-csrf",
            "action": "member",
            "team_id": team_id,
            "user_id": member_id,
        },
        follow_redirects=False,
    )
    assert added.status_code == 302
    visible = scoped_client(member_id).get("/audit-logs").get_data(as_text=True)
    assert "SCOPE_TASK_SNAPSHOT" in visible