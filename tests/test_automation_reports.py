"""Automation rules and performance reports.

The automation rules and the report export both exist as screens, so the tests
here pin the behaviour a user actually depends on:

* a rule fires inside the request that satisfies it, not on a later sweep,
* the notification reaches the assignee, not the creator,
* the recipient is pushed the notification over the live connection,
* a rule fires once per task and state, so a repeated sweep stays silent,
* `changes_to` needs a real transition while `equals` matches the current state,
* a disabled rule and an unsupported combination do not fire,
* the report is an aggregate scoped to the caller's visible tasks, honours a
  period, and is exportable as PDF, Excel, and CSV.
"""

from datetime import date, timedelta
from io import BytesIO
from uuid import uuid4

import pytest
from werkzeug.security import generate_password_hash

from main import (
    Attachment,
    AuditLog,
    AuditLogScopeOwner,
    AutomationRule,
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
    Team,
    TeamMember,
    User,
    UserPresence,
    UserRole,
    app,
    automation_matches,
    automation_recipient,
    db,
    realtime_token,
    run_automation_once,
    socketio,
    task_report,
)

CSRF = "automation-reports-csrf"
CREATED_AT = "2026-09-28T10:00:00"
TODAY = date.today()


def session_client(user_id, role="User"):
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = "automation-reports"
        session["role"] = role
        session["csrf_token"] = CSRF
    return client


def report_for(user_id, role="Admin", date_from=None, date_to=None):
    """Build a report outside a request; visibility reads the session role."""
    with app.test_request_context("/reports"):
        from flask import session

        session["user_id"] = user_id
        session["role"] = role
        return task_report(user_id, date_from, date_to)


@pytest.fixture
def automation_scenario():
    created = {"users": [], "roles": [], "rules": [], "tasks": [], "teams": []}
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        assert admin is not None

        def make_user(label, legacy_role="Guest", permission_keys=()):
            user = User(
                first_name="Auto",
                last_name=label,
                username=f"auto_{label.lower()}_{uuid4().hex[:8]}",
                password_hash=generate_password_hash("temporary-test-password"),
                role=legacy_role,
                created_at=CREATED_AT,
            )
            db.session.add(user)
            db.session.flush()
            created["users"].append(user.id)
            for key, scope in permission_keys:
                permission = Permission.query.filter_by(key=key).first()
                assert permission is not None, key
                role = Role(
                    name=f"auto_{label}_{key.replace('.', '_')}_{uuid4().hex[:8]}",
                    description="Automation report test role",
                    is_system=False,
                    created_at=CREATED_AT,
                )
                db.session.add(role)
                db.session.flush()
                created["roles"].append(role.id)
                db.session.add(RolePermission(role_id=role.id, permission_id=permission.id, scope=scope))
                db.session.add(UserRole(user_id=user.id, role_id=role.id, assigned_by=admin.id, created_at=CREATED_AT))
            return user

        # The assignee holds the own-level grants the seeded `User` role has, so
        # the person a task is assigned to is the one who can work on it: the
        # status rule makes the assignee the actor, not the admin who sent it.
        assignee = make_user(
            "Assignee",
            permission_keys=(
                ("tasks.view", "OWN"),
                ("tasks.change_status", "OWN"),
                ("comments.create", "OWN"),
            ),
        )
        other = make_user("Other")
        report_only = make_user("ReportOnly", permission_keys=(("reports.view", "ANY"),))
        manage_without_reports = make_user("Manager", permission_keys=(("permissions.manage", "ANY"),))

        team = Team(name=f"Auto Team {uuid4().hex[:8]}", created_at=CREATED_AT)
        db.session.add(team)
        db.session.flush()
        created["teams"].append(team.id)

        # Keep plain ids: the ORM objects from this context are detached once it
        # exits, and the helpers below run in later contexts.
        admin_id = admin.id
        team_id = team.id

        def make_task(label, status="Pending", assignee_id=None, due_date=None):
            task = Task(
                title=label,
                status=status,
                priority="Medium",
                creator_id=admin_id,
                user_id=assignee_id,
                team_id=team_id,
                due_date=due_date,
            )
            db.session.add(task)
            db.session.flush()
            created["tasks"].append(task.id)
            return task

        def make_rule(label, event="status_changed", condition="changes_to", value="Completed", action="notify", enabled=True):
            rule = AutomationRule(
                name=label,
                event=event,
                condition=condition,
                value=value,
                action=action,
                enabled=enabled,
                created_by=admin_id,
                created_at=CREATED_AT,
            )
            db.session.add(rule)
            db.session.flush()
            created["rules"].append(rule.id)
            return rule

        context = {
            "admin_id": admin_id,
            "assignee_id": assignee.id,
            "other_id": other.id,
            "report_only_id": report_only.id,
            "manage_without_reports_id": manage_without_reports.id,
            "team_id": team.id,
            "make_task": make_task,
            "make_rule": make_rule,
            "created": created,
            "tokens": {"assignee": realtime_token(assignee.id)},
        }
        # flush() alone is undone when the app context exits.
        db.session.commit()

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
            EmailLog.query.filter(EmailLog.user_id.in_(user_ids)).delete(synchronize_session=False)
            RealtimeEvent.query.filter(RealtimeEvent.actor_id.in_(user_ids)).delete(synchronize_session=False)
            # Automation markers are the dedupe keys, so they must go too.
            RealtimeEvent.query.filter(RealtimeEvent.event_id.like("automation-%")).delete(synchronize_session=False)
            AutomationRule.query.filter(AutomationRule.id.in_(created["rules"])).delete(synchronize_session=False)
            UserPresence.query.filter(UserPresence.user_id.in_(user_ids)).delete(synchronize_session=False)
            # Completing a task writes a comment, which blocks deleting the task.
            Comment.query.filter(Comment.task_id.in_(task_ids)).delete(synchronize_session=False)
            Attachment.query.filter(Attachment.task_id.in_(task_ids)).delete(synchronize_session=False)
            Detail.query.filter(Detail.task_id.in_(task_ids)).delete(synchronize_session=False)
            TaskDependency.query.filter(
                (TaskDependency.successor_id.in_(task_ids)) | (TaskDependency.predecessor_id.in_(task_ids))
            ).delete(synchronize_session=False)
            Task.query.filter(Task.id.in_(task_ids)).delete(synchronize_session=False)
            TeamMember.query.filter(TeamMember.team_id.in_(created["teams"])).delete(synchronize_session=False)
            Team.query.filter(Team.id.in_(created["teams"])).delete(synchronize_session=False)
            UserRole.query.filter(UserRole.user_id.in_(user_ids)).delete(synchronize_session=False)
            RolePermission.query.filter(RolePermission.role_id.in_(created["roles"])).delete(synchronize_session=False)
            Role.query.filter(Role.id.in_(created["roles"])).delete(synchronize_session=False)
            User.query.filter(User.id.in_(user_ids)).delete(synchronize_session=False)
            db.session.commit()


def test_automation_recipient_is_the_assignee_not_the_creator(automation_scenario):
    with app.app_context():
        task = automation_scenario["make_task"]("Recipient check", assignee_id=automation_scenario["assignee_id"])
        assert automation_recipient(task).id == automation_scenario["assignee_id"]
        unassigned = automation_scenario["make_task"]("No assignee", assignee_id=None)
        # With no assignee the creator is the responsible person.
        assert automation_recipient(unassigned).id == automation_scenario["admin_id"]


def test_a_rule_fires_in_the_status_request_and_reaches_the_assignee(automation_scenario):
    with app.app_context():
        task = automation_scenario["make_task"]("Fires on completion", assignee_id=automation_scenario["assignee_id"])
        automation_scenario["make_rule"]("Notify on completion")
        db.session.commit()
        task_id = task.id

    # The assignee moves their own task, which is the only person allowed to.
    client = session_client(automation_scenario["assignee_id"])
    response = client.post(
        f"/update_task_status/{task_id}/Completed",
        data={"csrf_token": CSRF, "comment": "Done by the automation test"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    with app.app_context():
        assert db.session.get(Task, task_id).status == "Completed"
        messages = [row.message for row in Notification.query.filter_by(user_id=automation_scenario["assignee_id"]).all()]
        assert any("matched task: Fires on completion" in message for message in messages)
        # The creator must not be the recipient here.
        assert not Notification.query.filter(
            Notification.user_id == automation_scenario["admin_id"],
            Notification.message.like("%matched task%"),
        ).first()
        audit = AuditLog.query.filter_by(action="automation_triggered", entity="task", entity_id=task_id).one()
        assert "Notify on completion" in audit.new_value
        assert "probe" not in audit.new_value


def test_the_recipient_is_pushed_the_automation_notification(automation_scenario):
    with app.app_context():
        task = automation_scenario["make_task"]("Pushed automation", assignee_id=automation_scenario["assignee_id"])
        rule = automation_scenario["make_rule"]("Pushed rule")
        db.session.commit()
        task_id, marker_prefix = task.id, f"automation-{rule.id}-"

    listener = socketio.test_client(app, auth={"token": automation_scenario["tokens"]["assignee"]})
    try:
        assert listener.is_connected()
        listener.get_received()

        client = session_client(automation_scenario["assignee_id"])
        response = client.post(
            f"/update_task_status/{task_id}/Completed",
            data={"csrf_token": CSRF, "comment": "Pushed"},
            follow_redirects=False,
        )
        assert response.status_code == 302

        packets = [packet for packet in listener.get_received() if packet["name"] == "realtime_event"]
        pushed = [packet["args"][0] for packet in packets if packet["args"][0]["eventType"] == "NOTIFICATION_CREATED"]
        assert pushed, "the assignee was not pushed the automation notification"
        assert any("matched task" in payload["payload"].get("message", "") for payload in pushed)
        # The published event carries the dedupe marker as its own id.
        assert any(str(payload["eventId"]).startswith(marker_prefix) for payload in pushed)
    finally:
        listener.disconnect()


def test_a_repeat_sweep_does_not_notify_twice(automation_scenario):
    with app.app_context():
        task = automation_scenario["make_task"]("Sweep dedupe", status="Completed", assignee_id=automation_scenario["assignee_id"])
        automation_scenario["make_rule"]("Equals completed", condition="equals", value="Completed")
        db.session.commit()
        task_id = task.id
        assert run_automation_once() == 1
        first_count = Notification.query.filter_by(user_id=automation_scenario["assignee_id"]).count()
        # A second, third, and fourth sweep must all be silent.
        assert run_automation_once() == 0
        assert run_automation_once() == 0
        assert Notification.query.filter_by(user_id=automation_scenario["assignee_id"]).count() == first_count
        assert first_count == 1
        assert db.session.get(Task, task_id).status == "Completed"


def test_a_disabled_rule_never_fires(automation_scenario):
    with app.app_context():
        task = automation_scenario["make_task"]("Disabled rule", status="Completed", assignee_id=automation_scenario["assignee_id"])
        automation_scenario["make_rule"]("Disabled", condition="equals", value="Completed", enabled=False)
        db.session.commit()
        assert run_automation_once() == 0
        assert Notification.query.filter_by(user_id=automation_scenario["assignee_id"]).count() == 0
        assert not AuditLog.query.filter_by(action="automation_triggered").first()
        assert automation_matches(
            AutomationRule.query.first(),
            automation_scenario["make_task"]("Another", status="Completed"),
        ) is False


def test_changes_to_needs_a_transition_and_equals_reads_the_state(automation_scenario):
    with app.app_context():
        task = automation_scenario["make_task"]("Pending work", status="Pending", assignee_id=automation_scenario["assignee_id"])
        changes_to = automation_scenario["make_rule"]("Changes to", condition="changes_to", value="Completed")
        equals = automation_scenario["make_rule"]("Equals", condition="equals", value="Completed")
        db.session.commit()

        # The task is not in the target state, so neither rule matches.
        assert automation_matches(changes_to, task, previous_status="In Progress") is False
        assert automation_matches(equals, task, previous_status="In Progress") is False

        task.status = "Completed"
        db.session.commit()
        # A real transition satisfies changes_to; a sweep, which passes no
        # previous status, must not.
        assert automation_matches(changes_to, task, previous_status="In Progress") is True
        assert automation_matches(changes_to, task, previous_status=None) is False
        assert automation_matches(equals, task, previous_status=None) is True


def test_an_overdue_rule_fires_once_per_day(automation_scenario):
    yesterday = (TODAY - timedelta(days=1)).isoformat()
    with app.app_context():
        task = automation_scenario["make_task"](
            "Overdue work", status="Pending", assignee_id=automation_scenario["assignee_id"], due_date=yesterday
        )
        automation_scenario["make_rule"]("Overdue", event="overdue", value=None)
        db.session.commit()

        assert automation_matches(AutomationRule.query.first(), task) is True
        assert run_automation_once() == 1
        assert run_automation_once() == 0
        assert Notification.query.filter_by(user_id=automation_scenario["assignee_id"]).count() == 1

        # A completed task is never overdue, and a future due date is not yet due.
        task.status = "Completed"
        assert automation_matches(AutomationRule.query.first(), task) is False
        task.status = "Pending"
        task.due_date = (TODAY + timedelta(days=2)).isoformat()
        assert automation_matches(AutomationRule.query.first(), task) is False


def test_the_rule_form_rejects_an_unsupported_combination(automation_scenario):
    client = session_client(automation_scenario["admin_id"], role="Admin")
    with app.app_context():
        before = AutomationRule.query.count()

    # An event the engine does not run, and a status that does not exist.
    for form in (
        {"event": "created", "condition": "equals", "value": "Completed"},
        {"event": "status_changed", "condition": "is_tomorrow", "value": "Completed"},
        {"event": "status_changed", "condition": "equals", "value": "Frozen"},
        {"event": "status_changed", "condition": "equals", "action": "shout", "value": "Completed"},
    ):
        response = client.post(
            "/automation",
            data={"csrf_token": CSRF, "name": f"Rejected {uuid4().hex[:6]}", "action": "notify", **form},
            follow_redirects=False,
        )
        assert response.status_code == 302
    with app.app_context():
        assert AutomationRule.query.count() == before

    accepted = client.post(
        "/automation",
        data={
            "csrf_token": CSRF,
            "name": f"Accepted {uuid4().hex[:6]}",
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
        for rule in AutomationRule.query.all():
            automation_scenario["created"]["rules"].append(rule.id)


def test_report_aggregates_the_callers_tasks(automation_scenario):
    with app.app_context():
        yesterday = (TODAY - timedelta(days=1)).isoformat()
        automation_scenario["make_task"]("Done task", status="Completed", assignee_id=automation_scenario["assignee_id"])
        automation_scenario["make_task"]("Open task", status="In Progress", assignee_id=automation_scenario["assignee_id"])
        automation_scenario["make_task"]("Late task", status="Pending", assignee_id=automation_scenario["assignee_id"], due_date=yesterday)
        automation_scenario["make_task"]("Someone else's task", status="Pending", assignee_id=automation_scenario["other_id"])
        db.session.commit()

    report = report_for(automation_scenario["admin_id"])
    summary = dict(report["summary"])
    assert summary["Tasks in period"] == "4"
    assert summary["Completed"] == "1"
    assert summary["Open"] == "3"
    assert summary["Overdue"] == "1"
    assert summary["Completion rate"] == "25%"
    by_status = {row["status"]: row["tasks"] for row in report["by_status"]}
    assert by_status["Completed"] == 1 and by_status["In Progress"] == 1
    assert len(report["assignees"]) == 2
    assert sum(row["assigned"] for row in report["assignees"]) == 4
    assert report["teams"][0]["tasks"] == 4


def test_report_period_excludes_tasks_outside_the_window(automation_scenario):
    old = (TODAY - timedelta(days=40)).isoformat()
    with app.app_context():
        automation_scenario["make_task"]("Old task", status="Completed", assignee_id=automation_scenario["assignee_id"], due_date=old)
        automation_scenario["make_task"]("Recent task", status="Completed", assignee_id=automation_scenario["assignee_id"])
        db.session.commit()

    today_only = report_for(automation_scenario["admin_id"], date_from=TODAY.isoformat(), date_to=TODAY.isoformat())
    assert dict(today_only["summary"])["Tasks in period"] == "1"
    wide = report_for(
        automation_scenario["admin_id"],
        date_from=(TODAY - timedelta(days=60)).isoformat(),
        date_to=TODAY.isoformat(),
    )
    assert dict(wide["summary"])["Tasks in period"] == "2"


def test_report_only_shows_what_the_caller_may_see(automation_scenario):
    with app.app_context():
        automation_scenario["make_task"]("Visible to member", assignee_id=automation_scenario["assignee_id"])
        automation_scenario["make_task"]("Hidden from member", assignee_id=automation_scenario["other_id"])
        db.session.commit()

    report = report_for(automation_scenario["assignee_id"], role="User")
    assert dict(report["summary"])["Tasks in period"] == "1"


def test_report_export_produces_the_aggregate_in_every_format(automation_scenario):
    with app.app_context():
        automation_scenario["make_task"]("Exported task", status="Completed", assignee_id=automation_scenario["assignee_id"])
        db.session.commit()
        username = db.session.get(User, automation_scenario["assignee_id"]).username

    client = session_client(automation_scenario["admin_id"], role="Admin")
    csv_body = client.get("/export/reports.csv")
    assert csv_body.status_code == 200
    csv_text = csv_body.data.decode("utf-8-sig")
    assert "Completion rate" in csv_text
    assert username in csv_text
    assert "Exported task" not in csv_text, "a report is an aggregate, not a task dump"

    xlsx_body = client.get("/export/reports.xlsx")
    assert xlsx_body.status_code == 200
    assert xlsx_body.data[:2] == b"PK", "the Excel export must be a real workbook"
    from openpyxl import load_workbook

    workbook = load_workbook(BytesIO(xlsx_body.data))
    assert "Summary" in workbook.sheetnames
    assert "By assignee" in workbook.sheetnames
    summary_text = "\n".join(str(cell.value) for row in workbook["Summary"].iter_rows() for cell in row if cell.value)
    assert "Tasks in period" in summary_text
    assert username in "\n".join(
        str(cell.value) for row in workbook["By assignee"].iter_rows() for cell in row if cell.value
    )

    pdf_body = client.get("/export/reports.pdf")
    assert pdf_body.status_code == 200
    assert pdf_body.data[:5] == b"%PDF-"
    assert len(pdf_body.data) > 500
    # reportlab compresses the page streams, so read the text back out of them.
    import base64
    import re
    import zlib

    streams = re.findall(rb"stream\r?\n(.*?)endstream", pdf_body.data, re.S)
    page_text = b""
    for stream in streams:
        data = stream.strip()
        for decode in (
            lambda value: zlib.decompress(base64.a85decode(value, adobe=True)),
            lambda value: base64.a85decode(value, adobe=True),
            lambda value: zlib.decompress(value),
            lambda value: value,
        ):
            try:
                page_text += decode(data)
                break
            except Exception:  # noqa: BLE001 - try the next encoding
                continue
    assert b"By assignee" in page_text, page_text[:400]
    assert b"Completion rate" in page_text
    assert username.encode() in page_text


def test_report_export_is_closed_without_the_permission(automation_scenario):
    manager_client = session_client(automation_scenario["manage_without_reports_id"], role="Admin")
    for fmt in ("pdf", "xlsx", "csv"):
        response = manager_client.get(f"/export/reports.{fmt}")
        assert response.status_code == 403, fmt
    # The screen redirects instead, and records the denial.
    assert manager_client.get("/reports", follow_redirects=False).status_code == 302
    with app.app_context():
        assert AuditLog.query.filter_by(action="access_denied", entity="reports").first() is not None


def test_report_screen_and_analytics_expose_the_export_links(automation_scenario):
    client = session_client(automation_scenario["admin_id"], role="Admin")
    reports_html = client.get("/reports").get_data(as_text=True)
    assert reports_html.count("/export/reports.") == 3
    assert 'name="date_from"' in reports_html
    assert "By assignee" in reports_html

    analytics_html = client.get("/analytics").get_data(as_text=True)
    assert analytics_html.count("/export/reports.") == 3
