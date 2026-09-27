import re
from html import unescape
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError

from main import AuditLog, User, app, db


@pytest.fixture
def audit_log_rows():
    with app.app_context():
        admin = User.query.filter_by(username="admin").first()
        assert admin is not None
        sort_actor = User(
            first_name="Sort",
            last_name="Actor",
            username=f"step4_sort_{uuid4().hex[:10]}",
            password="test-only",
            role="User",
            created_at="2026-09-28T10:00:00",
        )
        db.session.add(sort_actor)
        db.session.flush()
        rows = [
            AuditLog(
                user_id=admin.id if index % 2 == 0 else sort_actor.id,
                action=f"step4_page_probe_{index % 3}",
                entity="task" if index % 2 == 0 else "comment",
                entity_id=index,
                new_value=f"STEP4_MARKER_{index:03d}",
                created_at="2026-09-28T10:00:00",
            )
            for index in range(125)
        ]
        db.session.add_all(rows)
        db.session.commit()
        row_ids = [row.id for row in rows]
        admin_id = admin.id
        sort_actor_id = sort_actor.id

    try:
        yield row_ids, admin_id, sort_actor_id
    finally:
        with app.app_context():
            AuditLog.query.filter(AuditLog.id.in_(row_ids)).delete(synchronize_session=False)
            sort_actor = db.session.get(User, sort_actor_id)
            if sort_actor:
                db.session.delete(sort_actor)
            db.session.commit()


@pytest.fixture
def audit_client(audit_log_rows):
    _row_ids, admin_id, _sort_actor_id = audit_log_rows
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = admin_id
        session["username"] = "admin"
        session["role"] = "Admin"
    return client


def markers(response):
    return re.findall(r"STEP4_MARKER_\d{3}", response.get_data(as_text=True))


def test_page_sizes_limits_and_invalid_values(audit_client):
    response = audit_client.get("/audit-logs?action=step4_page_probe&search=STEP4_MARKER&page=1&per_page=25")
    assert len(markers(response)) == 25
    assert "Showing 1-25 of 125" in response.get_data(as_text=True)

    second_page = audit_client.get("/audit-logs?action=step4_page_probe&search=STEP4_MARKER&page=2&per_page=25")
    assert len(markers(second_page)) == 25
    assert set(markers(response)).isdisjoint(markers(second_page))

    assert len(markers(audit_client.get("/audit-logs?action=step4_page_probe&per_page=50"))) == 50
    assert len(markers(audit_client.get("/audit-logs?action=step4_page_probe&per_page=100"))) == 100
    capped = audit_client.get("/audit-logs?action=step4_page_probe&per_page=1000")
    assert len(markers(capped)) == 100
    assert 'option value="100" selected' in capped.get_data(as_text=True)

    for page in ("0", "-5", "abc"):
        invalid_page = audit_client.get(f"/audit-logs?action=step4_page_probe&page={page}&per_page=25")
        assert "Showing 1-25 of 125" in invalid_page.get_data(as_text=True)
    for per_page in ("0", "-1", "abc"):
        invalid_size = audit_client.get(f"/audit-logs?action=step4_page_probe&page=1&per_page={per_page}")
        assert len(markers(invalid_size)) == 25


def test_sorting_is_allowlisted_and_stable(audit_client, audit_log_rows):
    row_ids, admin_id, sort_actor_id = audit_log_rows
    ascending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=created_at&order=asc")
    descending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=created_at&order=desc")
    assert markers(ascending) == [f"STEP4_MARKER_{index:03d}" for index in range(25)]
    assert markers(descending) == [f"STEP4_MARKER_{index:03d}" for index in reversed(range(100, 125))]
    assert row_ids[0] < row_ids[-1]

    id_ascending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=id&order=asc")
    id_descending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=id&order=desc")
    assert markers(id_ascending) == [f"STEP4_MARKER_{index:03d}" for index in range(25)]
    assert markers(id_descending) == [f"STEP4_MARKER_{index:03d}" for index in reversed(range(100, 125))]

    action_ascending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=action&order=asc")
    action_descending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=action&order=desc")
    expected_action_ascending = sorted(range(125), key=lambda index: (index % 3, index))[:25]
    expected_action_descending = sorted(range(125), key=lambda index: (index % 3, index), reverse=True)[:25]
    assert markers(action_ascending) == [f"STEP4_MARKER_{index:03d}" for index in expected_action_ascending]
    assert markers(action_descending) == [f"STEP4_MARKER_{index:03d}" for index in expected_action_descending]

    entity_ascending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=entity&order=asc")
    entity_descending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=entity&order=desc")
    expected_entity_ascending = sorted(range(125), key=lambda index: ("task" if index % 2 == 0 else "comment", index))[:25]
    expected_entity_descending = sorted(range(125), key=lambda index: ("task" if index % 2 == 0 else "comment", index), reverse=True)[:25]
    assert markers(entity_ascending) == [f"STEP4_MARKER_{index:03d}" for index in expected_entity_ascending]
    assert markers(entity_descending) == [f"STEP4_MARKER_{index:03d}" for index in expected_entity_descending]

    entity_id_ascending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=entity_id&order=asc")
    entity_id_descending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=entity_id&order=desc")
    assert markers(entity_id_ascending) == [f"STEP4_MARKER_{index:03d}" for index in range(25)]
    assert markers(entity_id_descending) == [f"STEP4_MARKER_{index:03d}" for index in reversed(range(100, 125))]

    user_ascending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=user_id&order=asc")
    user_descending = audit_client.get("/audit-logs?action=step4_page_probe&per_page=25&sort=user_id&order=desc")
    expected_user_ascending = sorted(range(125), key=lambda index: (admin_id if index % 2 == 0 else sort_actor_id, index))[:25]
    expected_user_descending = sorted(range(125), key=lambda index: (admin_id if index % 2 == 0 else sort_actor_id, index), reverse=True)[:25]
    assert markers(user_ascending) == [f"STEP4_MARKER_{index:03d}" for index in expected_user_ascending]
    assert markers(user_descending) == [f"STEP4_MARKER_{index:03d}" for index in expected_user_descending]

    invalid = audit_client.get("/audit-logs?action=step4_page_probe&sort=unknown_field&order=sideways")
    assert invalid.status_code == 200
    assert 'aria-label="Sort by Date asc"' in invalid.get_data(as_text=True)
    assert 'aria-label="Sort by Actor desc"' in invalid.get_data(as_text=True)


def test_filters_pagination_links_empty_and_out_of_range(audit_client):
    response = audit_client.get(
        "/audit-logs?action=step4_page_probe&entity=task&search=STEP4_MARKER"
        "&page=2&per_page=25&sort=created_at&order=asc"
    )
    assert response.status_code == 200
    assert "Showing 26-50 of 63" in response.get_data(as_text=True)
    html = response.get_data(as_text=True)
    next_match = re.search(r'<a[^>]*href="([^"]+)"[^>]*>Next</a>', html)
    assert next_match is not None
    query = parse_qs(urlsplit(unescape(next_match.group(1))).query)
    assert query["page"] == ["3"]
    assert query["action"] == ["step4_page_probe"]
    assert query["entity"] == ["task"]
    assert query["search"] == ["STEP4_MARKER"]
    assert query["per_page"] == ["25"]
    assert query["sort"] == ["created_at"]
    assert query["order"] == ["asc"]

    last_page = audit_client.get("/audit-logs?action=step4_page_probe&page=9999&per_page=25")
    assert "Showing 101-125 of 125" in last_page.get_data(as_text=True)
    assert len(markers(last_page)) == 25

    empty = audit_client.get("/audit-logs?action=no_such_step4_action")
    assert "Showing 0-0 of 0" in empty.get_data(as_text=True)
    assert "No audit events" in empty.get_data(as_text=True)
    assert "Audit log pages" not in empty.get_data(as_text=True)


def test_pagination_query_uses_database_count_limit_and_offset(audit_client):
    statements = []

    def capture_sql(_connection, _cursor, statement, _parameters, _context, _executemany):
        if "audit_logs" in statement.lower():
            statements.append(statement.lower())

    with app.app_context():
        engine = db.engine
        event.listen(engine, "before_cursor_execute", capture_sql)
    try:
        response = audit_client.get("/audit-logs?action=step4_page_probe&page=2&per_page=25")
    finally:
        with app.app_context():
            event.remove(engine, "before_cursor_execute", capture_sql)

    assert response.status_code == 200
    assert any("count(" in statement and "audit_logs" in statement for statement in statements)
    assert any("limit" in statement and "offset" in statement for statement in statements)