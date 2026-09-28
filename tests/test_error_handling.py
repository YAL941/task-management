"""A crash must reach the user as a readable page, never as a traceback."""

import pytest

from main import AuditLog, app, db

ERROR_PROBE_PATH = "/_error_probe"


def test_a_broken_route_returns_a_readable_error_page(signed_in_client, crashing_route):
    client = signed_in_client
    response = client.get(crashing_route)
    assert response.status_code == 500
    body = response.get_data(as_text=True)
    assert "Something went wrong" in body
    # None of the internals may leak: no traceback, no module path, no SQL.
    for leak in ("Traceback", "jinja2", "werkzeug", "sqlalchemy", "sqlite3", "pyodbc", "UnboundLocalError", "main.py"):
        assert leak not in body, f"the error page leaked {leak!r}"
    # And the request is still a normal HTML document with the shared layout.
    assert "<!DOCTYPE html>" in body
    assert "Sign out" in body


def test_the_crash_is_audited_rather_than_shown(signed_in_client, crashing_route):
    with app.app_context():
        before = AuditLog.query.filter_by(action="access_denied", entity="request").count()
    signed_in_client.get(crashing_route)
    with app.app_context():
        rows = (
            AuditLog.query.filter_by(action="access_denied", entity="request")
            .order_by(AuditLog.id.desc())
            .limit(1)
            .all()
        )
        assert rows
        assert AuditLog.query.filter_by(action="access_denied", entity="request").count() == before + 1
        assert "application_error" in rows[0].new_value
        assert crashing_route in rows[0].new_value


def test_an_unknown_page_renders_the_404_page(signed_in_client):
    response = signed_in_client.get("/no-such-page-at-all")
    assert response.status_code == 404
    body = response.get_data(as_text=True)
    assert "Page not found" in body
    assert "Traceback" not in body


def test_an_xhr_route_gets_json_not_html(signed_in_client, crashing_route):
    response = signed_in_client.get(crashing_route, headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"})
    assert response.status_code == 500
    assert response.is_json
    assert response.get_json() == {"ok": False, "error": "Something went wrong on our side. Please try again."}


def test_a_wrong_method_still_reports_the_real_status(signed_in_client):
    response = signed_in_client.post("/tasks")
    assert response.status_code == 405


@pytest.fixture
def signed_in_client():
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "admin"
        session["role"] = "Admin"
        session["csrf_token"] = "error-page-csrf"
    return client


@pytest.fixture
def crashing_route():
    return ERROR_PROBE_PATH


def _raise_deliberately():
    raise ValueError("deliberate failure for the error handler test")


# Flask refuses to add a route once the first request has been handled, so the
# probe is registered while this module is imported, which pytest does before it
# runs any test.
if "error_probe" not in app.view_functions:
    app.add_url_rule(ERROR_PROBE_PATH, "error_probe", _raise_deliberately, methods=["GET"])
