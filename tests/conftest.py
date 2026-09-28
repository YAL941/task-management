"""Point the test session at a throwaway database.

`main` reads `DATABASE_URL` at import time and `load_environment_file` only
fills in missing keys, so setting the variable here keeps `.env` and any real
deployment out of the test run. By default the session runs on a temporary
SQLite file that is deleted at the end.

Setting `TEST_MSSQL_URL` switches the session to that SQL Server instead. By
default only `test_mssql_*` modules then run, so the SQLite suite cannot mix
into a T-SQL run by accident. `TEST_MSSQL_FULL=1` lifts that restriction and
runs every module against the server, which is how dialect differences outside
the audit page are found; that mode also empties the database first, under the
three guards in `_reset_sqlserver_database`, so the run starts from a known
state. The integration module additionally requires `TEST_MSSQL_ALLOW_WRITE=1`
before it writes anything.
"""

import atexit
import os
import shutil
import tempfile
import time
from pathlib import Path

_TEMP_DIR = Path(tempfile.mkdtemp(prefix="taskhq-tests-"))
_TEST_DATABASE = _TEMP_DIR / "TaskHQ-test.db"
_MSSQL_URL = (os.environ.get("TEST_MSSQL_URL") or "").strip()
_MSSQL_FULL = (os.environ.get("TEST_MSSQL_FULL") or "").strip() == "1"
os.environ["DATABASE_URL"] = _MSSQL_URL or f"sqlite:///{_TEST_DATABASE.as_posix()}"

import main  # noqa: E402  (must be imported after DATABASE_URL is set)

main.app.config["UPLOAD_FOLDER"] = str(_TEMP_DIR / "uploads")
Path(main.app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)


def _mssql_database_name():
    """The database the URL points at, whether it is in the URL or in an ODBC string.

    A `mssql+pyodbc:///?odbc_connect=...` URL has no `database` component, so the
    name has to be read out of the connection string.
    """
    with main.app.app_context():
        url = main.db.engine.url
    if url.database:
        return url.database
    odbc_connect = url.query.get("odbc_connect", "")
    for part in odbc_connect.split(";"):
        name, _, value = part.partition("=")
        if name.strip().lower() in {"database", "dsn"}:
            return value.strip()
    return ""


def _reset_sqlserver_database():
    """Empty the server database so a full run starts from a known state.

    The SQLite session gets a brand new temporary file every run, and the
    suite's tests assume that: they insert rows with a fixed `created_at` and
    then read the first page, which only works when nothing older is in the
    table. A server database persists between runs, so the same assumptions
    have to be re-established explicitly.

    Three independent guards, all required, because this drops every row:
    `TEST_MSSQL_FULL` must have opted into running the whole suite, writes must
    be allowed at all, and the database name must contain `test` - a URL
    pointed at a real deployment is refused rather than emptied. A full run
    without the write opt-in is refused too, because running against a database
    that was not emptied fails in ways that look like application defects.
    """
    if not (_MSSQL_URL and _MSSQL_FULL):
        return
    if (os.environ.get("TEST_MSSQL_ALLOW_WRITE") or "").strip() != "1":
        # A full run against a database that is not emptied would fail in ways
        # that look like application defects, so this is refused rather than
        # quietly left dirty.
        raise RuntimeError("TEST_MSSQL_FULL=1 also needs TEST_MSSQL_ALLOW_WRITE=1 to empty the database first")
    database_name = _mssql_database_name()
    if "test" not in database_name.lower():
        raise RuntimeError(
            f"refusing to drop every row of {database_name or 'the unnamed database'!r}: "
            "TEST_MSSQL_FULL only runs against a database whose name contains 'test'"
        )
    with main.app.app_context():
        main.db.session.remove()
        main.db.drop_all()
        main.db.create_all()
        main.seed_default_accounts()


def pytest_sessionstart(session):
    _reset_sqlserver_database()


def pytest_collection_modifyitems(config, items):
    if not _MSSQL_URL or _MSSQL_FULL:
        return
    keep, deselect = [], []
    for item in items:
        (keep if "test_mssql" in item.nodeid else deselect).append(item)
    if deselect:
        config.hook.pytest_deselected(items=deselect)
    items[:] = keep


def _remove_temp_dir():
    with main.app.app_context():
        main.db.session.remove()
        main.db.engine.dispose()
    for attempt in range(5):
        shutil.rmtree(_TEMP_DIR, ignore_errors=True)
        if not _TEMP_DIR.exists():
            return
        # A connection can still be closing on Windows; give it a moment.
        time.sleep(0.2 * (attempt + 1))


atexit.register(_remove_temp_dir)


def pytest_sessionfinish(session, exitstatus):
    _remove_temp_dir()
