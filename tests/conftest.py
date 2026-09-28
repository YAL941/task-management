"""Point the test session at a throwaway database.

`main` reads `DATABASE_URL` at import time and `load_environment_file` only
fills in missing keys, so setting the variable here keeps `.env` and any real
deployment out of the test run. By default the session runs on a temporary
SQLite file that is deleted at the end.

Setting `TEST_MSSQL_URL` switches the session to that SQL Server instead, and
in that case only `test_mssql_*` modules run: the whole application is then
exercised end to end against a real T-SQL server, so the SQLite suite must not
mix in. The integration module additionally requires `TEST_MSSQL_ALLOW_WRITE=1`
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
os.environ["DATABASE_URL"] = _MSSQL_URL or f"sqlite:///{_TEST_DATABASE.as_posix()}"

import main  # noqa: E402  (must be imported after DATABASE_URL is set)

main.app.config["UPLOAD_FOLDER"] = str(_TEMP_DIR / "uploads")
Path(main.app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)


def pytest_collection_modifyitems(config, items):
    if not _MSSQL_URL:
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
