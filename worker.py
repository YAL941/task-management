"""Run scheduled automation checks.

Usage: python worker.py
For production, run this command from Task Scheduler, cron, or a process manager.
"""
import time

from main import app, db, run_automation_once


if __name__ == "__main__":
    interval = 60
    while True:
        with app.app_context():
            fired = run_automation_once()
            if fired:
                print(f"Automation fired {fired} action(s)")
        time.sleep(interval)
