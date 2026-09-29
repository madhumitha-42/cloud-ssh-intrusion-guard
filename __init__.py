"""
__init__.py — central application module for the Cloud SSH Intrusion Guard
dashboard.

This file creates the shared Flask `app` object, loads/saves settings,
sets up the SQLite connection helper, and wires up Flask-Login. All other
route modules (auth.py, dashboard.py) import `app`, `login_manager`, and
`get_db_connection` from this file, and are themselves imported at the
bottom of this file so their @app.route(...) decorators register against
the same app instance. This is the same "import routes at the bottom"
pattern used by many small Flask projects to avoid circular imports.

run.py is the process entry point: `python run.py` starts the server.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask
from flask_login import LoginManager

# --------------------------------------------------------------------------
# Paths — everything lives alongside this file at the project root.
# --------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
SETTINGS_PATH = BASE_DIR / "settings.json"
DB_PATH = BASE_DIR / "users.db"

DEFAULT_SETTINGS = {
    "max_attempts": 3,
    "log_file": "/var/log/auth.log",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "block_duration_minutes": 1440,
    "monitor_interval_seconds": 5,
    "state_file": "blocked_ips.json",
    "events_file": "events.jsonl",
    "app_log_file": "monitor.log",
    "whitelist_ips": ["127.0.0.1"],
}


def load_settings() -> dict:
    """Loads settings.json, creating it with defaults (+ a fresh secret key) if missing."""
    if SETTINGS_PATH.exists():
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            merged = {**DEFAULT_SETTINGS, **data}
            if "secret_key" not in merged:
                merged["secret_key"] = secrets.token_hex(32)
                save_settings(merged)
            return merged
        except (json.JSONDecodeError, OSError):
            pass

    data = {**DEFAULT_SETTINGS, "secret_key": secrets.token_hex(32)}
    save_settings(data)
    return data


def save_settings(data: dict) -> None:
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------------------------------------------------
# Flask app
# --------------------------------------------------------------------------

app = Flask(__name__, template_folder="templates", static_folder="static")

_settings = load_settings()
app.config["SECRET_KEY"] = _settings["secret_key"]
app.config["SETTINGS"] = _settings

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to access the dashboard."
login_manager.login_message_category = "info"
login_manager.init_app(app)

# --------------------------------------------------------------------------
# Import route modules last — they attach routes to `app` above and rely
# on `app`, `login_manager`, and `get_db_connection` already being defined.
# --------------------------------------------------------------------------

import auth      # noqa: E402  (defines /login, /logout, User, user_loader)
import dashboard  # noqa: E402  (defines /home, /blocked-ips, /alerts, /settings, /profile, /api/*)
