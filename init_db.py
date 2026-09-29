#!/usr/bin/env python3
"""
init_db.py

Creates the local SQLite database (users.db) used by the dashboard for
authentication, and seeds it with a default administrator account.

Usage:
    python3 init_db.py
    python3 init_db.py --username admin --password "SomeStrongerPassword!23"

Run this once before starting the dashboard for the first time:
    python3 init_db.py
    python3 run.py
"""

from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "users.db"

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize the dashboard's user database.")
    parser.add_argument("--username", type=str, default=None, help="Admin username to create.")
    parser.add_argument(
        "--password", type=str, default=None,
        help="Admin password to set (omit to be prompted, or to use the insecure default).",
    )
    parser.add_argument(
        "--non-interactive", action="store_true",
        help="Do not prompt; use --username/--password or the insecure defaults.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    conn = sqlite3.connect(DB_PATH)
    conn.execute(SCHEMA)

    existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing > 0:
        print(f"Database already initialized at {DB_PATH} ({existing} user(s) present). Nothing to do.")
        conn.close()
        return

    username = args.username
    password = args.password

    if not args.non_interactive:
        if username is None:
            entered = input(f"Admin username [{DEFAULT_USERNAME}]: ").strip()
            username = entered or DEFAULT_USERNAME
        if password is None:
            entered = getpass.getpass(
                "Admin password (leave blank to use the insecure default 'admin123'): "
            )
            password = entered or DEFAULT_PASSWORD
    else:
        # Non-interactive (e.g. a platform's build/start command). Prefer
        # ADMIN_USERNAME / ADMIN_PASSWORD environment variables if set, so a
        # public deployment doesn't have to use the insecure default.
        username = username or os.environ.get("ADMIN_USERNAME") or DEFAULT_USERNAME
        password = password or os.environ.get("ADMIN_PASSWORD") or DEFAULT_PASSWORD

    password_hash = generate_password_hash(password)
    conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
    conn.commit()
    conn.close()

    print(f"Database created at {DB_PATH}")
    print(f"Admin account created — username: '{username}'")
    if password == DEFAULT_PASSWORD:
        print(
            "WARNING: Using the default password 'admin123'. "
            "Sign in and change it immediately from the Profile page."
        )
    print("You can now run: python3 run.py")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)
