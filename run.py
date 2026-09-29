#!/usr/bin/env python3
"""
run.py — entry point for the Cloud SSH Intrusion Guard dashboard.

Usage:
    python3 init_db.py     # first time only — creates the admin account
    python3 run.py         # starts the dashboard at http://localhost:5000
"""

import os

from __init__ import app

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
