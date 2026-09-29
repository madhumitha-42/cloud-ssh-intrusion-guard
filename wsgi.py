"""
wsgi.py — production entry point.

Local development uses run.py (Flask's built-in server). Production hosts
(Render, Railway, Heroku, etc.) use this file instead, pointing a WSGI
server such as gunicorn at it:

    gunicorn wsgi:app

It simply re-exports the same `app` object that run.py uses, so both
entry points stay in sync automatically.
"""

from __init__ import app

if __name__ == "__main__":
    app.run()
