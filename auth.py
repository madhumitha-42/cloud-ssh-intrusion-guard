"""
auth.py — login, logout, and the User model backing Flask-Login.

Users live in the local SQLite database (users.db), created by running
init_db.py once before the dashboard's first launch.
"""

from __future__ import annotations

from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from __init__ import app, login_manager, get_db_connection


class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = str(id)
        self.username = username
        self.password_hash = password_hash

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    return User(id=row["id"], username=row["username"], password_hash=row["password_hash"])


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if row is not None:
            user = User(id=row["id"], username=row["username"], password_hash=row["password_hash"])
            if user.check_password(password):
                login_user(user)
                flash("Signed in successfully. Welcome to the Security Operations Center.", "success")
                next_page = request.args.get("next")
                return redirect(next_page or url_for("home"))

        flash("Invalid username or password credentials.", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
@app.route("/signup", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username:
            flash("Username is required.", "error")
        elif len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif password != confirm_password:
            flash("Password and confirmation do not match.", "error")
        else:
            conn = get_db_connection()
            existing = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if existing is not None:
                conn.close()
                flash("Username is already registered in the system. Please sign in or choose another username.", "error")
            else:
                p_hash = generate_password_hash(password)
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, p_hash))
                user_id = cursor.lastrowid
                conn.commit()
                conn.close()

                user = User(id=user_id, username=username, password_hash=p_hash)
                login_user(user)
                flash("Account registered successfully. Access granted to Security Operations Portal.", "success")
                return redirect(url_for("home"))

    return render_template("register.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been signed out from the Security Portal.", "info")
    return redirect(url_for("login"))

