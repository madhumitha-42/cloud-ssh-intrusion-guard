"""
dashboard.py — Home, Blocked IPs, Alerts, Settings, and Profile pages, plus
small JSON API endpoints used for live auto-refresh on the Home page.
All routes require an authenticated session.
"""

from __future__ import annotations

from flask import render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from __init__ import app, get_db_connection, save_settings
from utils import get_blocked_ips, get_events, compute_stats, is_using_sample_data, get_settings


@app.route("/")
@login_required
def index():
    return redirect(url_for("home"))


@app.route("/home")
@login_required
def home():
    stats = compute_stats()
    recent_events = get_events(limit=12)
    blocked = get_blocked_ips()
    return render_template(
        "home.html",
        active_page="home",
        stats=stats,
        recent_events=recent_events,
        blocked_count=len(blocked),
        demo_mode=is_using_sample_data(),
    )


@app.route("/blocked-ips")
@login_required
def blocked_ips():
    blocked = get_blocked_ips()
    rows = sorted(blocked.items(), key=lambda kv: kv[1], reverse=True)
    return render_template(
        "blocked_ips.html",
        active_page="blocked_ips",
        rows=rows,
        demo_mode=is_using_sample_data(),
    )


@app.route("/alerts")
@login_required
def alerts():
    events = get_events(limit=300)
    return render_template(
        "alerts.html",
        active_page="alerts",
        events=events,
        demo_mode=is_using_sample_data(),
    )


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    settings_data = dict(get_settings())

    if request.method == "POST":
        try:
            settings_data["max_attempts"] = int(request.form.get("max_attempts", 3))
            settings_data["block_duration_minutes"] = int(
                request.form.get("block_duration_minutes", 1440)
            )
            settings_data["log_file"] = request.form.get("log_file", "").strip()
            settings_data["telegram_bot_token"] = request.form.get("telegram_bot_token", "").strip()
            settings_data["telegram_chat_id"] = request.form.get("telegram_chat_id", "").strip()
            whitelist_raw = request.form.get("whitelist_ips", "")
            settings_data["whitelist_ips"] = [
                ip.strip() for ip in whitelist_raw.split(",") if ip.strip()
            ]

            save_settings(settings_data)
            app.config["SETTINGS"] = settings_data
            flash("Settings saved. Restart ssh_monitor.py to apply changes.", "success")
        except (ValueError, OSError) as exc:
            flash(f"Could not save settings: {exc}", "error")

        return redirect(url_for("settings"))

    return render_template("settings.html", active_page="settings", settings=settings_data)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        conn = get_db_connection()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()

        if row is None or not check_password_hash(row["password_hash"], current_password):
            flash("Current password is incorrect.", "error")
        elif len(new_password) < 8:
            flash("New password must be at least 8 characters.", "error")
        elif new_password != confirm_password:
            flash("New password and confirmation do not match.", "error")
        else:
            new_hash = generate_password_hash(new_password)
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, current_user.id))
            conn.commit()
            flash("Password updated successfully.", "success")

        conn.close()
        return redirect(url_for("profile"))

    return render_template("profile.html", active_page="profile")


# --------------------------------------------------------------------------
# JSON API — used by the Home page's inline script to auto-refresh stats
# --------------------------------------------------------------------------

@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(compute_stats())


@app.route("/api/events")
@login_required
def api_events():
    return jsonify(get_events(limit=20))
