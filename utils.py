"""
utils.py — reads the SSH monitor's live output (blocked IPs, event feed)
and falls back to bundled sample data so the dashboard looks populated the
first time it's run, before ssh_monitor.py has produced real data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from flask import current_app

BASE_DIR = Path(__file__).resolve().parent

# Bundled demo data — shown until the real monitor writes its own files,
# so the dashboard looks fully alive immediately after setup.
SAMPLE_BLOCKED_IPS: Dict[str, str] = {
    "185.220.101.7": "2026-09-27T04:12:03",
    "103.87.169.4": "2026-09-27T05:47:21",
    "45.155.204.12": "2026-09-27T06:02:55",
}

SAMPLE_EVENTS: List[dict] = [
    {"type": "failed_login", "ip": "185.220.101.7", "user": "root", "attempt": 1, "timestamp": "2026-09-27T04:10:41"},
    {"type": "failed_login", "ip": "185.220.101.7", "user": "admin", "attempt": 2, "timestamp": "2026-09-27T04:11:22"},
    {"type": "failed_login", "ip": "185.220.101.7", "user": "root", "attempt": 3, "timestamp": "2026-09-27T04:12:03"},
    {"type": "blocked", "ip": "185.220.101.7", "attempts": 3, "timestamp": "2026-09-27T04:12:03"},
    {"type": "alert_sent", "ip": "185.220.101.7", "channel": "telegram", "timestamp": "2026-09-27T04:12:04"},
    {"type": "failed_login", "ip": "103.87.169.4", "user": "ubuntu", "attempt": 1, "timestamp": "2026-09-27T05:45:10"},
    {"type": "failed_login", "ip": "103.87.169.4", "user": "test", "attempt": 2, "timestamp": "2026-09-27T05:46:33"},
    {"type": "failed_login", "ip": "103.87.169.4", "user": "oracle", "attempt": 3, "timestamp": "2026-09-27T05:47:21"},
    {"type": "blocked", "ip": "103.87.169.4", "attempts": 3, "timestamp": "2026-09-27T05:47:21"},
    {"type": "alert_sent", "ip": "103.87.169.4", "channel": "telegram", "timestamp": "2026-09-27T05:47:22"},
    {"type": "failed_login", "ip": "45.155.204.12", "user": "postgres", "attempt": 1, "timestamp": "2026-09-27T06:01:02"},
    {"type": "failed_login", "ip": "45.155.204.12", "user": "guest", "attempt": 2, "timestamp": "2026-09-27T06:01:47"},
    {"type": "failed_login", "ip": "45.155.204.12", "user": "www-data", "attempt": 3, "timestamp": "2026-09-27T06:02:55"},
    {"type": "blocked", "ip": "45.155.204.12", "attempts": 3, "timestamp": "2026-09-27T06:02:55"},
    {"type": "alert_sent", "ip": "45.155.204.12", "channel": "telegram", "timestamp": "2026-09-27T06:02:56"},
    {"type": "failed_login", "ip": "51.68.201.9", "user": "admin", "attempt": 1, "timestamp": "2026-09-27T07:15:19"},
]


def _resolve(value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (BASE_DIR / p)


def get_settings() -> dict:
    return current_app.config["SETTINGS"]


def get_blocked_ips() -> Dict[str, str]:
    """Returns {ip: blocked_at_iso}. Uses the live state file if present, else sample data."""
    settings = get_settings()
    state_file = _resolve(settings.get("state_file", "blocked_ips.json"))

    if state_file.exists():
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data:
                    return data
        except (json.JSONDecodeError, OSError):
            pass

    return dict(SAMPLE_BLOCKED_IPS)


def get_events(limit: int = 200) -> List[dict]:
    """Returns the most recent events, newest first. Uses the live feed if present, else sample data."""
    settings = get_settings()
    events_file = _resolve(settings.get("events_file", "events.jsonl"))

    if not (events_file.exists() and events_file.stat().st_size > 0):
        events = list(SAMPLE_EVENTS)
        events.reverse()
        return events[:limit]

    events: List[dict] = []
    with open(events_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    events.reverse()
    return events[:limit]


def compute_stats() -> dict:
    events = get_events(limit=5000)
    blocked = get_blocked_ips()

    failed_attempts = sum(1 for e in events if e.get("type") == "failed_login")
    alerts_sent = sum(1 for e in events if e.get("type") == "alert_sent")
    tracking_ips = {
        e.get("ip") for e in events
        if e.get("type") == "failed_login" and e.get("ip") not in blocked
    }

    return {
        "failed_attempts": failed_attempts,
        "blocked_count": len(blocked),
        "tracking_count": len(tracking_ips),
        "alerts_sent": alerts_sent,
    }


def is_using_sample_data() -> bool:
    settings = get_settings()
    events_file = _resolve(settings.get("events_file", "events.jsonl"))
    return not (events_file.exists() and events_file.stat().st_size > 0)
