#!/usr/bin/env python3
"""
ssh_monitor.py

Part of: Cloud SSH Intrusion Guard & Automated Alert System (SIH Project)

Purpose:
    Continuously monitors the system SSH authentication log
    (default: /var/log/auth.log) for failed login attempts, tracks
    the number of failures per source IP address, automatically
    blocks IPs that cross a configurable threshold using `ufw deny`,
    sends real-time alert notifications to a Telegram chat, and writes
    a structured JSON-Lines event feed that the web dashboard reads.

    Reads its configuration from settings.json in the same folder — the
    exact file the dashboard's Settings page writes to, so both stay in
    sync automatically. If settings.json does not exist yet, built-in
    defaults are used (Telegram alerts stay disabled until configured).

Usage:
    sudo python3 ssh_monitor.py
    sudo python3 ssh_monitor.py --settings /path/to/settings.json

Requirements:
    - Python 3.7+
    - requests>=2.28.0  (pip install -r requirements.txt)
    - ufw installed and available on PATH (Ubuntu/Debian firewall)
    - Root privileges (to read auth.log and run ufw)

Author: Cloud SSH Intrusion Guard & Automated Alert System Contributors
License: MIT
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    print(
        "ERROR: The 'requests' package is required. "
        "Install it with: pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SETTINGS_PATH = BASE_DIR / "settings.json"

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

# Matches lines like:
#   Sep 27 10:15:32 host sshd[12345]: Failed password for invalid user admin \
#       from 203.0.113.7 port 51512 ssh2
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2"
)

# Matches: "Invalid user admin from 203.0.113.7 port 51512"
INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)


def resolve_path(value: str) -> Path:
    """Resolves a settings path relative to this script's folder, unless absolute."""
    p = Path(value)
    return p if p.is_absolute() else (BASE_DIR / p)


class Config:
    """Loads settings.json (shared with the dashboard), falling back to defaults."""

    def __init__(self, path: Path):
        self.path = path
        self._data: Dict = dict(DEFAULT_SETTINGS)
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            print(
                f"NOTE: {self.path} not found — using built-in defaults. "
                f"Configure via the dashboard's Settings page, or run the "
                f"dashboard once (python3 run.py) to generate it.",
                file=sys.stderr,
            )
            return
        with open(self.path, "r", encoding="utf-8") as f:
            self._data.update(json.load(f))

    @property
    def max_attempts(self) -> int:
        return int(self._data.get("max_attempts", 3))

    @property
    def log_file(self) -> str:
        return self._data.get("log_file", "/var/log/auth.log")

    @property
    def telegram_bot_token(self) -> str:
        return self._data.get("telegram_bot_token", "")

    @property
    def telegram_chat_id(self) -> str:
        return self._data.get("telegram_chat_id", "")

    @property
    def block_duration_minutes(self) -> int:
        return int(self._data.get("block_duration_minutes", 1440))

    @property
    def monitor_interval_seconds(self) -> float:
        return float(self._data.get("monitor_interval_seconds", 5))

    @property
    def state_file(self) -> Path:
        return resolve_path(self._data.get("state_file", "blocked_ips.json"))

    @property
    def events_file(self) -> Path:
        return resolve_path(self._data.get("events_file", "events.jsonl"))

    @property
    def app_log_file(self) -> Path:
        return resolve_path(self._data.get("app_log_file", "monitor.log"))

    @property
    def whitelist_ips(self) -> List[str]:
        return self._data.get("whitelist_ips", ["127.0.0.1"])


def setup_logging(app_log_file: Path) -> logging.Logger:
    logger = logging.getLogger("ssh_monitor")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    try:
        app_log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(app_log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except (PermissionError, OSError) as exc:
        logger.warning(
            "Could not open app log file %s (%s). Continuing with console logging only.",
            app_log_file, exc,
        )

    return logger


class EventFeed:
    """Appends structured JSON-Lines events for the web dashboard to consume."""

    def __init__(self, events_file: Path, logger: logging.Logger):
        self.events_file = events_file
        self.logger = logger
        self.events_file.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: Dict) -> None:
        event = {"timestamp": datetime.utcnow().isoformat(timespec="seconds"), **event}
        try:
            with open(self.events_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except OSError as exc:
            self.logger.warning("Could not write event to %s: %s", self.events_file, exc)


class TelegramNotifier:
    """Sends alert messages to a Telegram chat via the Bot API."""

    API_URL_TEMPLATE = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, bot_token: str, chat_id: str, logger: logging.Logger):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.logger = logger
        self.enabled = bool(bot_token) and bool(chat_id)

    def send(self, message: str) -> bool:
        if not self.enabled:
            self.logger.warning(
                "Telegram not configured (set telegram_bot_token / telegram_chat_id via "
                "the dashboard's Settings page); skipping alert. Message was: %s", message
            )
            return False

        url = self.API_URL_TEMPLATE.format(token=self.bot_token)
        payload = {"chat_id": self.chat_id, "text": message, "parse_mode": "Markdown"}
        try:
            response = requests.post(url, data=payload, timeout=10)
            response.raise_for_status()
            self.logger.info("Telegram alert sent successfully.")
            return True
        except requests.RequestException as exc:
            self.logger.error("Failed to send Telegram alert: %s", exc)
            return False


class IPBlocker:
    """Handles blocking IPs via ufw and persisting block state to disk."""

    def __init__(self, state_file: Path, logger: logging.Logger):
        self.state_file = state_file
        self.logger = logger
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.blocked: Dict[str, str] = self._load_state()

    def _load_state(self) -> Dict[str, str]:
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                self.logger.warning("Could not read state file (%s); starting fresh.", exc)
        return {}

    def _save_state(self) -> None:
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(self.blocked, f, indent=2)
        except OSError as exc:
            self.logger.error("Could not write state file: %s", exc)

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked

    def block(self, ip: str) -> bool:
        if self.is_blocked(ip):
            return True
        try:
            result = subprocess.run(
                ["ufw", "deny", "from", ip, "to", "any"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if result.returncode != 0:
                self.logger.error(
                    "ufw deny failed for %s (rc=%s): %s", ip, result.returncode, result.stderr.strip()
                )
                return False
            self.blocked[ip] = datetime.utcnow().isoformat()
            self._save_state()
            self.logger.info("Blocked IP %s via ufw.", ip)
            return True
        except FileNotFoundError:
            self.logger.error("ufw command not found. Install it with: sudo apt install ufw")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("ufw deny command timed out for %s.", ip)
            return False

    def unblock_expired(self, block_duration_minutes: int) -> List[str]:
        if block_duration_minutes <= 0:
            return []

        expired: List[str] = []
        cutoff = datetime.utcnow() - timedelta(minutes=block_duration_minutes)

        for ip, blocked_at_str in list(self.blocked.items()):
            try:
                blocked_at = datetime.fromisoformat(blocked_at_str)
            except ValueError:
                continue
            if blocked_at < cutoff and self._unblock(ip):
                expired.append(ip)

        if expired:
            self._save_state()
        return expired

    def _unblock(self, ip: str) -> bool:
        try:
            result = subprocess.run(
                ["ufw", "delete", "deny", "from", ip, "to", "any"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if result.returncode == 0:
                self.blocked.pop(ip, None)
                self.logger.info("Unblocked expired IP %s.", ip)
                return True
            self.logger.error(
                "Failed to unblock %s (rc=%s): %s", ip, result.returncode, result.stderr.strip()
            )
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            self.logger.error("Error unblocking %s: %s", ip, exc)
            return False


class SSHMonitor:
    """Tails the auth log, tracks failed attempts per IP, and reacts to threshold breaches."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.failed_attempts: Dict[str, int] = defaultdict(int)
        self.notifier = TelegramNotifier(config.telegram_bot_token, config.telegram_chat_id, logger)
        self.blocker = IPBlocker(config.state_file, logger)
        self.events = EventFeed(config.events_file, logger)

    def _is_whitelisted(self, ip: str) -> bool:
        return ip in self.config.whitelist_ips

    def _parse_line(self, line: str) -> Optional[tuple]:
        match = FAILED_LOGIN_PATTERN.search(line) or INVALID_USER_PATTERN.search(line)
        if match:
            return match.group("ip"), match.groupdict().get("user", "unknown")
        return None

    def _handle_failed_attempt(self, ip: str, user: str) -> None:
        if self._is_whitelisted(ip):
            self.logger.debug("Ignoring whitelisted IP %s.", ip)
            return
        if self.blocker.is_blocked(ip):
            return

        self.failed_attempts[ip] += 1
        count = self.failed_attempts[ip]
        self.logger.info(
            "Failed SSH login from %s (attempt %d/%d).", ip, count, self.config.max_attempts
        )
        self.events.emit({"type": "failed_login", "ip": ip, "user": user, "attempt": count})

        if count >= self.config.max_attempts:
            self._block_and_alert(ip, count)

    def _block_and_alert(self, ip: str, attempt_count: int) -> None:
        blocked = self.blocker.block(ip)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        self.events.emit(
            {"type": "blocked" if blocked else "block_failed", "ip": ip, "attempts": attempt_count}
        )

        if blocked:
            message = (
                "🚨 *SSH Intrusion Alert* 🚨\n\n"
                f"*IP Address:* `{ip}`\n"
                f"*Failed Attempts:* {attempt_count}\n"
                f"*Action Taken:* Blocked via ufw\n"
                f"*Time:* {timestamp}"
            )
        else:
            message = (
                "⚠️ *SSH Intrusion Alert (block failed)* ⚠️\n\n"
                f"*IP Address:* `{ip}`\n"
                f"*Failed Attempts:* {attempt_count}\n"
                f"*Action Taken:* Block attempt FAILED, manual action required\n"
                f"*Time:* {timestamp}"
            )

        sent = self.notifier.send(message)
        self.events.emit({"type": "alert_sent" if sent else "alert_failed", "ip": ip, "channel": "telegram"})

    def _follow(self, file_handle):
        file_handle.seek(0, os.SEEK_END)
        while True:
            line = file_handle.readline()
            if not line:
                time.sleep(self.config.monitor_interval_seconds)
                continue
            yield line

    def run(self) -> None:
        log_file = self.config.log_file
        if not os.path.exists(log_file):
            raise FileNotFoundError(
                f"Log file {log_file} not found. On some distributions this is "
                f"/var/log/secure instead of /var/log/auth.log; update settings.json."
            )

        self.logger.info("Starting SSH Intrusion Guard monitor on %s", log_file)
        self.logger.info(
            "Threshold: %d failed attempts. Block duration: %d minute(s).",
            self.config.max_attempts, self.config.block_duration_minutes,
        )

        last_cleanup = time.monotonic()
        cleanup_interval_seconds = 60

        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in self._follow(f):
                parsed = self._parse_line(line)
                if parsed:
                    ip, user = parsed
                    self._handle_failed_attempt(ip, user)

                if time.monotonic() - last_cleanup > cleanup_interval_seconds:
                    expired = self.blocker.unblock_expired(self.config.block_duration_minutes)
                    for ip in expired:
                        self.failed_attempts.pop(ip, None)
                        self.events.emit({"type": "unblocked", "ip": ip})
                    last_cleanup = time.monotonic()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Cloud SSH Intrusion Guard - monitors SSH auth logs, "
        "blocks brute-force attackers, and sends Telegram alerts."
    )
    parser.add_argument(
        "--settings", type=str, default=str(DEFAULT_SETTINGS_PATH),
        help="Path to settings.json (default: settings.json next to this script — "
        "the same file the dashboard's Settings page writes to).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = Config(Path(args.settings))
    logger = setup_logging(config.app_log_file)

    if os.geteuid() != 0:
        logger.warning(
            "Not running as root. Reading %s and running ufw may fail due to insufficient permissions.",
            config.log_file,
        )

    monitor = SSHMonitor(config, logger)

    try:
        monitor.run()
    except FileNotFoundError as exc:
        logger.error(str(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Monitor stopped by user (Ctrl+C).")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001 - top-level safety net for a long-running daemon
        logger.exception("Unexpected error in monitor loop: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
