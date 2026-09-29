# Cloud SSH Intrusion Guard & Automated Alert System

A full-stack security platform for the **Smart India Hackathon (SIH)**: it
**hardens SSH access** on a cloud server, **detects brute-force login
attempts** in real time, **automatically blocks attacker IPs**, **sends
instant Telegram alerts**, and presents everything through a **professional,
government-portal-style web dashboard** with authentication, a sidebar
navigation, live stats, and per-admin settings/profile management.

---

## 1. Project Structure

```
cloud-ssh-intrusion-guard/
├── README.md
├── requirements.txt
├── .gitignore
├── run.py              # Local dev entry point — starts the dashboard
├── wsgi.py              # Production entry point (used by gunicorn)
├── Procfile              # Start command for Heroku/Railway-style platforms
├── render.yaml            # One-click Render Blueprint (optional)
├── __init__.py         # Flask app instance, settings, DB connection, login manager
├── dashboard.py         # Home / Blocked IPs / Alerts / Settings / Profile routes + API
├── auth.py              # Login / logout routes and the User model
├── utils.py             # Reads live/sample data for the dashboard UI
├── init_db.py           # Run once — creates the admin account
├── harden_ssh.sh         # SSH hardening automation (run on the target server)
├── ssh_monitor.py        # Detection engine — monitor, block, alert
├── static/
│   └── style.css          # Full dashboard styling
└── templates/
    ├── base.html           # Sidebar shell shared by every page
    ├── login.html
    ├── home.html
    ├── blocked_ips.html
    ├── alerts.html
    ├── settings.html
    └── profile.html
```

`__init__.py`, `dashboard.py`, and `auth.py` share one Flask `app` instance:
`__init__.py` creates it, then imports `auth` and `dashboard` at the bottom
so their `@app.route(...)` decorators register against it. `run.py` simply
imports that `app` and starts the server. This keeps every Python file at
the project root, ready to push straight to GitHub.

**Runtime files** (`settings.json`, `users.db`, `blocked_ips.json`,
`events.jsonl`, `monitor.log`) are generated automatically the first time
you run the app or the monitor — they are not shipped in the repo.

---

## 2. What's Inside

| Layer | Technology | Purpose |
|---|---|---|
| **Backend detection engine** | Python 3 (`ssh_monitor.py`) | Tails `/var/log/auth.log`, detects brute-force attempts, blocks IPs via `ufw`, sends Telegram alerts, writes a structured event feed |
| **Hardening automation** | Bash (`harden_ssh.sh`) | One-command SSH server hardening with automatic config backup |
| **Web dashboard (backend)** | Flask + Flask-Login + SQLite | Session-based authentication, JSON API, settings persistence |
| **Web dashboard (frontend)** | Jinja2 templates + hand-written CSS (no build step) | Sidebar layout, Home/Blocked IPs/Alerts/Settings/Profile pages, live auto-refresh |

`ssh_monitor.py` and the dashboard are decoupled but share one file,
**`settings.json`**: the dashboard's Settings page writes to it, and the
monitor reads from it, so configuring the system from the browser is
enough — no need to edit files by hand on the server. The dashboard also
reads `blocked_ips.json` and `events.jsonl`, which the monitor writes to;
until those exist, the dashboard shows built-in sample data so it looks
fully populated immediately after setup.

---

## 3. SIH Project Objectives

1. **Harden** the SSH daemon automatically (disable password login, disable
   root login, cap authentication retries).
2. **Monitor** SSH logs in real time and detect brute-force patterns using a
   configurable failed-attempt threshold per IP.
3. **Respond** automatically by blocking offending IPs at the firewall level
   (`ufw deny`), with automatic time-bound unblocking.
4. **Alert** the administrator instantly via Telegram from anywhere.
5. **Visualize** everything through a secure, professional web portal an
   administrator can monitor from a browser — no SSH access required to see
   what's happening.

---

## 4. Architecture Diagram

```
                          ┌─────────────────────────────────────────┐
                          │              Cloud Server (VM)            │
                          │                                            │
   Attacker ───SSH────►   │  sshd (hardened by harden_ssh.sh)          │
                          │     │ writes                               │
                          │     ▼                                      │
                          │  /var/log/auth.log                         │
                          │     │ tailed by                            │
                          │     ▼                                      │
                          │  ssh_monitor.py  ◄── reads settings.json    │
                          │     │  ┌─────────────────────────────┐     │
                          │     ├─►│ Failed-attempt counter (IP)  │     │
                          │     │  └──────────────┬──────────────┘     │
                          │     │           attempts ≥ threshold        │
                          │     │                  ▼                    │
                          │     │   ufw deny <IP>   +   Telegram alert   │
                          │     ▼                                      │
                          │  blocked_ips.json                          │
                          │  events.jsonl   ◄── structured feed         │
                          │     │                                      │
                          │     ▼                                      │
                          │  Flask Dashboard (__init__.py + ...)        │
                          │   ├─ auth.py     → login / logout (SQLite)  │
                          │   ├─ dashboard.py→ Home/BlockedIPs/Alerts/  │
                          │   │                Settings/Profile + API  │
                          │   │                writes settings.json    │
                          │   └─ templates + static → sidebar UI        │
                          └───────────────┬───────────────────────────┘
                                          │  HTTPS (browser)
                                          ▼
                              ┌───────────────────────┐
                              │   Administrator's       │
                              │   browser / phone       │
                              │  🛡️ Security Dashboard  │
                              └───────────────────────┘
                                          │
                                          ▼ (parallel channel)
                              ┌───────────────────────┐
                              │  Admin's Telegram chat  │
                              │  🚨 SSH Intrusion Alert │
                              └───────────────────────┘
```

---

## 5. Prerequisites

- Python 3.8+ and `pip`
- For the **detection engine** on a real server: a Debian/Ubuntu Linux VM
  with `ufw` installed and root access
- A Telegram bot token + chat ID for alerts (optional but recommended —
  see Section 6.4)

---

## 6. Running the Dashboard Locally (or on any server)

### 6.1 Install dependencies

```bash
cd cloud-ssh-intrusion-guard
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 6.2 Create the admin account

```bash
python3 init_db.py
```

You'll be prompted for a username and password (press Enter to accept the
defaults `admin` / `admin123` for local testing — **change this immediately
after first login** via the Profile page). This creates `users.db`.

### 6.3 Start the dashboard

```bash
python3 run.py
```

Visit **http://localhost:5000**. The first launch auto-creates
`settings.json` with sensible defaults and a random session secret key.
Sign in with the account from step 6.2 — you'll land on Home with stat
cards, recent activity, and full sidebar navigation (Home, Blocked IPs,
Alerts, Settings, Profile, Logout), populated with sample data until the
real detection engine starts producing live data.

### 6.4 (Optional) Configure Telegram alerts

1. Open Telegram, search for **@BotFather**, send `/newbot`, and copy the
   bot token it gives you.
2. Send your new bot any message, then visit
   `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` in a browser and
   copy the `"chat":{"id": ...}` value.
3. Enter both values on the dashboard's **Settings** page and save — this
   writes them into `settings.json`, which `ssh_monitor.py` also reads.

---

## 7. Pushing This Project to GitHub

```bash
cd cloud-ssh-intrusion-guard
git init
git add .
git commit -m "Initial commit — Cloud SSH Intrusion Guard"
git branch -M main
git remote add origin https://github.com/<your-username>/cloud-ssh-intrusion-guard.git
git push -u origin main
```

The included `.gitignore` already excludes `settings.json`, `users.db`, and
the generated log/state files, so no secrets or local databases get
committed. GitHub only stores and displays the *code* — it does not run
Python, so the repo alone won't give you a clickable working link. That's
what Section 8 is for.

---

## 8. Get a Live Link (Deploy the Dashboard)

To have a URL you can visit and it "just works" — login page, sidebar, live
stats — you need a host that runs Python, not just GitHub. The steps below
use **Render** (free tier, no credit card needed), but the same
`wsgi.py` / `Procfile` also work on Railway, Fly.io, PythonAnywhere, or any
other Python-friendly host.

### 8.1 Deploy on Render

1. Push the project to GitHub first (Section 7).
2. Go to **[render.com](https://render.com)** → sign in with GitHub →
   **New +** → **Web Service**.
3. Select your `cloud-ssh-intrusion-guard` repository.
4. Render usually detects `render.yaml` automatically and fills these in;
   if it asks you to confirm/enter them manually:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python init_db.py --non-interactive && gunicorn wsgi:app`
5. Under **Environment**, add:
   - `ADMIN_USERNAME` = a username of your choice
   - `ADMIN_PASSWORD` = a strong password of your choice

   (These are read once by `init_db.py` to create your admin login — without
   them it falls back to the insecure `admin` / `admin123` default, which is
   fine for a quick demo but not for anything public-facing.)
6. Click **Create Web Service**. After the build finishes, Render gives you
   a live URL like `https://cloud-ssh-intrusion-guard.onrender.com` — open
   it, sign in with the credentials from step 5, and the full dashboard
   (Home, Blocked IPs, Alerts, Settings, Profile) works exactly as it does
   locally, populated with sample data until a real `ssh_monitor.py`
   feeds it live events.

### 8.2 Notes on the free tier

- Render's free web services spin down after inactivity and take ~30–60
  seconds to wake up on the next visit — this is normal, not a bug.
- The free tier's disk is ephemeral, so `settings.json`/`users.db` can reset
  on redeploys. For a hackathon demo this is fine; for anything long-lived,
  attach a persistent disk (Render) or use a managed database instead of
  SQLite.
- `ssh_monitor.py` and `harden_ssh.sh` are meant to run on your **own**
  Linux server being protected — not on Render — since they need root
  access to `ufw` and `/var/log/auth.log`. The deployed dashboard is the
  viewing/admin layer; point its `settings.json` paths at the same
  `blocked_ips.json`/`events.jsonl` your real server's monitor writes to
  (e.g. by syncing them, or running both on the same box) to see live data
  instead of samples.

---

## 9. Deploying the Detection Engine on a Cloud Server

Run these steps **on the actual cloud VM** you want to protect (e.g. an AWS
EC2 / Azure VM / DigitalOcean droplet). Copy the whole project there first.

### 7.1 Harden SSH

> ⚠️ Make sure SSH key-based login already works before running this — it
> disables password authentication.

```bash
chmod +x harden_ssh.sh
sudo ./harden_ssh.sh
```

### 7.2 Enable the firewall

```bash
sudo ufw allow OpenSSH
sudo ufw enable
```

### 7.3 Run the monitor

```bash
sudo python3 ssh_monitor.py
```

It reads `settings.json` from the same folder — the exact file the
dashboard's Settings page writes to, so configure once from the browser
and both processes stay in sync.

For continuous background operation, run it as a `systemd` service:

```bash
sudo tee /etc/systemd/system/ssh-intrusion-guard.service > /dev/null <<'EOF'
[Unit]
Description=Cloud SSH Intrusion Guard - Detection Engine
After=network.target sshd.service

[Service]
Type=simple
WorkingDirectory=/opt/cloud-ssh-intrusion-guard
ExecStart=/usr/bin/python3 /opt/cloud-ssh-intrusion-guard/ssh_monitor.py
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now ssh-intrusion-guard.service
```

Run the dashboard (`run.py`, Section 6) on the same server so it reflects
live activity instead of sample data.

---

## 10. Testing Steps

### 8.1 Dashboard smoke test (no real server needed)

1. Run through Section 6 end-to-end.
2. Confirm you're redirected to `/login` when visiting `/home` while signed
   out.
3. Sign in — confirm you land on Home with 4 populated stat cards and a
   recent-activity table (from bundled sample data).
4. Click through **Blocked IPs**, **Alerts**, **Settings**, **Profile** in
   the sidebar — each should load without errors.
5. On **Settings**, change `max_attempts` and save — confirm `settings.json`
   is updated and a success message appears.
6. On **Profile**, change your password, log out, and log back in with the
   new password.

### 8.2 Verify SSH hardening (on the target server)

```bash
sudo sshd -t
grep -E "PasswordAuthentication|PermitRootLogin|MaxAuthTries" /etc/ssh/sshd_config
```
Expected: `PasswordAuthentication no`, `PermitRootLogin no`,
`MaxAuthTries 3`.

### 8.3 Verify live detection end-to-end

From a separate, **non-whitelisted** machine:
```bash
ssh invalid_user@<your-server-ip>   # repeat 3 times
```
On the server:
```bash
tail -f monitor.log                 # should show 3 failed attempts, then a block
sudo ufw status | grep <attacker-ip> # should show a DENY rule
```
Refresh the dashboard's Home page (or wait ~8s for auto-refresh) — the
**Failed Login Attempts** and **IPs Blocked** counters should increase, and
the new block appears on the **Blocked IPs** page. Check your Telegram chat
for the alert message.

---

## 11. Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| Can't log in | `init_db.py` not run yet | Run `python3 init_db.py` |
| Dashboard shows only sample data forever | `ssh_monitor.py` not running, or running from a different folder than the dashboard | Run both from the same project folder so they share `settings.json` |
| `ufw command not found` | ufw not installed | `sudo apt install ufw` |
| No Telegram alerts | Invalid bot token/chat ID | Re-check Section 6.4 |
| Locked out of SSH after hardening | Password auth disabled without a working key | Recover via your cloud provider's console/rescue mode; restore the backup from `/etc/ssh/backups/` |

---

## 12. Security Notes

- Passwords are hashed with Werkzeug's `generate_password_hash` (PBKDF2) —
  never stored in plain text.
- `settings.json` and `users.db` hold live secrets and credentials — the
  bundled `.gitignore` already excludes them from version control; never
  remove that exclusion or commit real Telegram tokens.
- Change the default `admin`/`admin123` credentials immediately via the
  Profile page after first login.
- For a public-facing deployment, run the dashboard behind HTTPS
  (e.g. via Nginx + Let's Encrypt) rather than Flask's built-in server.

## 13. License

MIT License. You are free to use, modify, and distribute this project.
