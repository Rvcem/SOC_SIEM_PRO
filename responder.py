"""
responder.py — Active Response Engine for SOC SIEM PRO
Handles:
  1. Email alerts (Gmail SMTP) for CRITICAL/HIGH events
  2. Auto-block IPs based on threat score or rule triggers
  3. Custom rule engine with DB-persisted rules
"""

import sqlite3
import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import defaultdict

# ── Email Config (set via SettingsDialog, stored in DB) ───────────────────────

DEFAULT_EMAIL_CFG = {
    "smtp_host":    "smtp.gmail.com",
    "smtp_port":    587,
    "sender":       "",
    "app_password": "",
    "recipient":    "",
    "enabled":      False,
}

_email_sent_cache = {}
EMAIL_COOLDOWN = 300  # seconds between same alert emails

# ── DB Setup ──────────────────────────────────────────────────────────────────

def init_responder_tables(db_path: str):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_config (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocklist (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT UNIQUE,
                reason     TEXT,
                added_at   DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(blocklist)").fetchall()}
        if "added_at" not in columns:
            conn.execute("ALTER TABLE blocklist ADD COLUMN added_at DATETIME")
            if "blocked_at" in columns:
                conn.execute("UPDATE blocklist SET added_at = blocked_at WHERE added_at IS NULL")
            conn.execute("UPDATE blocklist SET added_at = CURRENT_TIMESTAMP WHERE added_at IS NULL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id   INTEGER,
                ip            TEXT,
                event_type    TEXT,
                quarantined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                notes         TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                condition  TEXT NOT NULL,
                threshold  INTEGER DEFAULT 5,
                window_sec INTEGER DEFAULT 60,
                action     TEXT NOT NULL DEFAULT 'block',
                enabled    INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rule_triggers (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id      INTEGER,
                source_ip    TEXT,
                triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                action_taken TEXT
            )
        """)
        count = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        if count == 0:
            default_rules = [
                ("Bruteforce Auto-Block", "bruteforce",   5,  60, "block"),
                ("Port Scan Auto-Block",  "port scan",    3,  60, "block"),
                ("DDoS Auto-Block",       "ddos",         2,  30, "block"),
                ("High Threat Score",     "threat_score", 75,  0, "block"),
                ("SQL Injection Alert",   "sql injection",1,  60, "email"),
                ("Malware Alert",         "malware",      1,  60, "email"),
            ]
            conn.executemany(
                "INSERT INTO rules (name, condition, threshold, window_sec, action) VALUES (?,?,?,?,?)",
                default_rules
            )
        conn.commit()
    finally:
        conn.close()

# ── Email Config ──────────────────────────────────────────────────────────────

def save_email_config(db_path: str, cfg: dict):
    with sqlite3.connect(db_path) as conn:
        for k, v in cfg.items():
            conn.execute(
                "INSERT OR REPLACE INTO email_config (key, value) VALUES (?, ?)",
                (k, str(v))
            )
        conn.commit()

def load_email_config(db_path: str) -> dict:
    cfg = dict(DEFAULT_EMAIL_CFG)
    try:
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute("SELECT key, value FROM email_config").fetchall()
            for k, v in rows:
                if k in cfg:
                    if k == "smtp_port":
                        cfg[k] = int(v)
                    elif k == "enabled":
                        cfg[k] = v == "True"
                    else:
                        cfg[k] = v
    except Exception as e:
        print(f"[EMAIL CONFIG LOAD ERROR] {e}")
    return cfg

# ── Email Sender ──────────────────────────────────────────────────────────────

def send_alert_email(cfg: dict, subject: str, body: str) -> bool:
    if not cfg.get("enabled"):
        return False
    if not cfg.get("sender") or not cfg.get("app_password") or not cfg.get("recipient"):
        print("[EMAIL] Not configured — skipping")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"SOC SIEM PRO <{cfg['sender']}>"
        msg["To"]      = cfg["recipient"]
        html = f"""
        <html><body style="background:#0b0b1a;color:#fff;font-family:Courier New;padding:20px;">
        <h2 style="color:#ff4757;">🚨 SOC SIEM ALERT</h2>
        <hr style="border-color:#2e2e66;">
        <pre style="color:#00f2ff;">{body}</pre>
        <hr style="border-color:#2e2e66;">
        <p style="color:#666;font-size:11px;">SOC SIEM PRO — Automated Alert System<br>
        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </body></html>
        """
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=10) as server:
            server.starttls()
            server.login(cfg["sender"], cfg["app_password"])
            server.sendmail(cfg["sender"], cfg["recipient"], msg.as_string())
        print(f"[EMAIL] Sent: {subject}")
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False

def send_alert_async(cfg: dict, subject: str, body: str, cache_key: str = None):
    if cache_key:
        now = time.time()
        if cache_key in _email_sent_cache:
            if now - _email_sent_cache[cache_key] < EMAIL_COOLDOWN:
                return
        _email_sent_cache[cache_key] = now
    threading.Thread(target=send_alert_email, args=(cfg, subject, body), daemon=True).start()

# ── Blocklist ─────────────────────────────────────────────────────────────────

def block_ip(db_path: str, ip: str, reason: str = "Auto-blocked by rule engine") -> bool:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO blocklist (ip, reason) VALUES (?, ?)",
                (ip, reason)
            )
            conn.execute("UPDATE incidents SET status = ? WHERE source_ip = ?", ("Blocked", ip))
            conn.commit()
        print(f"[BLOCK] {ip} — {reason}")
        return True
    except Exception as e:
        print(f"[BLOCK ERROR] {e}")
        return False

def unblock_ip(db_path: str, ip: str) -> bool:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("DELETE FROM blocklist WHERE ip = ?", (ip,))
            conn.commit()
        return True
    except Exception as e:
        print(f"[UNBLOCK ERROR] {e}")
        return False

def get_blocklist(db_path: str) -> list:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(
                "SELECT * FROM blocklist ORDER BY added_at DESC"
            ).fetchall()]
    except:
        return []

# ── Rule Engine ───────────────────────────────────────────────────────────────

_event_window: dict = defaultdict(list)
_window_lock = threading.Lock()

def get_rules(db_path: str) -> list:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(
                "SELECT * FROM rules ORDER BY id"
            ).fetchall()]
    except:
        return []

def add_rule(db_path: str, name: str, condition: str,
             threshold: int, window_sec: int, action: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO rules (name, condition, threshold, window_sec, action) VALUES (?,?,?,?,?)",
            (name, condition.lower(), threshold, window_sec, action)
        )
        conn.commit()

def toggle_rule(db_path: str, rule_id: int, enabled: bool):
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE rules SET enabled=? WHERE id=?",
                     (1 if enabled else 0, rule_id))
        conn.commit()

def delete_rule(db_path: str, rule_id: int):
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
        conn.commit()

def _log_trigger(db_path: str, rule_id: int, ip: str, action: str):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO rule_triggers (rule_id, source_ip, action_taken) VALUES (?,?,?)",
                (rule_id, ip, action)
            )
            conn.commit()
    except:
        pass

def evaluate_rules(db_path: str, ip: str, event_type: str,
                   severity: str, threat_score: int,
                   email_cfg: dict) -> list:
    """
    Evaluate all active rules against an incoming event.
    Returns list of action strings taken.
    """
    actions_taken = []
    now = datetime.utcnow()
    event_lower = event_type.lower()

    with _window_lock:
        _event_window[ip].append((event_lower, now))
        cutoff = now - timedelta(seconds=600)
        _event_window[ip] = [(e, t) for e, t in _event_window[ip] if t > cutoff]
        window_snapshot = list(_event_window[ip])

    rules = get_rules(db_path)

    for rule in rules:
        if not rule["enabled"]:
            continue
        condition  = rule["condition"].lower()
        threshold  = rule["threshold"]
        window_sec = rule["window_sec"]
        action     = rule["action"]
        rule_id    = rule["id"]
        rule_name  = rule["name"]
        triggered  = False

        if condition == "threat_score":
            if threat_score >= threshold:
                triggered = True
        else:
            window_start = now - timedelta(seconds=window_sec)
            matching = [e for e, t in window_snapshot
                        if condition in e and t >= window_start]
            if len(matching) >= threshold:
                triggered = True

        if not triggered:
            continue

        if action == "block":
            reason = f"Rule: {rule_name} ({event_type})"
            if block_ip(db_path, ip, reason):
                actions_taken.append(f"BLOCKED by '{rule_name}'")
                _log_trigger(db_path, rule_id, ip, "block")
                subject = f"[SOC SIEM] Auto-Block: {ip}"
                body = (
                    f"IP BLOCKED AUTOMATICALLY\n"
                    f"{'='*40}\n"
                    f"IP Address  : {ip}\n"
                    f"Rule        : {rule_name}\n"
                    f"Event Type  : {event_type}\n"
                    f"Severity    : {severity}\n"
                    f"Threat Score: {threat_score}\n"
                    f"Time        : {now.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
                )
                send_alert_async(email_cfg, subject, body, cache_key=f"block_{ip}")

        elif action == "email":
            subject = f"[SOC SIEM] {severity} Alert: {event_type} from {ip}"
            body = (
                f"SECURITY ALERT TRIGGERED\n"
                f"{'='*40}\n"
                f"Rule        : {rule_name}\n"
                f"IP Address  : {ip}\n"
                f"Event Type  : {event_type}\n"
                f"Severity    : {severity}\n"
                f"Threat Score: {threat_score}\n"
                f"Time        : {now.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            )
            send_alert_async(email_cfg, subject, body,
                             cache_key=f"email_{ip}_{event_lower}")
            actions_taken.append(f"EMAIL sent for '{rule_name}'")
            _log_trigger(db_path, rule_id, ip, "email")

    # Always email CRITICAL events regardless of rules
    if severity.upper() == "CRITICAL":
        subject = f"[SOC SIEM] CRITICAL: {event_type} from {ip}"
        body = (
            f"CRITICAL EVENT DETECTED\n"
            f"{'='*40}\n"
            f"IP Address  : {ip}\n"
            f"Event Type  : {event_type}\n"
            f"Severity    : CRITICAL\n"
            f"Threat Score: {threat_score}\n"
            f"Time        : {now.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        )
        send_alert_async(email_cfg, subject, body,
                         cache_key=f"critical_{ip}_{event_lower}")

    return actions_taken
