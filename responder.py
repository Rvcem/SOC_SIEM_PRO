"""
responder.py — Active Response Engine for SOC SIEM PRO
Handles:
  1. Email alerts (Gmail SMTP) for CRITICAL/HIGH events
  2. Auto-block IPs based on threat score or rule triggers
  3. Custom rule engine v1 (legacy) + v2 (multi-condition, multi-action)
"""

import ipaddress
import json
import re as _re
import sqlite3
import smtplib
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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


# ══════════════════════════════════════════════════════════════════════════════
#  RULE ENGINE v2 — multi-condition, multi-action, priority, cooldown
# ══════════════════════════════════════════════════════════════════════════════

# ── In-memory state ───────────────────────────────────────────────────────────

_v2_rule_windows  = defaultdict(list)    # {(rule_id, key): [timestamps]}
_v2_cooldowns: dict = {}                 # {(rule_id, ip): last_fired_ts}
_v2_global_window = deque(maxlen=5000)   # global event log for scope=global rules
_v2_lock          = threading.Lock()

# ── Default rules (seeded on first run) ───────────────────────────────────────

_DEFAULT_RULES_V2 = [
    {
        "name": "Whitelist Internal Networks",
        "description": "Skip rule evaluation for RFC-1918 source addresses",
        "priority": 1, "stop_on_match": 1, "enabled": 1,
        "conditions": json.dumps([
            {"field": "source_ip", "op": "regex",
             "value": r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"}
        ]),
        "condition_mode": "AND", "threshold": 1, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 0,
        "action_block": 0, "action_email": 0,
        "action_quarantine": 0, "action_escalate": 0,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "VT-Confirmed Malware",
        "description": "Block, quarantine and escalate any file flagged by VirusTotal",
        "priority": 10, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([{"field": "vt_score", "op": "gte", "value": "55"}]),
        "condition_mode": "AND", "threshold": 1, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 3600,
        "action_block": 1, "action_email": 1,
        "action_quarantine": 1, "action_escalate": 1,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "Off-Hours Critical Event",
        "description": "Escalate CRITICAL severity events that occur between 00:00 and 06:00",
        "priority": 20, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([
            {"field": "severity",  "op": "eq",      "value": "CRITICAL"},
            {"field": "hour",      "op": "between",  "value": "0,6"},
        ]),
        "condition_mode": "AND", "threshold": 1, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 1800,
        "action_block": 0, "action_email": 1,
        "action_quarantine": 0, "action_escalate": 1,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "Bruteforce Auto-Block",
        "description": "Block IP after 5 failed authentication events in 60 seconds",
        "priority": 30, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([{"field": "event_type", "op": "contains", "value": "bruteforce"}]),
        "condition_mode": "AND", "threshold": 5, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 600,
        "action_block": 1, "action_email": 0,
        "action_quarantine": 0, "action_escalate": 0,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "Password Spray — Behavioral",
        "description": "Block IPs whose behavior engine detects a spray pattern",
        "priority": 35, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([
            {"field": "behavior_score", "op": "gte", "value": "40"},
            {"field": "event_type",     "op": "contains", "value": "bruteforce"},
        ]),
        "condition_mode": "AND", "threshold": 1, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 1800,
        "action_block": 1, "action_email": 1,
        "action_quarantine": 0, "action_escalate": 0,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "DDoS Auto-Block",
        "description": "Block source IP on 2+ DDoS events in 30 seconds",
        "priority": 40, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([{"field": "event_type", "op": "contains", "value": "ddos"}]),
        "condition_mode": "AND", "threshold": 2, "window_sec": 30,
        "scope": "per_ip", "cooldown_sec": 600,
        "action_block": 1, "action_email": 1,
        "action_quarantine": 0, "action_escalate": 0,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "C2 Communication",
        "description": "Block, quarantine and escalate any confirmed C2 callback",
        "priority": 45, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([{"field": "event_type", "op": "contains", "value": "c2"}]),
        "condition_mode": "AND", "threshold": 1, "window_sec": 300,
        "scope": "per_ip", "cooldown_sec": 3600,
        "action_block": 1, "action_email": 1,
        "action_quarantine": 1, "action_escalate": 1,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "High Threat Score",
        "description": "Block any IP whose combined threat score reaches 80",
        "priority": 50, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([{"field": "threat_score", "op": "gte", "value": "80"}]),
        "condition_mode": "AND", "threshold": 1, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 300,
        "action_block": 1, "action_email": 0,
        "action_quarantine": 0, "action_escalate": 0,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "SQL Injection Alert",
        "description": "Email on any SQL injection; quarantine after 3 hits in 60s",
        "priority": 60, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([{"field": "event_type", "op": "contains", "value": "sql injection"}]),
        "condition_mode": "AND", "threshold": 1, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 300,
        "action_block": 0, "action_email": 1,
        "action_quarantine": 0, "action_escalate": 0,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "Port Scan Auto-Block",
        "description": "Block after 3 port-scan events in 60 seconds",
        "priority": 70, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([{"field": "event_type", "op": "contains", "value": "port scan"}]),
        "condition_mode": "AND", "threshold": 3, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 600,
        "action_block": 1, "action_email": 0,
        "action_quarantine": 0, "action_escalate": 0,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "Lateral Movement",
        "description": "Alert and quarantine on any lateral movement detection",
        "priority": 75, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([{"field": "event_type", "op": "contains", "value": "lateral movement"}]),
        "condition_mode": "AND", "threshold": 1, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 900,
        "action_block": 0, "action_email": 1,
        "action_quarantine": 1, "action_escalate": 1,
        "action_webhook": "", "exclude_ips": "",
    },
    {
        "name": "Malware / Ransomware",
        "description": "Email immediately on any malware or ransomware event",
        "priority": 80, "stop_on_match": 0, "enabled": 1,
        "conditions": json.dumps([{"field": "event_type", "op": "contains", "value": "malware"}]),
        "condition_mode": "AND", "threshold": 1, "window_sec": 60,
        "scope": "per_ip", "cooldown_sec": 300,
        "action_block": 0, "action_email": 1,
        "action_quarantine": 0, "action_escalate": 0,
        "action_webhook": "", "exclude_ips": "",
    },
]

# ── DB setup ──────────────────────────────────────────────────────────────────

def init_rules_v2_table(db_path: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rules_v2 (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                name             TEXT    NOT NULL,
                description      TEXT    DEFAULT '',
                priority         INTEGER DEFAULT 50,
                enabled          INTEGER DEFAULT 1,
                stop_on_match    INTEGER DEFAULT 0,
                conditions       TEXT    NOT NULL DEFAULT '[]',
                condition_mode   TEXT    DEFAULT 'AND',
                threshold        INTEGER DEFAULT 1,
                window_sec       INTEGER DEFAULT 60,
                scope            TEXT    DEFAULT 'per_ip',
                action_block     INTEGER DEFAULT 0,
                action_email     INTEGER DEFAULT 0,
                action_quarantine INTEGER DEFAULT 0,
                action_escalate  INTEGER DEFAULT 0,
                action_webhook   TEXT    DEFAULT '',
                cooldown_sec     INTEGER DEFAULT 300,
                exclude_ips      TEXT    DEFAULT '',
                created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        if conn.execute("SELECT COUNT(*) FROM rules_v2").fetchone()[0] == 0:
            for r in _DEFAULT_RULES_V2:
                conn.execute("""
                    INSERT INTO rules_v2
                      (name, description, priority, enabled, stop_on_match,
                       conditions, condition_mode, threshold, window_sec, scope,
                       action_block, action_email, action_quarantine, action_escalate,
                       action_webhook, cooldown_sec, exclude_ips)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    r["name"], r["description"], r["priority"], r["enabled"],
                    r["stop_on_match"], r["conditions"], r["condition_mode"],
                    r["threshold"], r["window_sec"], r["scope"],
                    r["action_block"], r["action_email"], r["action_quarantine"],
                    r["action_escalate"], r["action_webhook"], r["cooldown_sec"],
                    r["exclude_ips"],
                ))
        conn.commit()

# ── CRUD ──────────────────────────────────────────────────────────────────────

def get_rules_v2(db_path: str) -> list:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(
                "SELECT * FROM rules_v2 ORDER BY priority, id"
            ).fetchall()]
    except Exception:
        return []


def add_rule_v2(db_path: str, data: dict):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            INSERT INTO rules_v2
              (name, description, priority, enabled, stop_on_match,
               conditions, condition_mode, threshold, window_sec, scope,
               action_block, action_email, action_quarantine, action_escalate,
               action_webhook, cooldown_sec, exclude_ips)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            data["name"], data.get("description", ""), data.get("priority", 50), 1,
            data.get("stop_on_match", 0), data.get("conditions", "[]"),
            data.get("condition_mode", "AND"), data.get("threshold", 1),
            data.get("window_sec", 60), data.get("scope", "per_ip"),
            data.get("action_block", 0), data.get("action_email", 0),
            data.get("action_quarantine", 0), data.get("action_escalate", 0),
            data.get("action_webhook", ""), data.get("cooldown_sec", 300),
            data.get("exclude_ips", ""),
        ))
        conn.commit()


def update_rule_v2(db_path: str, rule_id: int, data: dict):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            UPDATE rules_v2 SET
              name=?, description=?, priority=?, stop_on_match=?,
              conditions=?, condition_mode=?, threshold=?, window_sec=?,
              scope=?, action_block=?, action_email=?, action_quarantine=?,
              action_escalate=?, action_webhook=?, cooldown_sec=?, exclude_ips=?
            WHERE id=?
        """, (
            data["name"], data.get("description", ""), data.get("priority", 50),
            data.get("stop_on_match", 0), data.get("conditions", "[]"),
            data.get("condition_mode", "AND"), data.get("threshold", 1),
            data.get("window_sec", 60), data.get("scope", "per_ip"),
            data.get("action_block", 0), data.get("action_email", 0),
            data.get("action_quarantine", 0), data.get("action_escalate", 0),
            data.get("action_webhook", ""), data.get("cooldown_sec", 300),
            data.get("exclude_ips", ""), rule_id,
        ))
        conn.commit()


def delete_rule_v2(db_path: str, rule_id: int):
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM rules_v2 WHERE id=?", (rule_id,))
        conn.commit()


def toggle_rule_v2(db_path: str, rule_id: int, enabled: bool):
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE rules_v2 SET enabled=? WHERE id=?",
                     (1 if enabled else 0, rule_id))
        conn.commit()

# ── Condition evaluator ───────────────────────────────────────────────────────

def _eval_condition(cond: dict, ctx: dict) -> bool:
    field = cond.get("field", "")
    op    = cond.get("op", "eq")
    value = str(cond.get("value", ""))
    raw   = ctx.get(field, "")

    try:
        if op == "eq":
            return str(raw).lower() == value.lower()
        if op == "neq":
            return str(raw).lower() != value.lower()
        if op == "contains":
            return value.lower() in str(raw).lower()
        if op == "regex":
            return bool(_re.search(value, str(raw), _re.I))
        if op == "in":
            items = [x.strip().lower() for x in value.split(",")]
            return str(raw).lower() in items
        if op in ("gt", "lt", "gte", "lte"):
            n, v = float(raw), float(value)
            return {"gt": n > v, "lt": n < v, "gte": n >= v, "lte": n <= v}[op]
        if op == "between":
            lo, hi = [float(x.strip()) for x in value.split(",", 1)]
            return lo <= float(raw) <= hi
    except Exception:
        pass
    return False


def _matches_conditions(conditions_json: str, mode: str, ctx: dict) -> bool:
    try:
        conditions = json.loads(conditions_json or "[]")
    except Exception:
        return False
    if not conditions:
        return True
    results = [_eval_condition(c, ctx) for c in conditions]
    return all(results) if mode.upper() == "AND" else any(results)


def _ip_excluded(ip: str, exclude_str: str) -> bool:
    if not exclude_str.strip():
        return False
    try:
        addr = ipaddress.ip_address(ip)
        for entry in exclude_str.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                if ip == entry:
                    return True
    except Exception:
        pass
    return False

# ── Quarantine helper ─────────────────────────────────────────────────────────

def _quarantine_ip(db_path: str, ip: str, event_type: str, rule_name: str):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT INTO quarantine (ip, event_type, notes)
                VALUES (?, ?, ?)
            """, (ip, event_type, f"Auto-quarantine by rule: {rule_name}"))
            conn.commit()
    except Exception as exc:
        print(f"[QUARANTINE ERROR] {exc}")


def _escalate_incident(db_path: str, ip: str):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                UPDATE incidents SET severity='CRITICAL'
                WHERE source_ip=? AND severity != 'CRITICAL'
                  AND id = (SELECT MAX(id) FROM incidents WHERE source_ip=?)
            """, (ip, ip))
            conn.commit()
    except Exception as exc:
        print(f"[ESCALATE ERROR] {exc}")


def _call_webhook(url: str, payload: dict):
    try:
        import requests as _req
        _req.post(url, json=payload, timeout=5)
    except Exception as exc:
        print(f"[WEBHOOK ERROR] {exc}")

# ── Main evaluator ────────────────────────────────────────────────────────────

def evaluate_rules_v2(
    db_path: str,
    ip: str,
    event_type: str,
    severity: str,
    category: str,
    threat_score: int,
    behavior_score: int,
    vt_score: int,
    anomaly_score: float,
    raw_log: str,
    email_cfg: dict,
) -> list:
    """
    Evaluate all enabled v2 rules (ordered by priority) against the event.
    Returns list of human-readable action strings taken.
    """
    now = datetime.utcnow()
    ts  = time.time()

    ctx = {
        "source_ip":      ip,
        "event_type":     event_type.lower(),
        "severity":       severity.upper(),
        "category":       (category or "").lower(),
        "threat_score":   int(threat_score or 0),
        "behavior_score": int(behavior_score or 0),
        "vt_score":       int(vt_score or 0),
        "anomaly_score":  float(anomaly_score or 0),
        "raw_log":        (raw_log or "").lower(),
        "hour":           now.hour,
        "day_of_week":    now.weekday(),
    }

    with _v2_lock:
        _v2_global_window.append({"ts": ts, "ctx": ctx})
        # Prune stale per-rule windows (keep max 1h)
        cutoff = ts - 3600
        for key in list(_v2_rule_windows.keys()):
            _v2_rule_windows[key] = [t for t in _v2_rule_windows[key] if t > cutoff]

    rules        = get_rules_v2(db_path)
    actions_taken = []

    for rule in rules:
        if not rule.get("enabled"):
            continue

        rule_id    = rule["id"]
        rule_name  = rule["name"]
        cooldown   = int(rule.get("cooldown_sec", 300))
        scope      = rule.get("scope", "per_ip")
        threshold  = int(rule.get("threshold", 1))
        window_sec = int(rule.get("window_sec", 60))

        # ── IP exclusion ──────────────────────────────────────────────────────
        if _ip_excluded(ip, rule.get("exclude_ips", "")):
            if rule.get("stop_on_match"):
                break
            continue

        # ── Condition check ───────────────────────────────────────────────────
        if not _matches_conditions(rule.get("conditions", "[]"),
                                   rule.get("condition_mode", "AND"), ctx):
            continue

        # ── Threshold / window check ──────────────────────────────────────────
        window_key = (rule_id, "global" if scope == "global" else ip)
        with _v2_lock:
            _v2_rule_windows[window_key].append(ts)
            hits_in_window = sum(
                1 for t in _v2_rule_windows[window_key]
                if ts - t <= window_sec
            )

        if hits_in_window < threshold:
            continue

        # ── Cooldown check ────────────────────────────────────────────────────
        cooldown_key = (rule_id, ip)
        with _v2_lock:
            last_fired = _v2_cooldowns.get(cooldown_key, 0)
            if cooldown > 0 and (ts - last_fired) < cooldown:
                continue
            _v2_cooldowns[cooldown_key] = ts

        # ── Execute actions ───────────────────────────────────────────────────
        fired_actions = []

        if rule.get("action_block"):
            reason = f"Rule v2: {rule_name} ({event_type})"
            if block_ip(db_path, ip, reason):
                fired_actions.append("BLOCKED")

        if rule.get("action_quarantine"):
            _quarantine_ip(db_path, ip, event_type, rule_name)
            fired_actions.append("QUARANTINED")

        if rule.get("action_escalate"):
            _escalate_incident(db_path, ip)
            fired_actions.append("ESCALATED")

        if rule.get("action_email"):
            actions_badge = " + ".join(fired_actions) or "alert"
            subject = f"[SOC SIEM v2] Rule '{rule_name}' fired — {ip}"
            body = (
                f"RULE ENGINE v2 — {actions_badge}\n"
                f"{'='*44}\n"
                f"Rule        : {rule_name}\n"
                f"Description : {rule.get('description','')}\n"
                f"Priority    : {rule.get('priority')}\n"
                f"IP Address  : {ip}\n"
                f"Event Type  : {event_type}  |  Severity: {severity}\n"
                f"Threat Score: {threat_score}  |  Behavior: {behavior_score}"
                f"  |  VT: {vt_score}\n"
                f"Hits/Window : {hits_in_window}/{threshold} in {window_sec}s\n"
                f"Time (UTC)  : {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            send_alert_async(email_cfg, subject, body,
                             cache_key=f"v2_{rule_id}_{ip}")
            fired_actions.append("EMAIL")

        if rule.get("action_webhook"):
            threading.Thread(
                target=_call_webhook,
                args=(rule["action_webhook"], {
                    "rule": rule_name, "ip": ip,
                    "event_type": event_type, "severity": severity,
                    "threat_score": threat_score, "actions": fired_actions,
                    "timestamp": now.isoformat(),
                }),
                daemon=True,
            ).start()
            fired_actions.append("WEBHOOK")

        if fired_actions:
            summary = f"[{rule_name}] → {' + '.join(fired_actions)}"
            actions_taken.append(summary)
            # Log to rule_triggers table
            try:
                with sqlite3.connect(db_path) as conn:
                    conn.execute(
                        "INSERT INTO rule_triggers (rule_id, source_ip, action_taken)"
                        " VALUES (?,?,?)",
                        (rule_id, ip, ", ".join(fired_actions)),
                    )
                    conn.commit()
            except Exception:
                pass

        if rule.get("stop_on_match"):
            break

    return actions_taken
