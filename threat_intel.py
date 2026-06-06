import requests
import sqlite3
import threading
import time
import os
from datetime import datetime, timedelta

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
CACHE_HOURS = 24  # Re-check IPs after 24 hours

# ── DB Setup ──────────────────────────────────────────────────────────────────

def init_threat_table(db_path: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                ip           TEXT PRIMARY KEY,
                abuse_score  INTEGER DEFAULT 0,
                country      TEXT,
                isp          TEXT,
                domain       TEXT,
                total_reports INTEGER DEFAULT 0,
                last_checked DATETIME,
                is_whitelisted INTEGER DEFAULT 0,
                usage_type   TEXT
            )
        """)
        conn.commit()

# ── API Call ──────────────────────────────────────────────────────────────────

def check_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for a single IP.
    Returns a dict with threat info or None on failure.
    """
    # Skip private/loopback IPs
    if ip.startswith(("127.", "192.168.", "10.", "172.16.", "0.0.0.0")):
        return {
            "ip": ip,
            "abuse_score": 0,
            "country": "Private",
            "isp": "Local Network",
            "domain": "",
            "total_reports": 0,
            "is_whitelisted": 0,
            "usage_type": "Private"
        }

    if not ABUSEIPDB_API_KEY:
        print("[ABUSEIPDB] ABUSEIPDB_API_KEY is not set; skipping live lookup")
        return None

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True
            },
            timeout=5,
        )

        if response.status_code == 200:
            d = response.json().get("data", {})
            return {
                "ip":             ip,
                "abuse_score":    d.get("abuseConfidenceScore", 0),
                "country":        d.get("countryCode", "Unknown"),
                "isp":            d.get("isp", "Unknown"),
                "domain":         d.get("domain", ""),
                "total_reports":  d.get("totalReports", 0),
                "is_whitelisted": 1 if d.get("isWhitelisted") else 0,
                "usage_type":     d.get("usageType", "Unknown"),
            }
        else:
            print(f"[ABUSEIPDB] HTTP {response.status_code} for {ip}")
            return None

    except Exception as e:
        print(f"[ABUSEIPDB ERROR] {ip}: {e}")
        return None

# ── Cache Layer ───────────────────────────────────────────────────────────────

def get_cached(db_path: str, ip: str) -> dict | None:
    """Return cached result if fresh enough."""
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM threat_intel WHERE ip = ?", (ip,)
            ).fetchone()
            if row:
                last = datetime.strptime(row["last_checked"], "%Y-%m-%d %H:%M:%S")
                if datetime.utcnow() - last < timedelta(hours=CACHE_HOURS):
                    return dict(row)
    except Exception as e:
        print(f"[THREAT CACHE ERROR] {e}")
    return None


def save_to_cache(db_path: str, data: dict):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO threat_intel
                (ip, abuse_score, country, isp, domain, total_reports, last_checked, is_whitelisted, usage_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["ip"],
                data["abuse_score"],
                data["country"],
                data["isp"],
                data["domain"],
                data["total_reports"],
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                data["is_whitelisted"],
                data["usage_type"],
            ))
            conn.commit()
    except Exception as e:
        print(f"[THREAT SAVE ERROR] {e}")

# ── Main Public Function ──────────────────────────────────────────────────────

def get_threat_info(db_path: str, ip: str) -> dict:
    """
    Get threat info for an IP — from cache or live API.
    Always returns a dict (never None).
    """
    cached = get_cached(db_path, ip)
    if cached:
        return cached

    result = check_ip(ip)

    # Cache either the real result or a failure stub — prevents infinite retries
    if not result:
        result = {
            "ip": ip,
            "abuse_score": -1,
            "country": "Unknown",
            "isp": "Unknown",
            "domain": "",
            "total_reports": 0,
            "is_whitelisted": 0,
            "usage_type": "Unknown",
        }

    save_to_cache(db_path, result)
    return result


def get_threat_score_async(db_path: str, ip: str, callback):
    """
    Non-blocking version — runs in background thread, calls callback(result) when done.
    Use this from the GUI to avoid freezing.
    """
    def _run():
        result = get_threat_info(db_path, ip)
        callback(result)
    threading.Thread(target=_run, daemon=True).start()


def score_to_label(score: int) -> tuple[str, str]:
    """Returns (label, color) for a given abuse score."""
    if score < 0:
        return "UNKNOWN", "#888888"
    elif score == 0:
        return "CLEAN", "#00ff88"
    elif score < 25:
        return "LOW RISK", "#74b9ff"
    elif score < 50:
        return "SUSPICIOUS", "#ffa502"
    elif score < 75:
        return "MALICIOUS", "#ff4757"
    else:
        return "CRITICAL THREAT", "#ff0000"


def bulk_enrich(db_path: str, ips: list, callback=None):
    """
    Enrich a list of IPs in background threads.
    Optional callback(ip, result) called for each result.
    """
    def _enrich_one(ip):
        result = get_threat_info(db_path, ip)
        if callback:
            callback(ip, result)

    for ip in set(ips):
        threading.Thread(target=_enrich_one, args=(ip,), daemon=True).start()
        time.sleep(0.05)  # Small delay to avoid hammering the API
