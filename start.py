import threading
import sys
import socket
import sqlite3
import re
import os
import time
import secrets
from collections import defaultdict
from PyQt6.QtWidgets import QApplication
from backend.api import app as flask_app, init_extra_tables
from gui.app import SOCDashboard
from core.detector import detect_event, check_anomaly
from core.ai_analyzer import analyze_log
from core.schema import ensure_incident_schema
from login import LoginWindow
from threat_intel import init_threat_table
from responder import block_ip, init_responder_tables
from sandbox_integrations import extract_observables, init_sandbox_tables, submit_observable_async


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents.db")
ensure_incident_schema(DB_PATH)
init_responder_tables(DB_PATH)
init_sandbox_tables(DB_PATH)
dedup_cache = {}
DEDUP_WINDOW = 30

def is_duplicate(ip, etype):
    key = (ip, etype)
    now = time.time()
    if key in dedup_cache:
        if now - dedup_cache[key] < DEDUP_WINDOW:
            return True
    dedup_cache[key] = now
    return False

ip_event_counts = defaultdict(int)
ip_event_window = defaultdict(float)
ANOMALY_WINDOW = 60
ANOMALY_THRESHOLD = 2.5

def get_blocklist():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute("SELECT ip FROM blocklist").fetchall()
            return {r[0] for r in rows}
    except:
        return set()

def engine_listener():
    print(f"[*] Engine starting. Database Path: {DB_PATH}")
    try:
        ensure_incident_schema(DB_PATH)
        print("[*] Database ready.")
    except Exception as e:
        print(f"Database Init Error: {e}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 5555))
        print("[*] UDP Engine listening on 127.0.0.1:5555")
    except Exception as e:
        print(f"Socket Error: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            log = data.decode("utf-8", errors="ignore")
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", log)
            sip = ip_match.group(1) if ip_match else addr[0]

            if sip in get_blocklist():
                print(f"[BLOCKED] Packet from {sip} dropped")
                continue

            etype, severity, category = detect_event(log)

            if is_duplicate(sip, etype):
                print(f"[~] Duplicate skipped: {etype} from {sip}")
                continue

            now = time.time()
            if now - ip_event_window[sip] > ANOMALY_WINDOW:
                ip_event_counts[sip] = 0
                ip_event_window[sip] = now
            ip_event_counts[sip] += 1

            anomaly_score = check_anomaly(sip, ip_event_counts[sip], etype, severity)
            if anomaly_score > ANOMALY_THRESHOLD:
                print(f"[!] ANOMALY DETECTED from {sip} (z-score: {anomaly_score:.2f})")
                etype = "Anomaly Detected"
                severity = "CRITICAL"
                category = "ML Detection"

            ai = analyze_log(log, sip, etype, severity, anomaly_score)
            status = "Logged"
            if ai.get("auto_block"):
                block_ip(DB_PATH, sip, f"Auto-block: AI threat score {ai['threat_score']}")
                status = "Blocked"

            for observable in extract_observables(log):
                submit_observable_async(DB_PATH, observable, sip)

            with sqlite3.connect(DB_PATH, timeout=10) as db_conn:
                db_conn.execute("""INSERT INTO incidents
                    (source_ip, event_type, severity, category, status, raw_log,
                     anomaly_score, threat_score, ai_score, ai_summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                        sip, etype, severity, category, status, log,
                        float(anomaly_score), ai["threat_score"], ai["ai_score"], ai["ai_summary"]
                    ))
            print(f"[+] Alert Logged: {etype} ({severity}) from {sip} | threat={ai['threat_score']}")

        except Exception as e:
            print(f"Engine Loop Error: {e}")


def _load_or_create_api_key(db_path: str) -> str:
    """Persist a random API key in the DB so it survives restarts."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)")
        row = conn.execute("SELECT value FROM app_config WHERE key='api_key'").fetchone()
        if row:
            return row[0]
        key = secrets.token_hex(32)
        conn.execute("INSERT INTO app_config (key, value) VALUES ('api_key', ?)", (key,))
        conn.commit()
        return key


def run_api(api_key: str):
    flask_app.config["DB_PATH"] = DB_PATH
    flask_app.config["API_KEY"] = api_key
    ensure_incident_schema(DB_PATH)
    init_extra_tables(DB_PATH)
    init_threat_table(DB_PATH)
    init_sandbox_tables(DB_PATH)
    print(f"[*] API starting. Pointing to: {DB_PATH}")
    flask_app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    api_key = _load_or_create_api_key(DB_PATH)

    threading.Thread(target=engine_listener, daemon=True).start()
    threading.Thread(target=run_api, args=(api_key,), daemon=True).start()
    print("[*] Launching SOC Dashboard...")

    app = QApplication(sys.argv)

    login = LoginWindow(DB_PATH)
    window = None

    def on_login(username, role):
        global window
        window = SOCDashboard(username=username, role=role, db_path=DB_PATH, api_key=api_key)
        window.show()

    login.login_successful.connect(on_login)
    login.show()
    sys.exit(app.exec())
