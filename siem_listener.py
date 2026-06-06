import socket
import sqlite3
import re
import time
from collections import defaultdict
from core.detector import detect_event, check_anomaly, extract_ip
from core.ai_analyzer import analyze_log
from core.schema import ensure_incident_schema
from responder import block_ip, init_responder_tables
from sandbox_integrations import extract_observables, init_sandbox_tables, submit_observable_async

DEDUP_WINDOW = 30
ANOMALY_THRESHOLD = 2.5

_dedup_cache = {}
_ip_event_counts = defaultdict(int)
_ip_event_window = defaultdict(float)

def _is_duplicate(ip, etype):
    key = (ip, etype)
    now = time.time()
    if key in _dedup_cache and now - _dedup_cache[key] < DEDUP_WINDOW:
        return True
    _dedup_cache[key] = now
    return False

def start_listener(host='0.0.0.0', port=5555):
    print("--- ENGINE STARTING ---")
    ensure_incident_schema("incidents.db")
    init_responder_tables("incidents.db")
    init_sandbox_tables("incidents.db")
    conn = sqlite3.connect('incidents.db', check_same_thread=False)
    cursor = conn.cursor()
    conn.commit()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        print(f"[*] LISTENING ON PORT {port}")
    except Exception as e:
        print(f"[ERROR] Could not bind: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            raw_log = data.decode('utf-8', errors='ignore')

            sip = extract_ip(raw_log)
            if sip == "unknown":
                sip = addr[0]

            etype, severity, category = detect_event(raw_log)

            if _is_duplicate(sip, etype):
                continue

            now = time.time()
            if now - _ip_event_window[sip] > 60:
                _ip_event_counts[sip] = 0
                _ip_event_window[sip] = now
            _ip_event_counts[sip] += 1

            anomaly_score = check_anomaly(sip, _ip_event_counts[sip], etype, severity)
            if anomaly_score > ANOMALY_THRESHOLD:
                etype = "Anomaly Detected"
                severity = "CRITICAL"
                category = "ML Detection"

            ai = analyze_log(raw_log, sip, etype, severity, anomaly_score)
            status = "Logged"
            if ai.get("auto_block"):
                block_ip("incidents.db", sip, f"Auto-block: AI threat score {ai['threat_score']}")
                status = "Blocked"
            for observable in extract_observables(raw_log):
                submit_observable_async("incidents.db", observable, sip)

            cursor.execute(
                """INSERT INTO incidents
                   (source_ip, event_type, severity, category, status, raw_log,
                    anomaly_score, threat_score, ai_score, ai_summary)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (sip, etype, severity, category, status, raw_log,
                 float(anomaly_score), ai["threat_score"], ai["ai_score"], ai["ai_summary"])
            )
            conn.commit()
            print(f"[+] {etype} ({severity}) from {sip} | threat={ai['threat_score']}")
        except Exception as e:
            print(f"[ENGINE ERROR] {e}")
