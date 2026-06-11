import socket
import sqlite3
import time
from collections import defaultdict

# ── Load environment variables from .env file ─────────────────────────────
from dotenv import load_dotenv
load_dotenv()

from core.behavioral import analyze_behavior
from core.detector import check_anomaly, detect_event, extract_ip
from core.ai_analyzer import analyze_log
from core.ollama_reporter import generate_report_async, init_reports_table
from core.schema import ensure_incident_schema
from core.threat_enrichment import enrich_incident_async
from core.virustotal import scan_log_async, scan_log_sync
from responder import block_ip, init_responder_tables
from sandbox_integrations import extract_observables, init_sandbox_tables, submit_observable_async

DEDUP_WINDOW     = 30
ANOMALY_THRESHOLD = 2.5

_dedup_cache     = {}
_ip_event_counts = defaultdict(int)
_ip_event_window = defaultdict(float)


def _is_duplicate(ip, etype):
    key = (ip, etype)
    now = time.time()
    if key in _dedup_cache and now - _dedup_cache[key] < DEDUP_WINDOW:
        return True
    _dedup_cache[key] = now
    return False


def start_listener(host="0.0.0.0", port=5555):
    print("--- ENGINE STARTING ---")
    ensure_incident_schema("incidents.db")
    init_responder_tables("incidents.db")
    init_sandbox_tables("incidents.db")
    init_reports_table("incidents.db")

    conn   = sqlite3.connect("incidents.db", check_same_thread=False)
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
            raw_log = data.decode("utf-8", errors="ignore")

            # ── IP extraction ─────────────────────────────────────────────────
            sip = extract_ip(raw_log)
            if sip == "unknown":
                sip = addr[0]

            # ── Signature-based classification ────────────────────────────────
            etype, severity, category = detect_event(raw_log)

            # ── Deduplication ─────────────────────────────────────────────────
            if _is_duplicate(sip, etype):
                continue

            # ── Event-rate anomaly (z-score) ──────────────────────────────────
            now = time.time()
            if now - _ip_event_window[sip] > 60:
                _ip_event_counts[sip]  = 0
                _ip_event_window[sip]  = now
            _ip_event_counts[sip] += 1

            anomaly_score = check_anomaly(sip, _ip_event_counts[sip], etype, severity)
            if anomaly_score > ANOMALY_THRESHOLD:
                etype    = "Anomaly Detected"
                severity = "CRITICAL"
                category = "ML Detection"

            # ── Behavioral analytics (in-memory, synchronous) ─────────────────
            behavior = analyze_behavior(raw_log, sip, etype, severity)
            behavior_score  = behavior["behavior_score"]
            behavior_alerts = behavior["alerts"]

            # Escalate classification if behavioral engine fires strongly
            if behavior_score >= 40 and etype == "System Event":
                etype    = "Behavioral Threat"
                severity = "HIGH"
                category = "Behavioral"

            # ── VT cache check (synchronous, no API call) ─────────────────────
            vt_cached = scan_log_sync("incidents.db", raw_log)
            vt_score  = 0
            vt_hash   = ""
            vt_link   = ""
            if vt_cached:
                from core.virustotal import vt_threat_score
                vt_score = vt_threat_score(vt_cached)
                vt_hash  = vt_cached.get("hash", "")
                vt_link  = vt_cached.get("vt_link", "")
                if vt_score >= 70:
                    etype    = "Malware"
                    severity = "CRITICAL"
                    category = "Endpoint"

            # ── AI / heuristic scoring ────────────────────────────────────────
            ai = analyze_log(
                raw_log, sip, etype, severity,
                anomaly_score=anomaly_score,
                vt_score=vt_score,
                behavior_score=behavior_score,
                behavior_alerts=behavior_alerts,
            )

            # ── Auto-block decision ───────────────────────────────────────────
            status = "Logged"
            if ai.get("auto_block"):
                block_ip(
                    "incidents.db", sip,
                    f"Auto-block: threat score {ai['threat_score']}"
                )
                status = "Blocked"

            # ── Persist incident ──────────────────────────────────────────────
            cursor.execute(
                """INSERT INTO incidents
                   (source_ip, event_type, severity, category, status, raw_log,
                    anomaly_score, threat_score, ai_score, ai_summary,
                    vt_score, vt_hash, vt_link,
                    behavior_score, behavior_alerts)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sip, etype, severity, category, status, raw_log,
                    float(anomaly_score), ai["threat_score"], ai["ai_score"], ai["ai_summary"],
                    vt_score, vt_hash, vt_link,
                    behavior_score, "; ".join(behavior_alerts),
                ),
            )
            conn.commit()
            incident_id = cursor.lastrowid

            # ── Async VT live lookup (updates row when result arrives) ─────────
            scan_log_async("incidents.db", incident_id, raw_log)

            # ── Threat enrichment (Shodan/GreyNoise/URLScan/VT-URL) ───────────
            enrich_incident_async("incidents.db", incident_id, sip, etype, raw_log)

            # ── Ollama deep-analysis report (deepseek-coder-v2:16b) ───────────
            generate_report_async(
                "incidents.db", incident_id, raw_log,
                sip, etype, severity, ai["threat_score"],
                behavior_alerts=behavior_alerts,
                vt_score=vt_score,
                vt_hash=vt_hash,
            )

            # ── Sandbox observable extraction ─────────────────────────────────
            for observable in extract_observables(raw_log):
                submit_observable_async("incidents.db", observable, sip)

            print(
                f"[+] {etype} ({severity}) from {sip} | "
                f"threat={ai['threat_score']} vt={vt_score} beh={behavior_score}"
            )

        except Exception as e:
            print(f"[ENGINE ERROR] {e}")
