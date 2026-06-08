"""Ollama-powered incident report generator.

For every incident the engine processes, this module:
  1. Builds a rich prompt containing the raw log, detected event type, severity,
     behavioral alerts, and VT result (if any).
  2. Sends it to the deepseek-coder-v2:16b model running locally via Ollama.
  3. Parses the model's JSON response into a structured report.
  4. Stores the report in the 'reports' table and links it to the incident row.

The call is always non-blocking — reports arrive in the background and are
written to the DB when ready.  The SIEM GUI can poll the reports table to
display them alongside incident details.

Environment variables:
  OLLAMA_URL          — default http://127.0.0.1:11434
  SOC_REPORT_MODEL    — default deepseek-coder-v2:16b
  SOC_ENABLE_REPORTS  — set to 0/false/no to disable
"""

import json
import os
import re
import sqlite3
import threading

import requests

OLLAMA_URL    = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
REPORT_MODEL  = os.getenv("SOC_REPORT_MODEL", "deepseek-coder-v2:16b")
ENABLE_REPORTS = os.getenv("SOC_ENABLE_REPORTS", "1").lower() not in ("0", "false", "no")

# ── DB setup ──────────────────────────────────────────────────────────────────

def init_reports_table(db_path: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id     INTEGER NOT NULL,
                model           TEXT,
                attack_summary  TEXT,
                mitre_tactics   TEXT,
                mitre_techniques TEXT,
                affected_assets TEXT,
                iocs            TEXT,
                recommended_actions TEXT,
                confidence      INTEGER DEFAULT 0,
                raw_response    TEXT,
                generated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_prompt(
    raw_log: str,
    source_ip: str,
    event_type: str,
    severity: str,
    threat_score: int,
    behavior_alerts: list,
    vt_score: int,
    vt_hash: str,
) -> str:
    behavior_section = (
        "Behavioral alerts:\n" + "\n".join(f"  - {a}" for a in behavior_alerts)
        if behavior_alerts else "No behavioral alerts."
    )
    vt_section = (
        f"VirusTotal hash: {vt_hash}  |  VT threat score: {vt_score}/100"
        if vt_score > 0 else "No VirusTotal results."
    )

    return f"""You are a senior SOC analyst generating a structured incident report.
Analyze the security event below and respond with ONLY valid JSON — no markdown, no explanation outside the JSON.

=== INCIDENT DATA ===
Source IP    : {source_ip}
Event Type   : {event_type}
Severity     : {severity}
Threat Score : {threat_score}/100
{behavior_section}
{vt_section}

Raw Log:
{raw_log[:2000]}

=== REQUIRED JSON SCHEMA ===
{{
  "attack_summary":        "<2-3 sentence description of what this attack is doing and why it is dangerous>",
  "mitre_tactics":         ["<tactic name>", ...],
  "mitre_techniques":      ["<T1234 - Technique Name>", ...],
  "affected_assets":       ["<asset description>", ...],
  "iocs":                  ["<ip/hash/domain/url>", ...],
  "recommended_actions":   ["<concrete remediation step>", ...],
  "confidence":            <integer 0-100 representing your confidence in this classification>
}}

Respond with ONLY the JSON object above. Do not wrap it in markdown code blocks."""


# ── Response parser ───────────────────────────────────────────────────────────

def _parse_response(text: str) -> dict:
    # Strip markdown fences if model ignores instructions
    text = re.sub(r"```(?:json)?", "", text).strip().rstrip("`").strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try to extract the first {...} block
        m = re.search(r'\{[\s\S]+\}', text)
        if not m:
            return {}
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return {}

    def _list(key):
        val = data.get(key, [])
        if isinstance(val, list):
            return "; ".join(str(v) for v in val[:10])
        return str(val)[:500]

    return {
        "attack_summary":       str(data.get("attack_summary", ""))[:1000],
        "mitre_tactics":        _list("mitre_tactics"),
        "mitre_techniques":     _list("mitre_techniques"),
        "affected_assets":      _list("affected_assets"),
        "iocs":                 _list("iocs"),
        "recommended_actions":  _list("recommended_actions"),
        "confidence":           min(100, max(0, int(data.get("confidence", 0)))),
    }

# ── Ollama call ───────────────────────────────────────────────────────────────

def _call_ollama(prompt: str) -> str | None:
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": REPORT_MODEL, "prompt": prompt, "stream": False},
            timeout=120,
        )
        if r.status_code != 200:
            print(f"[REPORTER] Ollama HTTP {r.status_code}")
            return None
        return r.json().get("response", "")
    except Exception as exc:
        print(f"[REPORTER] Ollama unavailable: {exc}")
        return None

# ── DB write ──────────────────────────────────────────────────────────────────

def _save_report(db_path: str, incident_id: int, parsed: dict, raw_response: str):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT INTO reports
                    (incident_id, model, attack_summary, mitre_tactics, mitre_techniques,
                     affected_assets, iocs, recommended_actions, confidence, raw_response)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id,
                REPORT_MODEL,
                parsed.get("attack_summary", ""),
                parsed.get("mitre_tactics", ""),
                parsed.get("mitre_techniques", ""),
                parsed.get("affected_assets", ""),
                parsed.get("iocs", ""),
                parsed.get("recommended_actions", ""),
                parsed.get("confidence", 0),
                raw_response[:4000],
            ))
            conn.commit()
        print(f"[REPORTER] Report saved for incident {incident_id}")
    except Exception as exc:
        print(f"[REPORTER] DB write error: {exc}")

# ── Background worker ─────────────────────────────────────────────────────────

def _generate_report(
    db_path: str,
    incident_id: int,
    raw_log: str,
    source_ip: str,
    event_type: str,
    severity: str,
    threat_score: int,
    behavior_alerts: list,
    vt_score: int,
    vt_hash: str,
):
    prompt       = _build_prompt(raw_log, source_ip, event_type, severity,
                                  threat_score, behavior_alerts, vt_score, vt_hash)
    raw_response = _call_ollama(prompt)
    if not raw_response:
        return

    parsed = _parse_response(raw_response)
    if not parsed:
        print(f"[REPORTER] Could not parse model response for incident {incident_id}")
        return

    _save_report(db_path, incident_id, parsed, raw_response)


def generate_report_async(
    db_path: str,
    incident_id: int,
    raw_log: str,
    source_ip: str,
    event_type: str,
    severity: str,
    threat_score: int,
    behavior_alerts: list = None,
    vt_score: int = 0,
    vt_hash: str = "",
):
    """
    Fire-and-forget: generate an Ollama report for this incident in the background.
    Does nothing if SOC_ENABLE_REPORTS=0 or the event is LOW severity and score < 30
    (avoids flooding Ollama with benign events).
    """
    if not ENABLE_REPORTS:
        return

    # Skip trivial events to keep Ollama load reasonable
    if severity.upper() == "LOW" and threat_score < 30:
        return

    threading.Thread(
        target=_generate_report,
        args=(
            db_path, incident_id, raw_log, source_ip, event_type,
            severity, threat_score, behavior_alerts or [], vt_score, vt_hash,
        ),
        daemon=True,
    ).start()


# ── Query helpers ─────────────────────────────────────────────────────────────

def get_report(db_path: str, incident_id: int) -> dict | None:
    """Fetch the latest report for a given incident_id, or None."""
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM reports WHERE incident_id=? ORDER BY id DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def get_recent_reports(db_path: str, limit: int = 20) -> list:
    """Fetch the most recent reports with their incident context."""
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT r.*, i.source_ip, i.event_type, i.severity, i.threat_score
                FROM reports r
                JOIN incidents i ON r.incident_id = i.id
                ORDER BY r.id DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []
