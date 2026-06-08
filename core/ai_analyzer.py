import json
import os
import re
import threading
import time
from collections import Counter, defaultdict, deque
from datetime import datetime

import requests


OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")
ENABLE_OLLAMA = os.getenv("SOC_ENABLE_OLLAMA", "1").lower() not in ("0", "false", "no")
AUTO_BLOCK_SCORE = int(os.getenv("SOC_AUTO_BLOCK_SCORE", "90"))

_ip_history = defaultdict(lambda: deque(maxlen=80))
_global_events = deque(maxlen=500)
_ollama_cache = {}
_ollama_lock = threading.Lock()


def _clamp_score(score):
    return max(0, min(100, int(round(score))))


def _severity_points(severity: str) -> int:
    return {"LOW": 8, "MEDIUM": 25, "HIGH": 55, "CRITICAL": 78}.get(str(severity).upper(), 10)


def _extract_ports(log: str) -> list[int]:
    ports = []
    for token in re.findall(r"\b(?:port|ports?)\s+([0-9,\-\s]+)", log.lower()):
        for value in re.findall(r"\d+", token):
            try:
                ports.append(int(value))
            except ValueError:
                pass
    return ports


def heuristic_log_score(raw_log: str, ip: str, event_type: str, severity: str, now=None) -> dict:
    """Score a log using local behavioral signals; no network or model required."""
    now = now or time.time()
    log_lower = raw_log.lower()
    history = _ip_history[ip]
    recent = [entry for entry in history if now - entry["ts"] <= 300]
    last_minute = [entry for entry in history if now - entry["ts"] <= 60]
    global_recent = [entry for entry in _global_events if now - entry["ts"] <= 300]

    score = _severity_points(severity)
    reasons = []

    if len(last_minute) >= 8:
        score += 18
        reasons.append(f"{len(last_minute)} events from same IP in 60s")
    if len(recent) >= 20:
        score += 15
        reasons.append(f"{len(recent)} events from same IP in 5m")

    event_diversity = len({entry["event_type"] for entry in recent})
    if event_diversity >= 4:
        score += 12
        reasons.append(f"{event_diversity} different event types from same IP")

    ports = set(_extract_ports(raw_log))
    prior_ports = {port for entry in recent for port in entry.get("ports", [])}
    if len(ports | prior_ports) >= 8:
        score += 14
        reasons.append("wide port spread")

    noisy_terms = {
        "ransomware": 25, "trojan": 20, "malware": 20, "c2": 20,
        "syn flood": 18, "ddos": 18, "drop table": 18, "union select": 18,
        "powershell": 10, "mimikatz": 25, "credential": 12,
    }
    for term, points in noisy_terms.items():
        if term in log_lower:
            score += points
            reasons.append(term)

    hour = datetime.fromtimestamp(now).hour
    if hour < 6 and str(severity).upper() in ("HIGH", "CRITICAL"):
        score += 5
        reasons.append("high severity during low-activity hours")

    if global_recent:
        counts = Counter(entry["source_ip"] for entry in global_recent)
        if counts.get(ip, 0) > max(10, len(global_recent) * 0.25):
            score += 10
            reasons.append("dominates recent event volume")

    entry = {
        "ts": now,
        "source_ip": ip,
        "event_type": str(event_type).lower(),
        "severity": str(severity).upper(),
        "ports": list(ports),
    }
    history.append(entry)
    _global_events.append(entry)

    score = _clamp_score(score)
    return {
        "score": score,
        "summary": "; ".join(reasons[:5]) or f"{event_type} classified as {severity}",
        "auto_block": score >= AUTO_BLOCK_SCORE,
    }


def _parse_ollama_text(text: str) -> dict:
    try:
        data = json.loads(text)
        return {
            "score": _clamp_score(data.get("score", 0)),
            "summary": str(data.get("summary", "")).strip()[:400],
        }
    except Exception:
        match = re.search(r"\b([0-9]{1,3})\b", text)
        score = _clamp_score(int(match.group(1))) if match else 0
        return {"score": score, "summary": text.strip()[:400]}


def ollama_log_score(raw_log: str, event_type: str, severity: str) -> dict | None:
    if not ENABLE_OLLAMA:
        return None
    cache_key = (raw_log[:500], event_type, severity)
    with _ollama_lock:
        if cache_key in _ollama_cache:
            return dict(_ollama_cache[cache_key])
    prompt = (
        "You are a SOC analyst. Return only JSON with keys score and summary. "
        "score must be 0-100. Analyze this security log for maliciousness.\n"
        f"Event type: {event_type}\nSeverity: {severity}\nLog: {raw_log[:1500]}"
    )
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=8,
        )
        if response.status_code != 200:
            return None
        result = _parse_ollama_text(response.json().get("response", ""))
        with _ollama_lock:
            _ollama_cache[cache_key] = result
        return result
    except Exception as exc:
        print(f"[OLLAMA] unavailable: {exc}")
        return None


def analyze_log(
    raw_log: str,
    ip: str,
    event_type: str,
    severity: str,
    anomaly_score: float = 0,
    vt_score: int = 0,
    behavior_score: int = 0,
    behavior_alerts: list = None,
) -> dict:
    heuristic = heuristic_log_score(raw_log, ip, event_type, severity)
    ollama    = ollama_log_score(raw_log, event_type, severity)
    ai_score  = ollama["score"] if ollama else heuristic["score"]

    combined = max(heuristic["score"], ai_score)

    # Statistical anomaly escalation
    if anomaly_score > 2.5:
        combined = max(combined, 85)

    # VirusTotal escalation — malicious file is strong signal
    if vt_score >= 70:
        combined = max(combined, vt_score)
    elif vt_score > 0:
        combined = max(combined, combined + (vt_score // 4))

    # Behavioral analytics escalation
    if behavior_score > 0:
        combined = max(combined, combined + (behavior_score // 3))
    if behavior_score >= 40:
        combined = max(combined, 80)

    combined = _clamp_score(combined)

    # Build a rich summary
    base_summary = ollama["summary"] if ollama and ollama.get("summary") else heuristic["summary"]
    extra_parts = []
    if vt_score > 0:
        extra_parts.append(f"VT score: {vt_score}/100")
    if behavior_alerts:
        extra_parts.extend(behavior_alerts[:2])
    summary = "; ".join(filter(None, [base_summary] + extra_parts))[:600]

    return {
        "heuristic_score":  heuristic["score"],
        "ai_score":         ai_score,
        "vt_score":         vt_score,
        "behavior_score":   behavior_score,
        "threat_score":     combined,
        "ai_summary":       summary,
        "auto_block":       combined >= AUTO_BLOCK_SCORE or heuristic["auto_block"],
    }
