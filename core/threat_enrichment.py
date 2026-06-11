"""
Threat enrichment layer — external API lookups per attack type.

Mirrors the VT pattern exactly:
  - sync cache check (zero latency in the hot path)
  - async live API call that patches the incident row when it arrives
  - every result cached in SQLite to avoid repeat API hits

APIs used (all free-tier friendly):
  Shodan          → IP info, open ports, known vulns, org      (Port Scan / Recon)
  GreyNoise       → mass-internet scanner vs targeted attacker  (Bruteforce / DDoS / Port Scan)
  URLScan.io      → URL sandbox, malicious verdict + screenshot (C2 / Web attacks)
  VirusTotal URL  → VT verdict for URLs/domains in logs         (C2 / DNS Tunneling)

Environment variables:
  SHODAN_API_KEY      — shodan.io free key
  GREYNOISE_API_KEY   — greynoise.io (Community API is keyless for basic lookups)
  URLSCAN_API_KEY     — urlscan.io free key
  VT_API_KEY          — already used by core/virustotal.py, reused here for URL/domain lookups
"""

import os
import re
import sqlite3
import threading
import time
from urllib.parse import urlparse

import requests

SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY", "").strip()
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "").strip()
URLSCAN_API_KEY   = os.getenv("URLSCAN_API_KEY", "").strip()
VT_API_KEY        = os.getenv("VT_API_KEY", "").strip()

_CACHE_HOURS = 24

# ── DB setup ──────────────────────────────────────────────────────────────────

def init_enrichment_tables(db_path: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS shodan_cache (
                ip           TEXT PRIMARY KEY,
                open_ports   TEXT DEFAULT '',
                vulns        TEXT DEFAULT '',
                org          TEXT DEFAULT '',
                country      TEXT DEFAULT '',
                score        INTEGER DEFAULT 0,
                raw          TEXT DEFAULT '',
                checked_at   DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS greynoise_cache (
                ip              TEXT PRIMARY KEY,
                noise           INTEGER DEFAULT 0,
                riot            INTEGER DEFAULT 0,
                classification  TEXT DEFAULT 'unknown',
                name            TEXT DEFAULT '',
                link            TEXT DEFAULT '',
                score           INTEGER DEFAULT 0,
                checked_at      DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS urlscan_cache (
                url             TEXT PRIMARY KEY,
                verdict         TEXT DEFAULT 'unknown',
                malicious       INTEGER DEFAULT 0,
                score           INTEGER DEFAULT 0,
                screenshot_url  TEXT DEFAULT '',
                report_url      TEXT DEFAULT '',
                checked_at      DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_url_cache (
                url_or_domain   TEXT PRIMARY KEY,
                malicious       INTEGER DEFAULT 0,
                suspicious      INTEGER DEFAULT 0,
                harmless        INTEGER DEFAULT 0,
                total           INTEGER DEFAULT 0,
                score           INTEGER DEFAULT 0,
                vt_link         TEXT DEFAULT '',
                checked_at      DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

# ── Generic cache helpers ─────────────────────────────────────────────────────

def _is_fresh(checked_at_str: str) -> bool:
    try:
        from datetime import datetime, timedelta
        checked = datetime.strptime(checked_at_str[:19], "%Y-%m-%d %H:%M:%S")
        return (datetime.utcnow() - checked) < timedelta(hours=_CACHE_HOURS)
    except Exception:
        return False


def _now_str() -> str:
    from datetime import datetime
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# ── Observable extraction ─────────────────────────────────────────────────────

_URL_RE    = re.compile(r'https?://[^\s\'"<>]+', re.I)
_DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)'
    r'+(?:com|net|org|io|ru|cn|cc|biz|info|xyz|top|tk|pw|club|online)\b',
    re.I
)
_PRIVATE_RE = re.compile(
    r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)'
)


def extract_urls(log: str) -> list:
    return list(dict.fromkeys(_URL_RE.findall(log)))[:4]


def extract_domains(log: str) -> list:
    urls  = extract_urls(log)
    hosts = [urlparse(u).hostname or "" for u in urls]
    # also naked domain matches
    hosts += _DOMAIN_RE.findall(log)
    return list(dict.fromkeys(h.lower() for h in hosts if h))[:4]


def _is_private(ip: str) -> bool:
    return bool(_PRIVATE_RE.match(ip))

# ══════════════════════════════════════════════════════════════════════════════
#  SHODAN — IP intelligence (Port Scan / Recon)
# ══════════════════════════════════════════════════════════════════════════════

def _shodan_score(data: dict) -> int:
    """Convert a Shodan result into a 0-100 threat score."""
    score = 0
    ports = data.get("open_ports", "")
    vulns = data.get("vulns", "")
    n_ports = len(ports.split(",")) if ports.strip() else 0
    n_vulns = len(vulns.split(",")) if vulns.strip() else 0

    if n_ports >= 20:   score += 30
    elif n_ports >= 10: score += 15
    elif n_ports >= 5:  score += 5

    if n_vulns >= 5:    score += 50
    elif n_vulns >= 2:  score += 30
    elif n_vulns >= 1:  score += 15

    return min(score, 100)


def _get_shodan_cached(db_path: str, ip: str) -> dict | None:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM shodan_cache WHERE ip=?", (ip,)).fetchone()
            if row and _is_fresh(row["checked_at"]):
                return dict(row)
    except Exception:
        pass
    return None


def _save_shodan(db_path: str, data: dict):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO shodan_cache
                    (ip, open_ports, vulns, org, country, score, raw, checked_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (data["ip"], data.get("open_ports",""), data.get("vulns",""),
                  data.get("org",""), data.get("country",""),
                  data.get("score",0), data.get("raw","")[:2000], _now_str()))
            conn.commit()
    except Exception:
        pass


def _live_shodan(ip: str) -> dict | None:
    if not SHODAN_API_KEY or _is_private(ip):
        return None
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
            timeout=10,
        )
        if r.status_code == 404:
            return {"ip": ip, "open_ports": "", "vulns": "", "org": "Not in Shodan",
                    "country": "", "score": 0, "raw": ""}
        if r.status_code != 200:
            return None
        d = r.json()
        ports = ",".join(str(p) for p in d.get("ports", []))
        vulns = ",".join(d.get("vulns", {}).keys())
        result = {
            "ip":         ip,
            "open_ports": ports,
            "vulns":      vulns,
            "org":        d.get("org", ""),
            "country":    d.get("country_name", ""),
            "raw":        str(d)[:2000],
        }
        result["score"] = _shodan_score(result)
        return result
    except Exception as exc:
        print(f"[SHODAN ERROR] {ip}: {exc}")
        return None


def check_shodan_sync(db_path: str, ip: str) -> dict | None:
    return _get_shodan_cached(db_path, ip)


def _shodan_live_and_patch(db_path: str, incident_id: int, ip: str):
    result = _live_shodan(ip)
    if not result:
        return
    _save_shodan(db_path, result)
    score = result["score"]
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE incidents SET shodan_score=?, shodan_ports=?, shodan_vulns=?,"
                " enrich_summary=enrich_summary||? WHERE id=?",
                (score, result["open_ports"], result["vulns"],
                 f" | Shodan: {result['org']} {result['open_ports'][:60]}", incident_id)
            )
            conn.commit()
        print(f"[SHODAN] incident {incident_id}: {ip} score={score}")
    except Exception as exc:
        print(f"[SHODAN UPDATE] {exc}")


def enrich_shodan_async(db_path: str, incident_id: int, ip: str):
    threading.Thread(target=_shodan_live_and_patch,
                     args=(db_path, incident_id, ip), daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  GREYNOISE — mass-scanner vs targeted attacker (Bruteforce / DDoS / Port Scan)
# ══════════════════════════════════════════════════════════════════════════════

def _greynoise_score(data: dict) -> int:
    classification = data.get("classification", "unknown")
    if classification == "malicious":   return 80
    if data.get("noise") and not data.get("riot"):
        return 35   # known scanner but not malicious
    if data.get("riot"):
        return 0    # known benign infrastructure (CDN, DNS, etc.)
    return 10


def _get_greynoise_cached(db_path: str, ip: str) -> dict | None:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM greynoise_cache WHERE ip=?", (ip,)).fetchone()
            if row and _is_fresh(row["checked_at"]):
                return dict(row)
    except Exception:
        pass
    return None


def _save_greynoise(db_path: str, data: dict):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO greynoise_cache
                    (ip, noise, riot, classification, name, link, score, checked_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (data["ip"], int(data.get("noise",0)), int(data.get("riot",0)),
                  data.get("classification","unknown"), data.get("name",""),
                  data.get("link",""), data.get("score",0), _now_str()))
            conn.commit()
    except Exception:
        pass


def _live_greynoise(ip: str) -> dict | None:
    if _is_private(ip):
        return None
    # Community API — no key needed for basic context
    headers = {}
    if GREYNOISE_API_KEY:
        headers["key"] = GREYNOISE_API_KEY
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers=headers,
            timeout=8,
        )
        if r.status_code == 404:
            return {"ip": ip, "noise": 0, "riot": 0,
                    "classification": "unknown", "name": "", "link": "", "score": 10}
        if r.status_code != 200:
            return None
        d = r.json()
        result = {
            "ip":             ip,
            "noise":          int(d.get("noise", False)),
            "riot":           int(d.get("riot", False)),
            "classification": d.get("classification", "unknown"),
            "name":           d.get("name", ""),
            "link":           d.get("link", ""),
        }
        result["score"] = _greynoise_score(result)
        return result
    except Exception as exc:
        print(f"[GREYNOISE ERROR] {ip}: {exc}")
        return None


def check_greynoise_sync(db_path: str, ip: str) -> dict | None:
    return _get_greynoise_cached(db_path, ip)


def _greynoise_live_and_patch(db_path: str, incident_id: int, ip: str):
    result = _live_greynoise(ip)
    if not result:
        return
    _save_greynoise(db_path, result)
    score = result["score"]
    label = result["classification"].upper()
    noise_flag = " [MASS SCANNER]" if result.get("noise") else ""
    riot_flag  = " [BENIGN INFRA]" if result.get("riot") else ""
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE incidents SET greynoise_score=?, greynoise_classification=?,"
                " enrich_summary=enrich_summary||? WHERE id=?",
                (score, label,
                 f" | GreyNoise: {label}{noise_flag}{riot_flag}", incident_id)
            )
            conn.commit()
        print(f"[GREYNOISE] incident {incident_id}: {ip} {label} score={score}")
    except Exception as exc:
        print(f"[GREYNOISE UPDATE] {exc}")


def enrich_greynoise_async(db_path: str, incident_id: int, ip: str):
    threading.Thread(target=_greynoise_live_and_patch,
                     args=(db_path, incident_id, ip), daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  URLSCAN.IO — URL sandbox (C2 / Web Attacks)
# ══════════════════════════════════════════════════════════════════════════════

def _get_urlscan_cached(db_path: str, url: str) -> dict | None:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM urlscan_cache WHERE url=?", (url,)).fetchone()
            if row and _is_fresh(row["checked_at"]):
                return dict(row)
    except Exception:
        pass
    return None


def _save_urlscan(db_path: str, data: dict):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO urlscan_cache
                    (url, verdict, malicious, score, screenshot_url, report_url, checked_at)
                VALUES (?,?,?,?,?,?,?)
            """, (data["url"], data.get("verdict","unknown"),
                  int(data.get("malicious",0)), data.get("score",0),
                  data.get("screenshot_url",""), data.get("report_url",""), _now_str()))
            conn.commit()
    except Exception:
        pass


def _live_urlscan(url: str) -> dict | None:
    if not URLSCAN_API_KEY:
        return None
    try:
        # Submit
        sub = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"},
            json={"url": url, "visibility": "private"},
            timeout=10,
        )
        if sub.status_code not in (200, 201):
            return None
        scan_uuid = sub.json().get("uuid")
        if not scan_uuid:
            return None

        # Poll for result (up to 60s)
        result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
        for _ in range(12):
            time.sleep(5)
            res = requests.get(result_url, timeout=10)
            if res.status_code == 200:
                d = res.json()
                verdicts = d.get("verdicts", {}).get("overall", {})
                malicious = int(verdicts.get("malicious", False))
                score_raw = int(verdicts.get("score", 0))
                return {
                    "url":            url,
                    "verdict":        "malicious" if malicious else "clean",
                    "malicious":      malicious,
                    "score":          min(score_raw, 100),
                    "screenshot_url": d.get("task", {}).get("screenshotURL", ""),
                    "report_url":     f"https://urlscan.io/result/{scan_uuid}/",
                }
        return None
    except Exception as exc:
        print(f"[URLSCAN ERROR] {url[:60]}: {exc}")
        return None


def check_urlscan_sync(db_path: str, url: str) -> dict | None:
    return _get_urlscan_cached(db_path, url)


def _urlscan_live_and_patch(db_path: str, incident_id: int, urls: list):
    worst, worst_score = None, -1
    for url in urls[:2]:   # max 2 URLs per incident to stay under rate limit
        result = _live_urlscan(url)
        if result:
            _save_urlscan(db_path, result)
            if result["score"] > worst_score:
                worst_score, worst = result["score"], result
    if not worst:
        return
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE incidents SET urlscan_score=?, urlscan_verdict=?,"
                " urlscan_link=?, enrich_summary=enrich_summary||? WHERE id=?",
                (worst_score, worst["verdict"], worst["report_url"],
                 f" | URLScan: {worst['verdict'].upper()} ({worst_score})", incident_id)
            )
            conn.commit()
        print(f"[URLSCAN] incident {incident_id}: {worst['verdict']} score={worst_score}")
    except Exception as exc:
        print(f"[URLSCAN UPDATE] {exc}")


def enrich_urlscan_async(db_path: str, incident_id: int, urls: list):
    if not urls:
        return
    threading.Thread(target=_urlscan_live_and_patch,
                     args=(db_path, incident_id, urls), daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  VIRUSTOTAL URL / DOMAIN — (C2 / DNS Tunneling)
# ══════════════════════════════════════════════════════════════════════════════

_vt_url_lock   = threading.Lock()
_last_vt_url_call = 0.0
_VT_URL_INTERVAL  = 16.0


def _get_vt_url_cached(db_path: str, target: str) -> dict | None:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM vt_url_cache WHERE url_or_domain=?", (target,)
            ).fetchone()
            if row and _is_fresh(row["checked_at"]):
                return dict(row)
    except Exception:
        pass
    return None


def _save_vt_url(db_path: str, target: str, data: dict):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO vt_url_cache
                    (url_or_domain, malicious, suspicious, harmless, total, score, vt_link, checked_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (target, data.get("malicious",0), data.get("suspicious",0),
                  data.get("harmless",0), data.get("total",0), data.get("score",0),
                  data.get("vt_link",""), _now_str()))
            conn.commit()
    except Exception:
        pass


def _vt_url_score(malicious: int, total: int) -> int:
    if total == 0: return 0
    ratio = malicious / total
    if ratio >= 0.5: return 95
    if ratio >= 0.25: return 75
    if ratio >= 0.1: return 55
    if malicious > 0: return 35
    return 0


def _live_vt_url(target: str, is_url: bool) -> dict | None:
    global _last_vt_url_call
    if not VT_API_KEY:
        return None
    with _vt_url_lock:
        wait = _VT_URL_INTERVAL - (time.time() - _last_vt_url_call)
        if wait > 0:
            time.sleep(wait)
        _last_vt_url_call = time.time()
    try:
        import base64
        if is_url:
            encoded = base64.urlsafe_b64encode(target.encode()).rstrip(b"=").decode()
            endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
        r = requests.get(endpoint, headers={"x-apikey": VT_API_KEY}, timeout=12)
        if r.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "harmless": 0,
                    "total": 0, "score": 0, "vt_link": ""}
        if r.status_code != 200:
            return None
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total     = sum(stats.values())
        score     = _vt_url_score(malicious, total)
        vt_path   = "urls" if is_url else "domain"
        return {
            "malicious":  malicious,
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "total":      total,
            "score":      score,
            "vt_link":    f"https://www.virustotal.com/gui/{vt_path}/{target}",
        }
    except Exception as exc:
        print(f"[VT URL ERROR] {target[:60]}: {exc}")
        return None


def check_vt_url_sync(db_path: str, target: str) -> dict | None:
    return _get_vt_url_cached(db_path, target)


def _vt_url_live_and_patch(db_path: str, incident_id: int, targets: list):
    worst, worst_score = None, -1
    for target, is_url in targets[:3]:
        cached = _get_vt_url_cached(db_path, target)
        result = cached or _live_vt_url(target, is_url)
        if result:
            if not cached:
                _save_vt_url(db_path, target, result)
            if result.get("score", 0) > worst_score:
                worst_score, worst = result["score"], result
    if not worst or worst_score == 0:
        return
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE incidents SET vt_url_score=?, vt_url_link=?,"
                " enrich_summary=enrich_summary||? WHERE id=?",
                (worst_score, worst.get("vt_link",""),
                 f" | VT URL: {worst_score}/100", incident_id)
            )
            conn.commit()
        print(f"[VT URL] incident {incident_id}: score={worst_score}")
    except Exception as exc:
        print(f"[VT URL UPDATE] {exc}")


def enrich_vt_url_async(db_path: str, incident_id: int, targets: list):
    """targets: list of (url_or_domain_str, is_url_bool)"""
    if not targets:
        return
    threading.Thread(target=_vt_url_live_and_patch,
                     args=(db_path, incident_id, targets), daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  DISPATCHER — routes enrichment by event type
# ══════════════════════════════════════════════════════════════════════════════

_SHODAN_EVENTS      = {"port scan", "reconnaissance"}
_GREYNOISE_EVENTS   = {"port scan", "bruteforce", "ddos", "anomaly detected",
                       "behavioral threat"}
_URLSCAN_EVENTS     = {"c2 communication", "sql injection", "xss",
                       "command injection", "path traversal", "malware",
                       "data exfiltration"}
_VT_URL_EVENTS      = {"c2 communication", "dns tunneling", "malware",
                       "data exfiltration"}


def enrich_incident_async(
    db_path: str,
    incident_id: int,
    source_ip: str,
    event_type: str,
    raw_log: str,
):
    """
    Dispatch the right enrichment APIs for this event type.
    All calls are non-blocking — each spawns its own daemon thread.
    """
    et = event_type.lower()

    if et in _SHODAN_EVENTS:
        enrich_shodan_async(db_path, incident_id, source_ip)

    if et in _GREYNOISE_EVENTS:
        enrich_greynoise_async(db_path, incident_id, source_ip)

    if et in _URLSCAN_EVENTS:
        urls = extract_urls(raw_log)
        if urls:
            enrich_urlscan_async(db_path, incident_id, urls)

    if et in _VT_URL_EVENTS:
        targets = [(u, True) for u in extract_urls(raw_log)]
        targets += [(d, False) for d in extract_domains(raw_log)
                    if not any(d in u for u, _ in targets)]
        if targets:
            enrich_vt_url_async(db_path, incident_id, targets)
