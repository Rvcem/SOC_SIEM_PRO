"""VirusTotal file-hash intelligence layer.

Workflow:
  1. Extract MD5 / SHA1 / SHA256 hashes and file paths from a raw log string.
  2. For file paths that exist locally, compute a SHA-256 hash.
  3. Query the VirusTotal v3 API for each candidate hash.
  4. Cache every result in the 'vt_cache' SQLite table (avoids duplicate API hits).
  5. Return the worst (highest threat) result found for a given log line.

Rate limiting: the free VT tier allows 4 lookups/minute.  A module-level lock
enforces a minimum 16-second gap between live API calls.  Cached results bypass
the rate limiter entirely.
"""

import hashlib
import os
import re
import sqlite3
import threading
import time

import requests

VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
_VT_MIN_INTERVAL = 16.0  # seconds between live API calls (free tier = 4/min)

_vt_lock = threading.Lock()
_last_vt_call = 0.0

# ── Regex patterns ────────────────────────────────────────────────────────────

_SHA256_RE = re.compile(r'\b([a-fA-F0-9]{64})\b')
_SHA1_RE   = re.compile(r'\b([a-fA-F0-9]{40})\b')
_MD5_RE    = re.compile(r'\b([a-fA-F0-9]{32})\b')

_FILE_PATH_RE = re.compile(
    r'(?:[A-Za-z]:\\[\w\\ .\-]+\.(?:exe|dll|bat|ps1|vbs|js|jar|zip|rar|7z|doc[xm]?|xls[xm]?|msi|scr|hta|cmd))'
    r'|(?:/(?:tmp|var|home|usr|opt|root|etc|dev/shm)/[\w/.\-]+\.(?:sh|py|pl|elf|bin|so|php|rb))',
    re.IGNORECASE,
)

# ── Hash extraction ───────────────────────────────────────────────────────────

def extract_hashes(log: str) -> list:
    """Return list of (hash_type, hash_value) found in *log*, most specific first."""
    seen = set()
    results = []

    for h in _SHA256_RE.findall(log):
        hv = h.lower()
        if hv not in seen:
            seen.add(hv)
            results.append(("sha256", hv))

    for h in _SHA1_RE.findall(log):
        hv = h.lower()
        if hv not in seen and not any(hv in sv for sv in seen):
            seen.add(hv)
            results.append(("sha1", hv))

    for h in _MD5_RE.findall(log):
        hv = h.lower()
        if hv not in seen and not any(hv in sv for sv in seen):
            seen.add(hv)
            results.append(("md5", hv))

    return results[:4]


def extract_file_paths(log: str) -> list:
    """Return list of file paths found in *log*."""
    return list(dict.fromkeys(_FILE_PATH_RE.findall(log)))[:5]


def hash_file(path: str):
    """SHA-256 hash a local file. Returns ('sha256', hex) or None."""
    try:
        if not os.path.isfile(path):
            return None
        if os.path.getsize(path) > 200 * 1024 * 1024:  # skip files > 200 MB
            return None
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return ("sha256", h.hexdigest())
    except Exception:
        return None

# ── SQLite cache ──────────────────────────────────────────────────────────────

def init_vt_table(db_path: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                hash        TEXT PRIMARY KEY,
                hash_type   TEXT,
                malicious   INTEGER DEFAULT 0,
                suspicious  INTEGER DEFAULT 0,
                harmless    INTEGER DEFAULT 0,
                total       INTEGER DEFAULT 0,
                file_names  TEXT DEFAULT '',
                vt_link     TEXT DEFAULT '',
                checked_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def _get_cached(db_path: str, hash_val: str):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM vt_cache WHERE hash = ?", (hash_val,)
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def _save_cached(db_path: str, data: dict):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO vt_cache
                    (hash, hash_type, malicious, suspicious, harmless, total, file_names, vt_link)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["hash"], data["hash_type"],
                data.get("malicious", 0), data.get("suspicious", 0),
                data.get("harmless", 0), data.get("total", 0),
                data.get("file_names", ""), data.get("vt_link", ""),
            ))
            conn.commit()
    except Exception:
        pass

# ── VirusTotal API ────────────────────────────────────────────────────────────

def _vt_get(hash_val: str):
    """Perform a rate-limited GET to the VT v3 files endpoint."""
    global _last_vt_call
    with _vt_lock:
        wait = _VT_MIN_INTERVAL - (time.time() - _last_vt_call)
        if wait > 0:
            time.sleep(wait)
        _last_vt_call = time.time()

    return requests.get(
        f"https://www.virustotal.com/api/v3/files/{hash_val}",
        headers={"x-apikey": VT_API_KEY},
        timeout=12,
    )


def check_hash_vt(db_path: str, hash_type: str, hash_val: str):
    """
    Look up *hash_val* on VirusTotal.
    Returns a result dict, or None if the API key is unset or the call fails.
    Cached results are returned instantly without an API call.
    """
    cached = _get_cached(db_path, hash_val)
    if cached:
        return cached

    if not VT_API_KEY:
        return None

    try:
        r = _vt_get(hash_val)

        if r.status_code == 404:
            result = {
                "hash": hash_val, "hash_type": hash_type,
                "malicious": 0, "suspicious": 0, "harmless": 0,
                "total": 0, "file_names": "Not found in VT", "vt_link": "",
            }
            _save_cached(db_path, result)
            return result

        if r.status_code != 200:
            print(f"[VT] HTTP {r.status_code} for {hash_val}")
            return None

        attrs  = r.json().get("data", {}).get("attributes", {})
        stats  = attrs.get("last_analysis_stats", {})
        names  = attrs.get("names", [])
        total  = sum(stats.values())

        result = {
            "hash":       hash_val,
            "hash_type":  hash_type,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "total":      total,
            "file_names": ", ".join(names[:4]),
            "vt_link":    f"https://www.virustotal.com/gui/file/{hash_val}",
        }
        _save_cached(db_path, result)
        return result

    except Exception as exc:
        print(f"[VT ERROR] {exc}")
        return None

# ── Threat score conversion ───────────────────────────────────────────────────

def vt_threat_score(vt_result: dict) -> int:
    """Convert a VT result dict to a 0-100 threat score."""
    if not vt_result or vt_result.get("total", 0) == 0:
        return 0
    total     = vt_result["total"]
    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    ratio = malicious / total
    if ratio >= 0.5:
        return 97
    elif ratio >= 0.25:
        return 85
    elif ratio >= 0.1:
        return 70
    elif malicious > 0:
        return 55
    elif suspicious > 0:
        return 35
    return 0

# ── High-level helpers ────────────────────────────────────────────────────────

def scan_log_sync(db_path: str, raw_log: str):
    """
    Extract hashes from *raw_log*, check VT cache for each
    (cache-only for speed — no live API call here).
    Returns the worst-scoring cached result, or None if nothing is cached.

    Note: file paths are NOT opened automatically from log content because
    the raw_log originates from untrusted UDP packets and could be attacker-crafted.
    """
    candidates = list(extract_hashes(raw_log))

    worst, worst_score = None, -1
    for hash_type, hash_val in candidates:
        cached = _get_cached(db_path, hash_val)
        if cached:
            s = vt_threat_score(cached)
            if s > worst_score:
                worst_score, worst = s, cached
    return worst


def _live_scan(db_path: str, incident_id: int, raw_log: str):
    """Background thread: perform live VT lookups and update the incident row.

    Only explicit hashes from the log are checked — local file paths are never
    opened because raw_log comes from untrusted UDP packets.
    """
    candidates = list(extract_hashes(raw_log))

    if not candidates:
        return

    worst, worst_score = None, -1
    for hash_type, hash_val in candidates:
        result = check_hash_vt(db_path, hash_type, hash_val)
        if result:
            s = vt_threat_score(result)
            if s > worst_score:
                worst_score, worst = s, result

    if worst and worst_score > 0:
        try:
            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    "UPDATE incidents SET vt_score=?, vt_hash=?, vt_link=? WHERE id=?",
                    (worst_score, worst["hash"], worst.get("vt_link", ""), incident_id),
                )
                # Escalate severity/threat_score if VT is damning
                if worst_score >= 70:
                    conn.execute(
                        "UPDATE incidents SET threat_score=MAX(threat_score,?), severity='CRITICAL' WHERE id=?",
                        (worst_score, incident_id),
                    )
                conn.commit()
            print(f"[VT] incident {incident_id}: {worst['hash'][:16]}… score={worst_score}")
        except Exception as exc:
            print(f"[VT UPDATE ERROR] {exc}")


def scan_log_async(db_path: str, incident_id: int, raw_log: str):
    """Fire-and-forget VT scan that updates the incident row when results arrive."""
    threading.Thread(
        target=_live_scan, args=(db_path, incident_id, raw_log), daemon=True
    ).start()
