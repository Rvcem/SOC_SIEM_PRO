import os
import threading
import time

import requests


CUCKOO_URL = os.getenv("CUCKOO_URL", "").rstrip("/")
CUCKOO_API_KEY = os.getenv("CUCKOO_API_KEY", "")
LITTERBOX_URL = os.getenv("LITTERBOX_URL", "").rstrip("/")
LITTERBOX_API_KEY = os.getenv("LITTERBOX_API_KEY", "")


def init_sandbox_tables(db_path: str):
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS sandbox_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT,
            observable TEXT,
            source_ip TEXT,
            status TEXT,
            result TEXT,
            submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.commit()
    finally:
        conn.close()


def _log_job(db_path: str, provider: str, observable: str, source_ip: str, status: str, result: str = ""):
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO sandbox_jobs (provider, observable, source_ip, status, result) VALUES (?, ?, ?, ?, ?)",
            (provider, observable, source_ip, status, result[:1000]),
        )
        conn.commit()
    finally:
        conn.close()


def submit_observable_async(db_path: str, observable: str, source_ip: str):
    if not observable:
        return
    threading.Thread(target=_submit_observable, args=(db_path, observable, source_ip), daemon=True).start()


def _submit_observable(db_path: str, observable: str, source_ip: str):
    submitted = False
    if CUCKOO_URL:
        submitted = True
        try:
            headers = {"Authorization": f"Bearer {CUCKOO_API_KEY}"} if CUCKOO_API_KEY else {}
            r = requests.post(f"{CUCKOO_URL}/tasks/create/url", data={"url": observable}, headers=headers, timeout=8)
            _log_job(db_path, "cuckoo", observable, source_ip, f"HTTP {r.status_code}", r.text)
        except Exception as exc:
            _log_job(db_path, "cuckoo", observable, source_ip, "error", str(exc))
    if LITTERBOX_URL:
        submitted = True
        try:
            headers = {"Authorization": f"Bearer {LITTERBOX_API_KEY}"} if LITTERBOX_API_KEY else {}
            r = requests.post(f"{LITTERBOX_URL}/submit", json={"observable": observable}, headers=headers, timeout=8)
            _log_job(db_path, "litterbox", observable, source_ip, f"HTTP {r.status_code}", r.text)
        except Exception as exc:
            _log_job(db_path, "litterbox", observable, source_ip, "error", str(exc))
    if not submitted:
        _log_job(db_path, "none", observable, source_ip, "not_configured", "Set CUCKOO_URL or LITTERBOX_URL")


def extract_observables(raw_log: str) -> list[str]:
    import re

    observables = re.findall(r"https?://[^\s'\"<>]+", raw_log)
    observables.extend(re.findall(r"\b[a-fA-F0-9]{32,64}\b", raw_log))
    return list(dict.fromkeys(observables))[:5]
