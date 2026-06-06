import sqlite3


INCIDENT_COLUMNS = {
    "raw_log": "TEXT",
    "anomaly_score": "REAL DEFAULT 0",
    "threat_score": "INTEGER DEFAULT 0",
    "ai_score": "INTEGER DEFAULT 0",
    "ai_summary": "TEXT DEFAULT ''",
}


def ensure_incident_schema(db_path: str):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS incidents
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
             source_ip TEXT, event_type TEXT, severity TEXT,
             category TEXT, status TEXT)""")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
        for name, ddl in INCIDENT_COLUMNS.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE incidents ADD COLUMN {name} {ddl}")
        conn.commit()
    finally:
        conn.close()


def get_app_config(db_path: str, key: str, default=None):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)")
        row = conn.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
        return row[0] if row else default
    finally:
        conn.close()


def set_app_config(db_path: str, key: str, value):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("INSERT OR REPLACE INTO app_config (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
    finally:
        conn.close()
