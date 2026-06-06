import sqlite3
import os

DB = "incidents.db"

def init():
    # Force the creation of the correct schema
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS incidents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT,
        event_type TEXT,
        severity TEXT,
        category TEXT,
        status TEXT
    )''')
    conn.commit()
    conn.close()
    print("[*] Database Initialized with 'source_ip' column.")