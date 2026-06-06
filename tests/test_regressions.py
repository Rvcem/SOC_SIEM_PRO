import os
import sqlite3
import tempfile
import unittest

from backend.api import app, init_extra_tables
from core.parser import LogParser
from responder import init_responder_tables


def _exec_db(db_path, statements):
    conn = sqlite3.connect(db_path)
    try:
        for statement, params in statements:
            conn.execute(statement, params)
        conn.commit()
    finally:
        conn.close()


def _fetchone(db_path, statement, params=()):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(statement, params).fetchone()
    finally:
        conn.close()


def _columns(db_path, table):
    conn = sqlite3.connect(db_path)
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


class ParserTests(unittest.TestCase):
    def test_parse_syslog_returns_severity(self):
        parsed = LogParser().parse_syslog(
            "Failed password for invalid user root from 203.0.113.5 port 22"
        )
        self.assertEqual(parsed, ("203.0.113.5", "Bruteforce", "HIGH", "Auth"))


class BlocklistSchemaTests(unittest.TestCase):
    def test_backend_schema_uses_added_at(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "incidents.db")
            init_extra_tables(db_path)
            columns = _columns(db_path, "blocklist")
            self.assertIn("added_at", columns)
            self.assertNotIn("blocked_at", columns)

    def test_responder_migrates_legacy_blocked_at(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "incidents.db")
            _exec_db(db_path, [
                (
                    "CREATE TABLE blocklist (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "ip TEXT UNIQUE, reason TEXT, blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
                    (),
                ),
                ("INSERT INTO blocklist (ip, reason) VALUES (?, ?)", ("203.0.113.5", "legacy")),
            ])
            init_responder_tables(db_path)
            row = _fetchone(db_path, "SELECT added_at FROM blocklist WHERE ip=?", ("203.0.113.5",))
            self.assertIsNotNone(row[0])


class ApiAuthTests(unittest.TestCase):
    def test_incidents_requires_api_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "incidents.db")
            _exec_db(db_path, [
                (
                    "CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, source_ip TEXT, "
                    "event_type TEXT, severity TEXT, category TEXT, status TEXT)",
                    (),
                )
            ])
            app.config["DB_PATH"] = db_path
            app.config["API_KEY"] = "secret"
            client = app.test_client()

            self.assertEqual(client.get("/incidents").status_code, 401)
            self.assertEqual(client.get("/incidents", headers={"X-API-Key": "secret"}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
