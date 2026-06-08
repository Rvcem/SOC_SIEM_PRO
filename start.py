import threading
import sys
import sqlite3
import os
import secrets

# ── Load environment variables from .env file ─────────────────────────────
from dotenv import load_dotenv
load_dotenv()

from PyQt6.QtWidgets import QApplication
from backend.api import app as flask_app, init_extra_tables
from gui.app import SOCDashboard
from core.schema import ensure_incident_schema
from core.ollama_reporter import init_reports_table
from login import LoginWindow
from threat_intel import init_threat_table
from responder import init_responder_tables
from sandbox_integrations import init_sandbox_tables
from siem_listener import start_listener


DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents.db")


def _load_or_create_api_key(db_path: str) -> str:
    """Persist a random API key in the DB so it survives restarts."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)")
        row = conn.execute("SELECT value FROM app_config WHERE key='api_key'").fetchone()
        if row:
            return row[0]
        key = secrets.token_hex(32)
        conn.execute("INSERT INTO app_config (key, value) VALUES ('api_key', ?)", (key,))
        conn.commit()
        return key


def run_api(api_key: str):
    flask_app.config["DB_PATH"] = DB_PATH
    flask_app.config["API_KEY"] = api_key
    ensure_incident_schema(DB_PATH)
    init_extra_tables(DB_PATH)
    init_threat_table(DB_PATH)
    init_sandbox_tables(DB_PATH)
    init_reports_table(DB_PATH)
    print(f"[*] API starting on http://127.0.0.1:5000")
    flask_app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    api_key = _load_or_create_api_key(DB_PATH)

    threading.Thread(target=start_listener, daemon=True).start()
    threading.Thread(target=run_api, args=(api_key,), daemon=True).start()
    print("[*] Launching SOC Dashboard...")

    app = QApplication(sys.argv)

    login = LoginWindow(DB_PATH)
    window = None

    def on_login(username, role):
        global window
        window = SOCDashboard(username=username, role=role, db_path=DB_PATH, api_key=api_key)
        window.show()

    login.login_successful.connect(on_login)
    login.show()
    sys.exit(app.exec())
