from flask import Flask, jsonify, request
import sqlite3
from functools import wraps

app = Flask(__name__)


def _require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = app.config.get("API_KEY")
        if key:
            provided = request.headers.get("X-API-Key", "")
            if provided != key:
                return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def get_db_connection():
    db_path = app.config.get("DB_PATH", "incidents.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_extra_tables(db_path):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS blocklist
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             ip TEXT UNIQUE,
             reason TEXT,
             blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS quarantine
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             incident_id INTEGER,
             ip TEXT,
             event_type TEXT,
             quarantined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
             notes TEXT)""")


@app.route("/incidents", methods=["GET"])
def get_incidents():
    try:
        conn = get_db_connection()
        limit = request.args.get("limit", 50, type=int)
        rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        print(f"[API ERROR] {e}")
        return jsonify([])


@app.route("/incidents/<int:incident_id>/status", methods=["PATCH"])
@_require_api_key
def update_status(incident_id):
    try:
        new_status = request.get_json().get("status", "Logged")
        db_path = app.config.get("DB_PATH", "incidents.db")
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (new_status, incident_id))
        return jsonify({"success": True})
    except Exception as e:
        print(f"[API ERROR] {e}")
        return jsonify({"success": False}), 500


@app.route("/blocklist", methods=["GET"])
def get_blocklist():
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM blocklist ORDER BY blocked_at DESC").fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        print(f"[API ERROR] {e}")
        return jsonify([])


@app.route("/blocklist/<ip>", methods=["POST"])
@_require_api_key
def block_ip(ip):
    try:
        reason = request.get_json(silent=True) or {}
        reason = reason.get("reason", "Manually blocked")
        db_path = app.config.get("DB_PATH", "incidents.db")
        with sqlite3.connect(db_path) as conn:
            conn.execute("INSERT OR IGNORE INTO blocklist (ip, reason) VALUES (?, ?)", (ip, reason))
            conn.execute("UPDATE incidents SET status = ? WHERE source_ip = ?", ("Blocked", ip))
        print(f"[BLOCK] {ip} blocked")
        return jsonify({"success": True})
    except Exception as e:
        print(f"[API ERROR] {e}")
        return jsonify({"success": False}), 500


@app.route("/blocklist/<ip>", methods=["DELETE"])
@_require_api_key
def unblock_ip(ip):
    try:
        db_path = app.config.get("DB_PATH", "incidents.db")
        with sqlite3.connect(db_path) as conn:
            conn.execute("DELETE FROM blocklist WHERE ip = ?", (ip,))
        print(f"[UNBLOCK] {ip} unblocked")
        return jsonify({"success": True})
    except Exception as e:
        print(f"[API ERROR] {e}")
        return jsonify({"success": False}), 500


@app.route("/quarantine/<int:incident_id>", methods=["POST"])
@_require_api_key
def quarantine_incident(incident_id):
    try:
        db_path = app.config.get("DB_PATH", "incidents.db")
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if row:
                conn.execute("""INSERT INTO quarantine (incident_id, ip, event_type, notes)
                    VALUES (?, ?, ?, ?)""", (incident_id, row["source_ip"], row["event_type"], "Quarantined via GUI"))
                conn.execute("UPDATE incidents SET status = ? WHERE id = ?", ("Quarantined", incident_id))
        return jsonify({"success": True})
    except Exception as e:
        print(f"[API ERROR] {e}")
        return jsonify({"success": False}), 500


@app.route("/quarantine", methods=["GET"])
def get_quarantine():
    try:
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM quarantine ORDER BY quarantined_at DESC").fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        print(f"[API ERROR] {e}")
        return jsonify([])


if __name__ == "__main__":
    app.run(port=5000)
