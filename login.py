import sys
import sqlite3
import hashlib
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QFrame, QMessageBox, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QLinearGradient, QBrush, QPixmap, QPalette

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents.db")

# ── Styles ────────────────────────────────────────────────────────────────────

STYLE = """
QMainWindow, QWidget#bg {
    background-color: #05050f;
}
QFrame#card {
    background-color: rgba(16, 16, 40, 0.95);
    border: 1px solid #1e1e4a;
    border-radius: 18px;
}
QLabel#title {
    color: #00f2ff;
    font-family: 'Courier New';
    font-size: 26px;
    font-weight: bold;
    letter-spacing: 6px;
}
QLabel#subtitle {
    color: #4a4a8a;
    font-family: 'Courier New';
    font-size: 11px;
    letter-spacing: 3px;
}
QLabel#field_label {
    color: #6060a0;
    font-family: 'Courier New';
    font-size: 10px;
    letter-spacing: 2px;
}
QLabel#error_label {
    color: #ff4757;
    font-family: 'Courier New';
    font-size: 10px;
    letter-spacing: 1px;
}
QLabel#success_label {
    color: #00ff88;
    font-family: 'Courier New';
    font-size: 10px;
    letter-spacing: 1px;
}
QLineEdit#input_field {
    background-color: #0a0a20;
    color: #00f2ff;
    border: 1px solid #1e1e4a;
    border-radius: 8px;
    padding: 12px 16px;
    font-family: 'Courier New';
    font-size: 13px;
    selection-background-color: #6c5ce7;
}
QLineEdit#input_field:focus {
    border: 1px solid #00f2ff;
    background-color: #0d0d28;
}
QLineEdit#input_field:hover {
    border: 1px solid #3a3a7a;
}
QPushButton#btn_login {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #6c5ce7, stop:1 #00cec9);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 13px;
    font-family: 'Courier New';
    font-size: 12px;
    font-weight: bold;
    letter-spacing: 4px;
}
QPushButton#btn_login:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #7d6ff0, stop:1 #00dfd8);
}
QPushButton#btn_login:pressed {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #5a4dd4, stop:1 #00b5b0);
}
QPushButton#btn_login:disabled {
    background: #1e1e4a;
    color: #3a3a6a;
}
QPushButton#btn_toggle {
    background: transparent;
    color: #4a4a8a;
    border: none;
    font-family: 'Courier New';
    font-size: 10px;
    letter-spacing: 1px;
    padding: 2px;
    text-align: right;
}
QPushButton#btn_toggle:hover {
    color: #00f2ff;
}
QLabel#role_badge {
    background-color: #1a1a40;
    color: #6c5ce7;
    border: 1px solid #2e2e66;
    border-radius: 4px;
    padding: 2px 8px;
    font-family: 'Courier New';
    font-size: 9px;
    letter-spacing: 2px;
}
"""

# ── DB helpers ────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def init_users_table(db_path: str):
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role     TEXT NOT NULL DEFAULT 'analyst',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Seed default admin if table is empty
        existing = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing == 0:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", hash_password("admin123"), "admin")
            )
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("analyst", hash_password("analyst123"), "analyst")
            )
        conn.commit()


def verify_user(db_path: str, username: str, password: str):
    """Returns (role, username) or None if invalid."""
    try:
        with sqlite3.connect(db_path) as conn:
            row = conn.execute(
                "SELECT role FROM users WHERE username=? AND password=?",
                (username, hash_password(password))
            ).fetchone()
            return row[0] if row else None
    except Exception as e:
        print(f"[AUTH ERROR] {e}")
        return None


# ── Animated background grid ──────────────────────────────────────────────────

class GridBackground(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._offset = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(50)

    def _tick(self):
        self._offset = (self._offset + 1) % 40
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Dark background
        painter.fillRect(self.rect(), QColor("#05050f"))

        # Scrolling grid
        pen = QPen(QColor(30, 30, 74, 120))
        pen.setWidth(1)
        painter.setPen(pen)
        step = 40
        for x in range(-step, self.width() + step, step):
            painter.drawLine(x + self._offset, 0, x + self._offset, self.height())
        for y in range(-step, self.height() + step, step):
            painter.drawLine(0, y + self._offset, self.width(), y + self._offset)

        # Glow dots at intersections (sparse)
        dot_pen = QPen(QColor(0, 242, 255, 40))
        dot_pen.setWidth(2)
        painter.setPen(dot_pen)
        for x in range(0, self.width(), step * 3):
            for y in range(0, self.height(), step * 3):
                rx = (x + self._offset) % self.width()
                ry = (y + self._offset) % self.height()
                painter.drawPoint(rx, ry)

        # Top gradient overlay
        grad = QLinearGradient(0, 0, 0, self.height() // 3)
        grad.setColorAt(0, QColor(0, 242, 255, 18))
        grad.setColorAt(1, QColor(0, 0, 0, 0))
        painter.fillRect(self.rect(), QBrush(grad))


# ── Blinking cursor label ─────────────────────────────────────────────────────

class BlinkLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self._show = True
        t = QTimer(self)
        t.timeout.connect(self._blink)
        t.start(600)

    def _blink(self):
        self._show = not self._show
        self.setVisible(self._show)


# ── Login Window ──────────────────────────────────────────────────────────────

class LoginWindow(QMainWindow):
    login_successful = pyqtSignal(str, str)   # (username, role)

    def __init__(self, db_path=DB_PATH):
        super().__init__()
        self.db_path = db_path
        init_users_table(db_path)

        self.setWindowTitle("SOC SIEM PRO — Secure Access")
        self.setFixedSize(480, 580)
        self.setStyleSheet(STYLE)

        # Animated grid background
        self.bg = GridBackground(self)
        self.bg.setGeometry(0, 0, 480, 580)

        # Central card
        self.card = QFrame(self)
        self.card.setObjectName("card")
        self.card.setGeometry(50, 80, 380, 420)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(60)
        shadow.setColor(QColor(0, 242, 255, 80))
        shadow.setOffset(0, 0)
        self.card.setGraphicsEffect(shadow)

        layout = QVBoxLayout(self.card)
        layout.setContentsMargins(36, 36, 36, 36)
        layout.setSpacing(16)

        # Logo row
        logo_row = QHBoxLayout()
        shield = QLabel("⬡")
        shield.setStyleSheet("color: #00f2ff; font-size: 28px;")
        title = QLabel("SOC SIEM PRO")
        title.setObjectName("title")
        logo_row.addWidget(shield)
        logo_row.addWidget(title)
        logo_row.addStretch()
        layout.addLayout(logo_row)

        sub = QLabel("THREAT INTELLIGENCE PLATFORM")
        sub.setObjectName("subtitle")
        layout.addWidget(sub)

        layout.addSpacing(8)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("color: #1e1e4a; background: #1e1e4a; max-height: 1px;")
        layout.addWidget(div)

        layout.addSpacing(4)

        # Username
        lbl_user = QLabel("OPERATOR ID")
        lbl_user.setObjectName("field_label")
        layout.addWidget(lbl_user)
        self.inp_user = QLineEdit()
        self.inp_user.setObjectName("input_field")
        self.inp_user.setPlaceholderText("Enter username...")
        self.inp_user.returnPressed.connect(self.attempt_login)
        layout.addWidget(self.inp_user)

        # Password
        lbl_pass = QLabel("ACCESS KEY")
        lbl_pass.setObjectName("field_label")
        layout.addWidget(lbl_pass)

        pass_row = QHBoxLayout()
        pass_row.setSpacing(0)
        self.inp_pass = QLineEdit()
        self.inp_pass.setObjectName("input_field")
        self.inp_pass.setPlaceholderText("Enter password...")
        self.inp_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_pass.returnPressed.connect(self.attempt_login)

        self.btn_toggle = QPushButton("SHOW")
        self.btn_toggle.setObjectName("btn_toggle")
        self.btn_toggle.setFixedWidth(45)
        self.btn_toggle.clicked.connect(self.toggle_password)

        pass_row.addWidget(self.inp_pass)
        pass_row.addWidget(self.btn_toggle)
        layout.addLayout(pass_row)

        # Feedback label
        self.lbl_feedback = QLabel("")
        self.lbl_feedback.setObjectName("error_label")
        self.lbl_feedback.setFixedHeight(16)
        layout.addWidget(self.lbl_feedback)

        # Login button
        self.btn_login = QPushButton("AUTHENTICATE")
        self.btn_login.setObjectName("btn_login")
        self.btn_login.setFixedHeight(46)
        self.btn_login.clicked.connect(self.attempt_login)
        layout.addWidget(self.btn_login)

        layout.addStretch()

        # Default credentials hint
        hint = QLabel("Default: admin / admin123  |  analyst / analyst123")
        hint.setStyleSheet("color: #2a2a5a; font-family: 'Courier New'; font-size: 9px;")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hint)

        # Bottom status bar
        status_row = QHBoxLayout()
        dot = QLabel("●")
        dot.setStyleSheet("color: #00ff88; font-size: 8px;")
        conn_lbl = QLabel("SYSTEM ONLINE")
        conn_lbl.setStyleSheet("color: #2a4a2a; font-family: 'Courier New'; font-size: 9px; letter-spacing: 2px;")
        cursor = BlinkLabel("█")
        cursor.setStyleSheet("color: #00f2ff; font-size: 10px;")
        status_row.addWidget(dot)
        status_row.addWidget(conn_lbl)
        status_row.addStretch()
        status_row.addWidget(cursor)

        bottom = QWidget(self)
        bottom.setGeometry(50, 515, 380, 30)
        bottom.setStyleSheet("background: transparent;")
        bl = QHBoxLayout(bottom)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addWidget(dot)
        bl.addWidget(conn_lbl)
        bl.addStretch()
        bl.addWidget(cursor)

        # Entry animation
        self.card.setGeometry(50, 140, 380, 420)
        self._anim = QPropertyAnimation(self.card, b"geometry")
        self._anim.setDuration(600)
        self._anim.setStartValue(QRect(50, 140, 380, 420))
        self._anim.setEndValue(QRect(50, 80, 380, 420))
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        QTimer.singleShot(100, self._anim.start)

        self._fail_count = 0

    def toggle_password(self):
        if self.inp_pass.echoMode() == QLineEdit.EchoMode.Password:
            self.inp_pass.setEchoMode(QLineEdit.EchoMode.Normal)
            self.btn_toggle.setText("HIDE")
        else:
            self.inp_pass.setEchoMode(QLineEdit.EchoMode.Password)
            self.btn_toggle.setText("SHOW")

    def attempt_login(self):
        username = self.inp_user.text().strip()
        password = self.inp_pass.text()

        if not username or not password:
            self._set_error("⚠  ALL FIELDS REQUIRED")
            return

        self.btn_login.setEnabled(False)
        self.btn_login.setText("AUTHENTICATING...")
        QTimer.singleShot(600, lambda: self._do_verify(username, password))

    def _do_verify(self, username, password):
        role = verify_user(self.db_path, username, password)
        if role:
            self.lbl_feedback.setObjectName("success_label")
            self.lbl_feedback.setStyleSheet("color: #00ff88; font-family: 'Courier New'; font-size: 10px;")
            self.lbl_feedback.setText(f"✓  ACCESS GRANTED — {role.upper()}")
            self.btn_login.setText("ACCESS GRANTED ✓")
            self.btn_login.setStyleSheet("background: #00b894; color: white; border-radius: 8px; padding: 13px; font-family: 'Courier New'; font-size: 12px; font-weight: bold; letter-spacing: 4px;")
            QTimer.singleShot(800, lambda: self._open_dashboard(username, role))
        else:
            self._fail_count += 1
            self._set_error(f"✕  ACCESS DENIED  [{self._fail_count} FAILED ATTEMPT{'S' if self._fail_count > 1 else ''}]")
            self.inp_pass.clear()
            self.btn_login.setEnabled(True)
            self.btn_login.setText("AUTHENTICATE")
            # Shake animation
            self._shake()

    def _set_error(self, msg):
        self.lbl_feedback.setStyleSheet("color: #ff4757; font-family: 'Courier New'; font-size: 10px;")
        self.lbl_feedback.setText(msg)

    def _shake(self):
        orig = self.card.geometry()
        sequence = [6, -6, 4, -4, 2, -2, 0]
        def _step(i=0):
            if i < len(sequence):
                g = self.card.geometry()
                self.card.setGeometry(orig.x() + sequence[i], g.y(), g.width(), g.height())
                QTimer.singleShot(40, lambda: _step(i + 1))
        _step()

    def _open_dashboard(self, username, role):
        self.login_successful.emit(username, role)
        self.close()


# ── Integration helper ────────────────────────────────────────────────────────

def launch_with_login(db_path=DB_PATH):
    """
    Call this from start.py instead of launching SOCDashboard directly.
    Returns (username, role) after successful login, then opens the dashboard.

    Usage in start.py:
        from login import launch_with_login
        launch_with_login(DB_PATH)
    """
    from gui.app import SOCDashboard

    app = QApplication.instance() or QApplication(sys.argv)
    login_win = LoginWindow(db_path)

    dashboard = None

    def on_login(username, role):
        nonlocal dashboard
        dashboard = SOCDashboard(username=username, role=role)
        dashboard.show()

    login_win.login_successful.connect(on_login)
    login_win.show()
    sys.exit(app.exec())


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = LoginWindow()

    def on_success(user, role):
        print(f"[LOGIN] Welcome {user} ({role})")
        QMessageBox.information(None, "Success", f"Welcome {user}!\nRole: {role}")

    win.login_successful.connect(on_success)
    win.show()
    sys.exit(app.exec())
