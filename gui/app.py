import sys, io, json, os, folium, requests, pyqtgraph as pg, threading
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWebEngineWidgets import QWebEngineView
from fpdf import FPDF
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import ipaddress
from core.schema import get_app_config, set_app_config
from core.ollama_reporter import get_recent_reports, generate_report_async
from core.pdf_report import generate_pdf
from threat_intel import get_threat_score_async, score_to_label
from responder import (
    init_responder_tables, load_email_config, save_email_config,
    send_alert_async, block_ip, unblock_ip, get_blocklist,
    get_rules_v2, add_rule_v2, update_rule_v2, delete_rule_v2,
    toggle_rule_v2, evaluate_rules_v2,
)

try:
    import winsound
    HAS_SOUND = True
except ImportError:
    HAS_SOUND = False

STYLE_SOC = """
    QMainWindow { background-color: #0b0b1a; }
    QWidget { font-family: 'Segoe UI'; }
    QFrame#Card { background-color: #161633; border: 1px solid #2e2e66; border-radius: 10px; }
    QLabel { color: #ffffff; font-family: 'Segoe UI'; font-size: 13px; }

    QPushButton {
        background-color: #6c5ce7; color: white; border-radius: 7px;
        padding: 8px 18px; font-weight: bold; font-size: 12px; min-height: 32px;
    }
    QPushButton:hover { background-color: #7d6ff0; }
    QPushButton:pressed { background-color: #5a4dd4; }
    QPushButton#danger { background-color: #ff4757; }
    QPushButton#danger:hover { background-color: #ff6b7a; }
    QPushButton#success { background-color: #00b894; }
    QPushButton#success:hover { background-color: #00d4aa; }

    QTableWidget {
        background-color: #161633; color: white; border: none;
        gridline-color: #2e2e66; alternate-background-color: #1a1a3a; font-size: 12px;
    }
    QTableWidget::item { padding: 4px 6px; min-height: 28px; }
    QTableWidget::item:hover { background-color: #222250; }
    QTableWidget::item:selected { background-color: #3a3a7a; color: #ffffff; }
    QTableWidget::item:selected:active { background-color: #4a4ab0; color: #ffffff; }

    QHeaderView::section {
        background-color: #1c1c44; color: #00f2ff; padding: 8px 6px;
        font-size: 12px; font-weight: bold; border: none; border-right: 1px solid #2e2e66;
    }
    QHeaderView::section:hover { background-color: #252565; color: #ffffff; }

    QLineEdit {
        background-color: #1c1c44; color: white; border: 1px solid #2e2e66;
        border-radius: 5px; padding: 7px 10px; min-height: 28px; font-size: 12px;
    }
    QLineEdit:hover { border: 1px solid #4a4a9a; }
    QLineEdit:focus { border: 1px solid #6c5ce7; }

    QTabWidget::pane { border: 1px solid #2e2e66; background-color: #0b0b1a; }
    QTabBar::tab {
        background-color: #161633; color: #aaaaaa; padding: 9px 18px;
        border-radius: 5px; margin: 2px; font-size: 12px; min-height: 16px;
    }
    QTabBar::tab:hover { background-color: #1e1e55; color: #cccccc; }
    QTabBar::tab:selected { background-color: #6c5ce7; color: white; }

    QSpinBox {
        background-color: #1c1c44; color: white; border: 1px solid #2e2e66;
        border-radius: 5px; padding: 6px 8px; min-height: 28px; font-size: 12px;
    }
    QComboBox {
        background-color: #1c1c44; color: white; border: 1px solid #2e2e66;
        border-radius: 5px; padding: 6px 10px; min-height: 28px; font-size: 12px;
    }
    QComboBox:hover { border: 1px solid #4a4a9a; }
    QComboBox::drop-down { border: none; }
    QComboBox QAbstractItemView {
        background-color: #161633; color: white;
        selection-background-color: #6c5ce7; font-size: 12px;
    }

    QMenu { background-color: #161633; color: white; border: 1px solid #2e2e66; font-size: 12px; padding: 4px 0px; }
    QMenu::item { padding: 6px 20px; }
    QMenu::item:selected { background-color: #6c5ce7; }

    QCheckBox { color: white; font-size: 12px; spacing: 6px; }
    QCheckBox:hover { color: #a29bfe; }

    QScrollBar:vertical { background: #0b0b1a; width: 10px; border-radius: 5px; }
    QScrollBar::handle:vertical { background: #3a3a7a; border-radius: 5px; min-height: 30px; }
    QScrollBar::handle:vertical:hover { background: #6c5ce7; }
    QScrollBar:horizontal { background: #0b0b1a; height: 10px; border-radius: 5px; }
    QScrollBar::handle:horizontal { background: #6c5ce7; border-radius: 5px; min-width: 30px; }
    QScrollBar::handle:horizontal:hover { background: #7d6ff0; }
    QScrollBar::add-line, QScrollBar::sub-line { width: 0px; height: 0px; }

    QSplitter::handle { background-color: #2e2e66; border-radius: 2px; }
    QSplitter::handle:hover { background-color: #6c5ce7; }
    QSplitter::handle:horizontal { width: 5px; }
    QSplitter::handle:vertical { height: 5px; }

    QTextEdit { font-size: 12px; }

    QTextBrowser#chat_browser {
        background-color: #0b0b1a;
        border: none;
        font-family: 'Segoe UI', sans-serif;
        font-size: 12px;
        padding: 4px;
    }
    QPushButton#chat_quick {
        background-color: #1c1c44;
        color: #a0a0cc;
        border: 1px solid #2e2e66;
        border-radius: 5px;
        padding: 5px 10px;
        font-size: 11px;
        text-align: left;
        min-height: 28px;
        font-weight: normal;
    }
    QPushButton#chat_quick:hover {
        background-color: #252565;
        color: #00f2ff;
        border-color: #4a4a9a;
    }
    QPushButton#chat_quick:pressed { background-color: #1a1a3a; }
"""

SEV_COLORS = {"CRITICAL": "#ff0000", "HIGH": "#ff4757", "MEDIUM": "#ffa502", "LOW": "#00ff88"}
MAP_COLORS = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "blue", "LOW": "green"}

# ── SOC Assist chatbot ────────────────────────────────────────────────────────

_CHAT_SYSTEM = """You are SOC Assist, an AI assistant embedded in SOC SIEM PRO — a security operations platform with real-time threat detection, behavioral analytics, and AI-powered incident analysis.

You serve three functions:
1. Application guide — navigate analysts to the right tab, field, or action
2. Decision support — triage incidents, interpret scores, recommend responses
3. Threat intelligence assistant — explain attack patterns, interpret logs, IOC analysis

## APPLICATION LAYOUT

**Live Alerts tab** — Real-time incident table (Timestamp | Source IP | Country | Type | Severity | Threat Score | Status). Click any row to open the detail panel below with the full log, enrichment data, and AI report. Use the A−/A+ buttons next to the search bar to adjust font size.

**Blocklist tab** — Manually block or unblock IPs. Enter IP → Block. Select row → Unblock. Input is validated. Auto-blocked IPs (threat score ≥ 90) also appear here.

**Rule Engine tab** — Create multi-condition detection rules. Click "+ NEW RULE" → fill Rule Builder dialog. Conditions: field (event_type, severity, source_ip, threat_score, behavior_score, vt_score, anomaly_score, raw_log, hour, day_of_week) + operator (eq, neq, contains, regex, in, gt, lt, gte, lte, between) + value. Logic: AND or OR. Actions: block, email, quarantine, escalate, webhook. Each rule has priority, cooldown, stop_on_match, CIDR exclusion.

**AI Reports tab** — Per-incident deepseek analysis: MITRE ATT&CK tactics, IOCs, recommended actions, confidence. LOW severity + score < 30 do not generate reports.

**Threat Intel tab** — AbuseIPDB confidence scores per source IP.

**Stats tab** — Severity distribution chart, top offending IPs bar chart, event type breakdown.

## SCORING

Threat Score (0–100): composite of heuristic + Ollama LLM + VirusTotal + behavioral + Shodan + GreyNoise + URLScan + anomaly. Auto-block at 90 (SOC_AUTO_BLOCK_SCORE).
- 90+: auto-blocked
- 70–89: high priority, manual review
- 50–69: monitor and correlate
- <50: informational

Detection layers: signature regex matching, IsolationForest anomaly (z-score per IP), behavioral sliding windows (password spray, credential stuffing, distributed brute-force, beaconing CV, lateral movement, low-and-slow port scan, DNS tunneling).

Enrichment (async, per incident): VirusTotal hash + URL, Shodan open ports/CVEs, GreyNoise mass-scanner classification, URLScan.io URL sandbox.

## RESPONSE FORMAT

Navigation: exact tab name + specific action steps. 2–5 lines max.

Triage: always use this block:
  Severity: [CRITICAL/HIGH/MEDIUM/LOW]
  Confidence: [High/Medium/Low]
  Recommended Action: [steps]
  Rationale: [1–3 sentences, evidence-based]

Log/JSON input: extract source IP, event type, severity, timestamps, IOCs. Identify patterns. Suggest MITRE ATT&CK techniques by ID.

Rules of engagement:
- Recommend block if score ≥ 90, or 70–89 with behavioral signal
- At 70–89 without behavioral signal: monitor + manual enrichment
- Below 70: do not recommend block without corroborating signals
- Never invent reputation data — direct to Threat Intel tab, VirusTotal, or Shodan enrichment
- No filler phrases. Professional and direct. Bullets over paragraphs.

## MITRE QUICK REFERENCE
T1110 Brute Force | T1110.003 Password Spraying | T1110.004 Credential Stuffing
T1046 Network Service Discovery (port scan) | T1595.001 Active Scanning
T1071 Application Layer Protocol (C2) | T1071.004 DNS tunneling
T1498 Network DoS | T1021 Remote Services (lateral movement)"""

_CHAT_QUICK_ACTIONS = [
    ("Shift Summary (8h)",         "shift_summary"),
    ("Analyze Selected Incident",  "analyze_selected"),
    ("Should I Block This IP?",    "block_decision"),
    ("Explain This Log",           "explain_log"),
    ("Suggest Detection Rule",     "suggest_rule"),
    ("MITRE ATT&CK Mapping",       "mitre_map"),
]

_CHAT_PLAYBOOKS = [
    ("Playbook: Brute Force",  "playbook_bruteforce"),
    ("Playbook: C2 / Beaconing", "playbook_c2"),
    ("Playbook: Port Scan",    "playbook_portscan"),
    ("Playbook: DDoS",         "playbook_ddos"),
]
EVENT_TYPES = [
    ("BRUTEFORCE", "#ff4757"), ("PORT SCAN", "#ffa502"), ("SQL INJECTION", "#ff6b81"),
    ("DDOS", "#ff0000"), ("MALWARE", "#a29bfe"), ("ANOMALY DETECTED", "#fd79a8"),
    ("SUCCESSFUL LOGIN", "#00ff88"), ("SYSTEM EVENT", "#74b9ff"), ("CRITICAL", "#ff0000"),
]


def _screen_h():
    """Available screen height in pixels."""
    screen = QApplication.primaryScreen()
    if screen:
        return screen.availableGeometry().height()
    return 1080


def _screen_w():
    screen = QApplication.primaryScreen()
    if screen:
        return screen.availableGeometry().width()
    return 1920


# ── Settings Dialog ───────────────────────────────────────────────────────────

class SettingsDialog(QDialog):
    def __init__(self, parent=None, settings=None, db_path=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setStyleSheet(STYLE_SOC)
        self.setMinimumSize(520, 500)
        self.settings = settings or {}
        self.db_path  = db_path
        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        # ── General tab ──
        gen = QWidget()
        form = QFormLayout(gen)
        self.inp_host    = QLineEdit(self.settings.get("host", "127.0.0.1"))
        self.inp_port    = QSpinBox(); self.inp_port.setRange(1000, 99999); self.inp_port.setValue(int(self.settings.get("port", 5000)))
        self.inp_refresh = QSpinBox(); self.inp_refresh.setRange(200, 10000); self.inp_refresh.setSuffix(" ms"); self.inp_refresh.setValue(int(self.settings.get("refresh", 500)))
        self.inp_limit   = QSpinBox(); self.inp_limit.setRange(10, 500); self.inp_limit.setValue(int(self.settings.get("limit", 50)))
        form.addRow(QLabel("Flask Host:"),    self.inp_host)
        form.addRow(QLabel("Flask Port:"),    self.inp_port)
        form.addRow(QLabel("Refresh Rate:"),  self.inp_refresh)
        form.addRow(QLabel("Max Alerts:"),    self.inp_limit)
        tabs.addTab(gen, "General")

        # ── Email tab ──
        email_widget = QWidget()
        ef = QFormLayout(email_widget)
        email_cfg = load_email_config(db_path) if db_path else {}
        self.chk_email   = QCheckBox("Enable Email Alerts")
        self.chk_email.setChecked(email_cfg.get("enabled", False))
        self.inp_sender  = QLineEdit(email_cfg.get("sender", ""))
        self.inp_sender.setPlaceholderText("your@gmail.com")
        self.inp_apppass = QLineEdit(email_cfg.get("app_password", ""))
        self.inp_apppass.setPlaceholderText("Gmail App Password (16 chars)")
        self.inp_apppass.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_recip   = QLineEdit(email_cfg.get("recipient", ""))
        self.inp_recip.setPlaceholderText("alerts-recipient@email.com")
        lbl_help = QLabel("⚠ Use a Gmail App Password, not your account password.\nGet one at: myaccount.google.com → Security → App Passwords")
        lbl_help.setStyleSheet("color: #ffa502; font-size: 12px;")
        lbl_help.setWordWrap(True)
        self.btn_test = QPushButton("SEND TEST EMAIL")
        self.btn_test.setObjectName("success")
        self.btn_test.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_test.clicked.connect(self.test_email)
        ef.addRow(self.chk_email)
        ef.addRow(QLabel("From (Gmail):"),    self.inp_sender)
        ef.addRow(QLabel("App Password:"),    self.inp_apppass)
        ef.addRow(QLabel("Send Alerts To:"),  self.inp_recip)
        ef.addRow(lbl_help)
        ef.addRow(self.btn_test)
        tabs.addTab(email_widget, "Email Alerts")

        # Buttons
        btns = QHBoxLayout()
        btn_save   = QPushButton("SAVE")
        btn_cancel = QPushButton("CANCEL")
        btn_cancel.setStyleSheet("background-color: #444;")
        btn_save.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_save.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)
        btns.addWidget(btn_save); btns.addWidget(btn_cancel)
        layout.addLayout(btns)

    def test_email(self):
        cfg = self._get_email_cfg()
        cfg["enabled"] = True
        from responder import send_alert_email
        ok = send_alert_email(cfg, "[SOC SIEM] Test Alert",
                              "This is a test alert from SOC SIEM PRO.\nEmail alerts are working correctly.")
        if ok:
            QMessageBox.information(self, "Success", "Test email sent successfully!")
        else:
            QMessageBox.critical(self, "Failed", "Failed to send. Check your Gmail and App Password.\n\nMake sure 2FA is ON and you used an App Password.")

    def _get_email_cfg(self):
        return {
            "smtp_host":    "smtp.gmail.com",
            "smtp_port":    587,
            "sender":       self.inp_sender.text().strip(),
            "app_password": self.inp_apppass.text().strip(),
            "recipient":    self.inp_recip.text().strip(),
            "enabled":      self.chk_email.isChecked(),
        }

    def get_settings(self):
        return {"host": self.inp_host.text(), "port": self.inp_port.value(),
                "refresh": self.inp_refresh.value(), "limit": self.inp_limit.value()}

    def get_email_cfg(self):
        return self._get_email_cfg()


# ── Condition row widget ──────────────────────────────────────────────────────

class ConditionRow(QWidget):
    removed = pyqtSignal(object)

    _FIELDS = [
        "event_type", "severity", "category", "source_ip", "raw_log",
        "threat_score", "behavior_score", "vt_score", "anomaly_score",
        "hour", "day_of_week",
    ]
    _STRING_OPS = ["contains", "eq", "neq", "regex", "in"]
    _NUMBER_OPS = ["gte", "lte", "gt", "lt", "eq", "neq", "between", "in"]
    _NUMERIC    = {"threat_score", "behavior_score", "vt_score",
                   "anomaly_score", "hour", "day_of_week"}

    _OP_LABELS = {
        "eq": "=", "neq": "≠", "contains": "contains", "regex": "regex",
        "in": "in list", "gt": ">", "lt": "<", "gte": "≥", "lte": "≤",
        "between": "between",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 4)
        lay.setSpacing(8)

        self.cmb_field = QComboBox()
        self.cmb_field.addItems(self._FIELDS)
        self.cmb_field.setMinimumWidth(155)
        self.cmb_field.currentTextChanged.connect(self._update_ops)

        self.cmb_op = QComboBox()
        self.cmb_op.setMinimumWidth(120)

        self.inp_value = QLineEdit()
        self.inp_value.setPlaceholderText("value…")

        btn_rm = QPushButton("×")
        btn_rm.setFixedWidth(32)
        btn_rm.setStyleSheet("background:#c0392b; color:white; font-weight:bold; border-radius:4px;")
        btn_rm.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_rm.clicked.connect(lambda: self.removed.emit(self))

        lay.addWidget(self.cmb_field)
        lay.addWidget(self.cmb_op)
        lay.addWidget(self.inp_value, 1)
        lay.addWidget(btn_rm)

        self._update_ops(self.cmb_field.currentText())

    def _update_ops(self, field):
        ops = self._NUMBER_OPS if field in self._NUMERIC else self._STRING_OPS
        cur = self.cmb_op.currentText()
        self.cmb_op.blockSignals(True)
        self.cmb_op.clear()
        self.cmb_op.addItems([self._OP_LABELS.get(o, o) for o in ops])
        self._op_keys = ops
        idx = ops.index(cur) if cur in ops else 0
        self.cmb_op.setCurrentIndex(idx)
        self.cmb_op.blockSignals(False)
        # value hint
        hints = {"hour": "0–23", "day_of_week": "0=Mon…6=Sun",
                 "between": "low,high", "in": "val1, val2, …",
                 "severity": "CRITICAL / HIGH / MEDIUM / LOW"}
        self.inp_value.setPlaceholderText(hints.get(field, "value…"))

    def to_dict(self):
        idx = self.cmb_op.currentIndex()
        op  = self._op_keys[idx] if hasattr(self, "_op_keys") and idx < len(self._op_keys) else "eq"
        return {"field": self.cmb_field.currentText(),
                "op": op,
                "value": self.inp_value.text().strip()}

    def from_dict(self, d):
        fi = self.cmb_field.findText(d.get("field", "event_type"))
        if fi >= 0:
            self.cmb_field.setCurrentIndex(fi)
        self._update_ops(self.cmb_field.currentText())
        op = d.get("op", "eq")
        if hasattr(self, "_op_keys") and op in self._op_keys:
            self.cmb_op.setCurrentIndex(self._op_keys.index(op))
        self.inp_value.setText(str(d.get("value", "")))


# ── Rule builder dialog ───────────────────────────────────────────────────────

class RuleBuilderDialog(QDialog):
    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.setWindowTitle("New Rule" if rule is None else f"Edit Rule — {rule.get('name','')}")
        self.setStyleSheet(STYLE_SOC)
        self.setMinimumSize(820, 700)
        self._cond_rows = []

        outer = QVBoxLayout(self)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;}")
        content = QWidget()
        lay = QVBoxLayout(content)
        lay.setSpacing(8)

        # ── Name / Description / Priority ─────────────────────────────────────
        meta = QFrame(); meta.setObjectName("Card")
        mf = QFormLayout(meta)
        mf.setContentsMargins(14, 12, 14, 12)
        self.inp_name = QLineEdit()
        self.inp_desc = QLineEdit()
        self.spn_prio = QSpinBox(); self.spn_prio.setRange(1, 999); self.spn_prio.setValue(50)
        self.chk_stop = QCheckBox("Stop on match (skip lower-priority rules if this fires)")
        mf.addRow("Name *",       self.inp_name)
        mf.addRow("Description",  self.inp_desc)
        mf.addRow("Priority",     self.spn_prio)
        mf.addRow("",             self.chk_stop)
        lay.addWidget(meta)

        # ── Conditions ────────────────────────────────────────────────────────
        cond_frame = QFrame(); cond_frame.setObjectName("Card")
        cf = QVBoxLayout(cond_frame)
        cf.setContentsMargins(14, 12, 14, 12)
        ch = QHBoxLayout()
        lbl_c = QLabel("CONDITIONS")
        lbl_c.setStyleSheet("color:#00f2ff; font-weight:bold; letter-spacing:1px; font-size:13px;")
        lbl_mode = QLabel("Match:")
        self.cmb_mode = QComboBox(); self.cmb_mode.addItems(["AND", "OR"]); self.cmb_mode.setFixedWidth(60)
        btn_add_c = QPushButton("+ Add Condition")
        btn_add_c.setObjectName("success")
        btn_add_c.setFixedWidth(140)
        btn_add_c.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_add_c.clicked.connect(self._add_row)
        ch.addWidget(lbl_c); ch.addSpacing(10)
        ch.addWidget(lbl_mode); ch.addWidget(self.cmb_mode)
        ch.addStretch(); ch.addWidget(btn_add_c)
        cf.addLayout(ch)
        self.cond_layout = QVBoxLayout()
        self.cond_layout.setSpacing(6)
        cf.addLayout(self.cond_layout)
        lay.addWidget(cond_frame)

        # ── Threshold / Window / Scope ────────────────────────────────────────
        tw = QFrame(); tw.setObjectName("Card")
        twf = QHBoxLayout(tw)
        twf.setContentsMargins(14, 12, 14, 12)
        self.spn_thr = QSpinBox(); self.spn_thr.setRange(1, 9999); self.spn_thr.setValue(1)
        self.spn_win = QSpinBox(); self.spn_win.setRange(0, 86400); self.spn_win.setSuffix(" s"); self.spn_win.setValue(60)
        self.cmb_scope = QComboBox(); self.cmb_scope.addItems(["per_ip", "global"])
        self.spn_cool = QSpinBox(); self.spn_cool.setRange(0, 86400); self.spn_cool.setSuffix(" s"); self.spn_cool.setValue(300)
        for lbl, w in [("Threshold:", self.spn_thr), ("Window:", self.spn_win),
                       ("Scope:", self.cmb_scope), ("Cooldown:", self.spn_cool)]:
            twf.addWidget(QLabel(lbl)); twf.addWidget(w)
        twf.addStretch()
        lay.addWidget(tw)

        # ── Actions ───────────────────────────────────────────────────────────
        act_frame = QFrame(); act_frame.setObjectName("Card")
        af = QVBoxLayout(act_frame)
        af.setContentsMargins(14, 12, 14, 12)
        lbl_act = QLabel("ACTIONS  (select one or more)")
        lbl_act.setStyleSheet("color:#00f2ff; font-weight:bold; letter-spacing:1px; font-size:13px;")
        af.addWidget(lbl_act)
        act_row = QHBoxLayout()
        self.chk_block = QCheckBox("🚫 Block IP")
        self.chk_email = QCheckBox("📧 Email Alert")
        self.chk_quar  = QCheckBox("🔒 Quarantine")
        self.chk_esc   = QCheckBox("⬆ Escalate to CRITICAL")
        for c in (self.chk_block, self.chk_email, self.chk_quar, self.chk_esc):
            act_row.addWidget(c)
        act_row.addStretch()
        af.addLayout(act_row)
        wh_row = QHBoxLayout()
        wh_row.addWidget(QLabel("Webhook URL:"))
        self.inp_webhook = QLineEdit()
        self.inp_webhook.setPlaceholderText("https://hooks.slack.com/… (optional)")
        wh_row.addWidget(self.inp_webhook)
        af.addLayout(wh_row)
        lay.addWidget(act_frame)

        # ── Exclude IPs ───────────────────────────────────────────────────────
        excl = QFrame(); excl.setObjectName("Card")
        ef = QHBoxLayout(excl)
        ef.setContentsMargins(14, 12, 14, 12)
        ef.addWidget(QLabel("Exclude IPs / CIDRs:"))
        self.inp_excl = QLineEdit()
        self.inp_excl.setPlaceholderText("10.0.0.0/8, 192.168.0.0/16")
        ef.addWidget(self.inp_excl)
        lay.addWidget(excl)

        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        # ── Buttons ───────────────────────────────────────────────────────────
        btns = QHBoxLayout()
        btn_save   = QPushButton("SAVE RULE"); btn_save.setObjectName("success")
        btn_cancel = QPushButton("CANCEL");    btn_cancel.setStyleSheet("background:#444;")
        btn_save.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_save.clicked.connect(self._on_save)
        btn_cancel.clicked.connect(self.reject)
        btns.addStretch(); btns.addWidget(btn_save); btns.addWidget(btn_cancel)
        outer.addLayout(btns)

        self._add_row()  # start with one empty condition
        if rule:
            self._load(rule)

    def _add_row(self, data=None):
        row = ConditionRow(self)
        row.removed.connect(self._rm_row)
        if data:
            row.from_dict(data)
        self.cond_layout.addWidget(row)
        self._cond_rows.append(row)

    def _rm_row(self, row):
        if len(self._cond_rows) <= 1:
            return
        self.cond_layout.removeWidget(row)
        row.deleteLater()
        self._cond_rows.remove(row)

    def _load(self, rule):
        self.inp_name.setText(rule.get("name", ""))
        self.inp_desc.setText(rule.get("description", ""))
        self.spn_prio.setValue(int(rule.get("priority", 50)))
        self.chk_stop.setChecked(bool(rule.get("stop_on_match", 0)))
        self.spn_thr.setValue(int(rule.get("threshold", 1)))
        self.spn_win.setValue(int(rule.get("window_sec", 60)))
        self.spn_cool.setValue(int(rule.get("cooldown_sec", 300)))
        idx = self.cmb_scope.findText(rule.get("scope", "per_ip"))
        if idx >= 0: self.cmb_scope.setCurrentIndex(idx)
        idx = self.cmb_mode.findText(rule.get("condition_mode", "AND"))
        if idx >= 0: self.cmb_mode.setCurrentIndex(idx)
        self.chk_block.setChecked(bool(rule.get("action_block", 0)))
        self.chk_email.setChecked(bool(rule.get("action_email", 0)))
        self.chk_quar.setChecked(bool(rule.get("action_quarantine", 0)))
        self.chk_esc.setChecked(bool(rule.get("action_escalate", 0)))
        self.inp_webhook.setText(rule.get("action_webhook", ""))
        self.inp_excl.setText(rule.get("exclude_ips", ""))
        try:
            conds = json.loads(rule.get("conditions", "[]"))
        except Exception:
            conds = []
        while self._cond_rows:
            r = self._cond_rows[0]
            self.cond_layout.removeWidget(r)
            r.deleteLater()
            self._cond_rows.clear()
        for c in conds:
            self._add_row(c)
        if not self._cond_rows:
            self._add_row()

    def _on_save(self):
        if not self.inp_name.text().strip():
            QMessageBox.warning(self, "Validation", "Rule name is required.")
            return
        if not any([self.chk_block.isChecked(), self.chk_email.isChecked(),
                    self.chk_quar.isChecked(), self.chk_esc.isChecked(),
                    self.inp_webhook.text().strip()]):
            QMessageBox.warning(self, "Validation", "Select at least one action.")
            return
        self.accept()

    def get_data(self) -> dict:
        conds = [r.to_dict() for r in self._cond_rows if r.to_dict().get("value")]
        return {
            "name":            self.inp_name.text().strip(),
            "description":     self.inp_desc.text().strip(),
            "priority":        self.spn_prio.value(),
            "stop_on_match":   int(self.chk_stop.isChecked()),
            "conditions":      json.dumps(conds),
            "condition_mode":  self.cmb_mode.currentText(),
            "threshold":       self.spn_thr.value(),
            "window_sec":      self.spn_win.value(),
            "scope":           self.cmb_scope.currentText(),
            "cooldown_sec":    self.spn_cool.value(),
            "action_block":    int(self.chk_block.isChecked()),
            "action_email":    int(self.chk_email.isChecked()),
            "action_quarantine": int(self.chk_quar.isChecked()),
            "action_escalate": int(self.chk_esc.isChecked()),
            "action_webhook":  self.inp_webhook.text().strip(),
            "exclude_ips":     self.inp_excl.text().strip(),
        }


# ── Main Dashboard ────────────────────────────────────────────────────────────

class SOCDashboard(QMainWindow):
    _threat_ready   = pyqtSignal(str)
    _action_signal  = pyqtSignal(str, str)
    _chat_reply_sig = pyqtSignal(str)   # Ollama chat response → main thread
    _pdf_done_sig   = pyqtSignal(str, str, str)  # (path|"", error|"", output_path) → main thread

    def __init__(self, username="operator", role="analyst", db_path=None, api_key=None):
        super().__init__()
        self.username = username
        self.role     = role
        self.db_path  = db_path
        self._api_key = api_key
        self.setWindowTitle(f"SOC SIEM PRO  —  {username.upper()}  [{role.upper()}]")
        self.setStyleSheet(STYLE_SOC)

        # Fill the screen on startup
        screen_geom = QApplication.primaryScreen().availableGeometry()
        self.setGeometry(screen_geom)

        # State
        self.trend_points  = [0]
        self._all_alerts   = []
        self._all_ips      = set()
        self._geo_cache    = {}      # ip → dict | None (None = lookup in-flight)
        self._geo_lock     = threading.Lock()
        self._ip_severity  = {}
        self._prev_ids     = set()
        self._threat_cache = {}
        self._threat_lock  = threading.Lock()
        self.settings      = {"host": "127.0.0.1", "port": 5000, "refresh": 500, "limit": 50}
        self.email_cfg     = load_email_config(db_path) if db_path else {}
        self._reports_data = []
        self.gui_zoom      = self._load_int_pref("gui_zoom", 10)
        # Bounded thread pool for background geo/enrich/rule tasks
        self._bg_pool      = ThreadPoolExecutor(max_workers=8)
        # Report cache: avoid re-querying SQLite every 500ms for the same alert
        self._last_report_id  = None
        self._last_report     = None

        sw = _screen_w()
        default_left  = int(sw * 0.38)
        default_right = sw - default_left - 12
        self.alert_split_sizes = self._load_json_pref("alert_split_sizes", [default_left, default_right])

        if db_path:
            init_responder_tables(db_path)

        self._threat_ready.connect(self._on_threat_ready)
        self._action_signal.connect(self._on_action_taken)

        self._build_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.fetch_data)
        self.timer.start(self.settings["refresh"])
        QTimer.singleShot(1500, self.update_world_map)

    def _load_int_pref(self, key, default):
        if not self.db_path:
            return default
        try:
            return int(get_app_config(self.db_path, key, default))
        except Exception:
            return default

    def _load_json_pref(self, key, default):
        if not self.db_path:
            return default
        try:
            value = get_app_config(self.db_path, key, None)
            return json.loads(value) if value else default
        except Exception:
            return default

    def _save_pref(self, key, value):
        if self.db_path:
            set_app_config(self.db_path, key, json.dumps(value) if isinstance(value, (list, dict)) else value)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)

        # ── Header ───────────────────────────────────────────────────────────
        header = QHBoxLayout()
        header.setSpacing(10)
        lbl_title = QLabel("SOC MONITORING ENGINE")
        lbl_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #00f2ff; letter-spacing: 2px;")
        lbl_user  = QLabel(f"👤 {self.username.upper()}  |  {self.role.upper()}")
        lbl_user.setStyleSheet("font-size: 13px; color: #6c5ce7; font-family: 'Courier New';")
        self.lbl_action = QLabel("")
        self.lbl_action.setStyleSheet("font-size: 12px; color: #00ff88; font-family: 'Courier New';")
        self.btn_settings = QPushButton("SETTINGS")
        self.btn_settings.setStyleSheet("background-color: #2e2e66;")
        self.btn_settings.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_settings.clicked.connect(self.open_settings)
        self.btn_report = QPushButton("EXPORT PDF")
        self.btn_report.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_report.clicked.connect(self.generate_pdf_report)
        header.addWidget(lbl_title)
        header.addWidget(lbl_user)
        header.addWidget(self.lbl_action)
        header.addStretch()
        header.addWidget(self.btn_settings)
        header.addWidget(self.btn_report)
        layout.addLayout(header)

        # ── Stats bar ────────────────────────────────────────────────────────
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFixedHeight(110)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        scroll_widget = QWidget(); scroll_widget.setStyleSheet("background: transparent;")
        self.stats_bar = QHBoxLayout(scroll_widget)
        self.stats_bar.setSpacing(8)
        self.stats_bar.setContentsMargins(4, 4, 4, 4)
        self.card_total, self.lbl_total = self._make_stat_card("TOTAL ALERTS", "0", "#00f2ff")
        self.stats_bar.addWidget(self.card_total)
        self.event_type_labels = {}
        for name, color in EVENT_TYPES:
            card, lbl = self._make_stat_card(name, "0", color)
            self.event_type_labels[name] = lbl
            self.stats_bar.addWidget(card)
        self.card_threats, self.lbl_threats = self._make_stat_card("MALICIOUS IPs", "0", "#ff4757")
        self.stats_bar.addWidget(self.card_threats)
        self.card_blocked, self.lbl_blocked = self._make_stat_card("BLOCKED IPs", "0", "#fd79a8")
        self.stats_bar.addWidget(self.card_blocked)
        self.stats_bar.addStretch()
        scroll_area.setWidget(scroll_widget)
        layout.addWidget(scroll_area)

        # ── Tabs ─────────────────────────────────────────────────────────────
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self._build_tab_alerts()
        self._build_tab_stats()
        self._build_tab_timeline()
        self._build_tab_threat()
        self._build_tab_reports()
        self._build_tab_blocklist()
        self._build_tab_rules()
        self._build_tab_chat()

    def _build_tab_alerts(self):
        sh = _screen_h()
        map_h     = max(260, int(sh * 0.29))   # ~313px on 1080p — bigger map
        details_h = max(220, int(sh * 0.30))   # ~324px on 1080p

        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.setContentsMargins(8, 8, 8, 8)
        tl.setSpacing(8)
        self.alert_splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left panel: trend graph + map ────────────────────────────────────
        left_widget = QWidget(); left = QVBoxLayout(left_widget)
        left.setContentsMargins(0, 0, 4, 0)
        left.setSpacing(8)

        self.graph_card = QFrame(); self.graph_card.setObjectName("Card")
        gv = QVBoxLayout(self.graph_card)
        gv.setContentsMargins(8, 6, 8, 6)
        gv.setSpacing(4)
        lbl_trend = QLabel("INCIDENT TREND (LIVE)")
        lbl_trend.setStyleSheet("font-size: 13px; color: #00f2ff; font-weight: bold; letter-spacing: 1px;")
        gv.addWidget(lbl_trend)
        self.graph_widget = pg.PlotWidget(); self.graph_widget.setBackground("#161633")
        self.curve = self.graph_widget.plot(pen=pg.mkPen(color="#00f2ff", width=2))
        gv.addWidget(self.graph_widget)
        self.graph_widget.setMinimumHeight(160)
        left.addWidget(self.graph_card, 1)   # equal 1:1 with map

        self.map_card = QFrame(); self.map_card.setObjectName("Card")
        mv = QVBoxLayout(self.map_card)
        mv.setContentsMargins(8, 6, 8, 6)
        mv.setSpacing(6)
        mh = QHBoxLayout()
        lbl_map = QLabel("LIVE ATTACK MAP")
        lbl_map.setStyleSheet("font-size: 13px; color: #00f2ff; font-weight: bold; letter-spacing: 1px;")
        self.btn_refresh_map = QPushButton("REFRESH MAP"); self.btn_refresh_map.setFixedWidth(110)
        self.btn_refresh_map.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh_map.clicked.connect(self.update_world_map)
        mh.addWidget(lbl_map); mh.addStretch(); mh.addWidget(self.btn_refresh_map)
        mv.addLayout(mh)
        self.web_view = QWebEngineView()
        self.web_view.setMinimumHeight(160)
        mv.addWidget(self.web_view)
        left.addWidget(self.map_card, 1)     # equal 1:1 with trend

        # ── Right panel: risk + search + table + details ──────────────────────
        right_widget = QWidget(); right = QVBoxLayout(right_widget)
        right.setContentsMargins(4, 0, 0, 0)
        right.setSpacing(8)

        self.risk_card = QFrame(); self.risk_card.setObjectName("Card")
        self.risk_card.setFixedHeight(88)
        rv = QHBoxLayout(self.risk_card)
        rv.setContentsMargins(20, 8, 20, 8)
        lbl_risk_title = QLabel("CURRENT RISK LEVEL")
        lbl_risk_title.setStyleSheet("font-size: 12px; color: #888; letter-spacing: 1px;")
        self.lbl_risk = QLabel("NORMAL")
        self.lbl_risk.setStyleSheet("font-size: 30px; color: #00ff88; font-weight: bold;")
        rv.addWidget(lbl_risk_title)
        rv.addStretch()
        rv.addWidget(self.lbl_risk)
        right.addWidget(self.risk_card)

        tools = QHBoxLayout()
        tools.setSpacing(8)
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search by IP, country, event, severity, threat...")
        self.search_bar.textChanged.connect(self.filter_table)
        btn_zoom_out = QPushButton("A−"); btn_zoom_out.setFixedWidth(48)
        btn_zoom_in  = QPushButton("A+"); btn_zoom_in.setFixedWidth(48)
        btn_zoom_out.setToolTip("Decrease table font size")
        btn_zoom_in.setToolTip("Increase table font size")
        btn_zoom_out.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_zoom_in.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_zoom_out.clicked.connect(lambda: self._set_zoom(self.gui_zoom - 1))
        btn_zoom_in.clicked.connect(lambda: self._set_zoom(self.gui_zoom + 1))
        tools.addWidget(self.search_bar)
        tools.addWidget(btn_zoom_out)
        tools.addWidget(btn_zoom_in)
        right.addLayout(tools)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Timestamp","Source IP","Country","Type","Severity","Threat Score","Status"])
        ah = self.table.horizontalHeader()
        ah.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        ah.setMinimumSectionSize(50)
        self.table.setColumnWidth(0, 140)  # Timestamp
        self.table.setColumnWidth(1, 115)  # Source IP
        self.table.setColumnWidth(2, 90)   # Country
        self.table.setColumnWidth(3, 160)  # Type
        self.table.setColumnWidth(4, 80)   # Severity
        self.table.setColumnWidth(5, 95)   # Threat Score
        self.table.setColumnWidth(6, 80)   # Status
        ah.setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_status_menu)
        self.table.itemSelectionChanged.connect(self._show_selected_alert_details)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        right.addWidget(self.table, 1)
        self.table.viewport().setCursor(Qt.CursorShape.PointingHandCursor)

        self.details_card = QFrame(); self.details_card.setObjectName("Card")
        dv = QVBoxLayout(self.details_card)
        dv.setContentsMargins(8, 6, 8, 6)
        dv.setSpacing(4)
        lbl_det = QLabel("FULL INCIDENT REPORT")
        lbl_det.setStyleSheet("font-size: 13px; color: #00f2ff; font-weight: bold; letter-spacing: 1px;")
        dv.addWidget(lbl_det)
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFixedHeight(details_h)
        self.detail_text.setStyleSheet(
            "background-color:#0a0a1e; color:#ffffff; border:1px solid #2e2e66;"
            "font-family:'Consolas'; font-size:12px;"
        )
        dv.addWidget(self.detail_text)
        right.addWidget(self.details_card)

        self.alert_splitter.addWidget(left_widget)
        self.alert_splitter.addWidget(right_widget)
        self.alert_splitter.setSizes(self.alert_split_sizes)
        tl.addWidget(self.alert_splitter)
        self._apply_zoom()
        self.tabs.addTab(tab, "🔴 Live Alerts")

    def _build_tab_stats(self):
        sh = _screen_h()
        chart_h = max(200, int(sh * 0.24))   # ~259px on 1080p
        heat_h  = max(150, int(sh * 0.17))   # ~183px on 1080p
        tbl_h   = max(110, int(sh * 0.12))   # ~129px on 1080p

        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.setContentsMargins(8, 8, 8, 8)
        tl.setSpacing(8)

        # ── Top row: pie + severity bar ───────────────────────────────────────
        top_row = QHBoxLayout(); top_row.setSpacing(8)

        pie_card = QFrame(); pie_card.setObjectName("Card")
        pie_vl = QVBoxLayout(pie_card)
        pie_vl.setContentsMargins(8, 6, 8, 6)
        pie_title = QLabel("EVENT TYPE DISTRIBUTION")
        pie_title.setStyleSheet("color:#00f2ff; font-size:13px; font-weight:bold; letter-spacing:2px;")
        pie_vl.addWidget(pie_title)
        self.pie_widget = pg.PlotWidget()
        self.pie_widget.setBackground("#161633")
        self.pie_widget.setFixedHeight(chart_h)
        self.pie_widget.hideAxis("left"); self.pie_widget.hideAxis("bottom")
        self.pie_widget.setAspectLocked(True)
        pie_vl.addWidget(self.pie_widget)
        top_row.addWidget(pie_card, 3)

        sev_card = QFrame(); sev_card.setObjectName("Card")
        sev_vl = QVBoxLayout(sev_card)
        sev_vl.setContentsMargins(8, 6, 8, 6)
        sev_title = QLabel("SEVERITY BREAKDOWN")
        sev_title.setStyleSheet("color:#00f2ff; font-size:13px; font-weight:bold; letter-spacing:2px;")
        sev_vl.addWidget(sev_title)
        self.sev_widget = pg.PlotWidget()
        self.sev_widget.setBackground("#161633")
        self.sev_widget.setFixedHeight(chart_h)
        self.sev_widget.showGrid(y=True, alpha=0.3)
        sev_vl.addWidget(self.sev_widget)
        top_row.addWidget(sev_card, 2)
        tl.addLayout(top_row)

        # ── Heatmap ───────────────────────────────────────────────────────────
        heat_card = QFrame(); heat_card.setObjectName("Card")
        heat_vl = QVBoxLayout(heat_card)
        heat_vl.setContentsMargins(8, 6, 8, 6)
        heat_title = QLabel("ATTACK HEATMAP — DAY × HOUR")
        heat_title.setStyleSheet("color:#00f2ff; font-size:13px; font-weight:bold; letter-spacing:2px;")
        heat_vl.addWidget(heat_title)
        self.heat_widget = pg.PlotWidget()
        self.heat_widget.setBackground("#161633")
        self.heat_widget.setFixedHeight(heat_h)
        self.heat_widget.setLabel("left",   "Day",          color="#00f2ff")
        self.heat_widget.setLabel("bottom", "Hour (0–23)",  color="#00f2ff")
        heat_vl.addWidget(self.heat_widget)
        tl.addWidget(heat_card)

        # ── Event breakdown table ─────────────────────────────────────────────
        tbl_card = QFrame(); tbl_card.setObjectName("Card")
        tbl_vl = QVBoxLayout(tbl_card)
        tbl_vl.setContentsMargins(8, 6, 8, 6)
        tbl_lbl = QLabel("DETAILED EVENT BREAKDOWN")
        tbl_lbl.setStyleSheet("color:#00f2ff; font-size:13px; font-weight:bold; letter-spacing:2px;")
        tbl_vl.addWidget(tbl_lbl)
        self.stats_table = QTableWidget(0, 3)
        self.stats_table.setHorizontalHeaderLabels(["Event Type", "Count", "% of Total"])
        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.stats_table.setFixedHeight(tbl_h)
        tbl_vl.addWidget(self.stats_table)
        tl.addWidget(tbl_card)

        self.tabs.addTab(tab, "📊 Statistics")

    def _build_tab_timeline(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.setContentsMargins(8, 8, 8, 8)
        lbl = QLabel("INCIDENTS PER HOUR (LAST 24H)")
        lbl.setStyleSheet("font-size: 13px; color: #00f2ff; font-weight: bold; letter-spacing: 2px;")
        tl.addWidget(lbl)
        self.timeline_widget = pg.PlotWidget(); self.timeline_widget.setBackground("#161633")
        self.timeline_widget.setLabel("left",   "Count", color="#00f2ff")
        self.timeline_widget.setLabel("bottom", "Hour",  color="#00f2ff")
        self.timeline_widget.showGrid(x=True, y=True, alpha=0.3)
        tl.addWidget(self.timeline_widget)
        self.tabs.addTab(tab, "📈 Timeline")

    def _build_tab_threat(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.setContentsMargins(8, 8, 8, 8)
        lbl = QLabel("THREAT INTELLIGENCE — AbuseIPDB + AI Analysis")
        lbl.setStyleSheet("font-size: 13px; color: #00f2ff; font-weight: bold; letter-spacing: 2px;")
        tl.addWidget(lbl)
        self.threat_table = QTableWidget(0, 8)
        self.threat_table.setHorizontalHeaderLabels(["IP","Combined","AI","AbuseIPDB","Risk Level","Country","ISP","AI Summary"])
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tl.addWidget(self.threat_table)
        self.threat_table.viewport().setCursor(Qt.CursorShape.PointingHandCursor)
        self.tabs.addTab(tab, "🌐 Threat Intel")

    def _build_tab_reports(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.setContentsMargins(8, 8, 8, 8)
        tl.setSpacing(8)

        # ── Top bar ───────────────────────────────────────────────────────────
        top = QHBoxLayout()
        lbl = QLabel("AI INCIDENT REPORTS  —  deepseek-coder-v2:16b via Ollama")
        lbl.setStyleSheet("font-size: 13px; color: #00f2ff; font-weight: bold; letter-spacing: 1px;")
        self.lbl_report_status = QLabel("")
        self.lbl_report_status.setStyleSheet("font-size: 12px; color: #6c5ce7; font-family: 'Courier New';")
        top.addWidget(lbl)
        top.addWidget(self.lbl_report_status)
        top.addStretch()
        tl.addLayout(top)

        # ── Report list table (top half) ──────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)

        list_frame = QFrame(); list_frame.setObjectName("Card")
        lf = QVBoxLayout(list_frame)
        lf.setContentsMargins(6, 6, 6, 6)
        self.reports_table = QTableWidget(0, 7)
        self.reports_table.setHorizontalHeaderLabels([
            "Report #", "Incident", "Time", "Event Type", "Source IP", "Severity", "Confidence"
        ])
        self.reports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.reports_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.reports_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.reports_table.itemSelectionChanged.connect(self._show_report_detail)
        lf.addWidget(self.reports_table)
        self.reports_table.viewport().setCursor(Qt.CursorShape.PointingHandCursor)
        splitter.addWidget(list_frame)

        # ── Detail panel (bottom half) ────────────────────────────────────────
        detail_frame = QFrame(); detail_frame.setObjectName("Card")
        df = QVBoxLayout(detail_frame)
        df.setContentsMargins(10, 8, 10, 8)
        df.setSpacing(6)

        detail_header = QHBoxLayout()
        self.lbl_report_title = QLabel("Select a report above to view full analysis")
        self.lbl_report_title.setStyleSheet("font-size: 13px; color: #00f2ff; font-weight: bold;")
        self.lbl_report_confidence = QLabel("")
        self.lbl_report_confidence.setStyleSheet("font-size: 12px; color: #ffa502; font-weight: bold;")
        detail_header.addWidget(self.lbl_report_title)
        detail_header.addStretch()
        detail_header.addWidget(self.lbl_report_confidence)
        df.addLayout(detail_header)

        # Two-column detail layout
        cols = QHBoxLayout(); cols.setSpacing(8)

        # Left column: summary + MITRE
        left_col = QVBoxLayout()
        lbl_sum = QLabel("ATTACK SUMMARY")
        lbl_sum.setStyleSheet("font-size: 11px; color: #888; letter-spacing: 1px;")
        self.report_summary = QTextEdit()
        self.report_summary.setReadOnly(True)
        self.report_summary.setMinimumHeight(100)
        self.report_summary.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.report_summary.setStyleSheet("background:#101028; color:#ffffff; border:1px solid #2e2e66; font-size:12px;")

        lbl_mitre = QLabel("MITRE ATT&CK")
        lbl_mitre.setStyleSheet("font-size: 11px; color: #888; letter-spacing: 1px; margin-top: 4px;")
        self.report_mitre = QTextEdit()
        self.report_mitre.setReadOnly(True)
        self.report_mitre.setMinimumHeight(90)
        self.report_mitre.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.report_mitre.setStyleSheet("background:#101028; color:#a29bfe; border:1px solid #2e2e66; font-size:12px;")

        left_col.addWidget(lbl_sum)
        left_col.addWidget(self.report_summary)
        left_col.addWidget(lbl_mitre)
        left_col.addWidget(self.report_mitre)
        cols.addLayout(left_col, 3)

        # Right column: IOCs + actions
        right_col = QVBoxLayout()
        lbl_iocs = QLabel("IOCs")
        lbl_iocs.setStyleSheet("font-size: 11px; color: #888; letter-spacing: 1px;")
        self.report_iocs = QTextEdit()
        self.report_iocs.setReadOnly(True)
        self.report_iocs.setMinimumHeight(80)
        self.report_iocs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.report_iocs.setStyleSheet("background:#101028; color:#ff4757; border:1px solid #2e2e66; font-size:12px;")

        lbl_actions = QLabel("RECOMMENDED ACTIONS")
        lbl_actions.setStyleSheet("font-size: 11px; color: #888; letter-spacing: 1px; margin-top: 4px;")
        self.report_actions = QTextEdit()
        self.report_actions.setReadOnly(True)
        self.report_actions.setMinimumHeight(110)
        self.report_actions.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.report_actions.setStyleSheet("background:#101028; color:#00ff88; border:1px solid #2e2e66; font-size:12px;")

        right_col.addWidget(lbl_iocs)
        right_col.addWidget(self.report_iocs)
        right_col.addWidget(lbl_actions)
        right_col.addWidget(self.report_actions)
        cols.addLayout(right_col, 2)

        df.addLayout(cols)
        splitter.addWidget(detail_frame)

        sh = _screen_h()
        splitter.setSizes([int(sh * 0.28), int(sh * 0.30)])
        tl.addWidget(splitter, 1)
        self.tabs.addTab(tab, "🤖 AI Reports")

        # Store reports data for selection lookup
        self._reports_data = []

    def _refresh_reports_tab(self):
        if not self.db_path:
            return
        try:
            reports = get_recent_reports(self.db_path, limit=50)
            self._reports_data = reports
            self.reports_table.clearContents()
            self.reports_table.setRowCount(len(reports))

            conf_colors = {
                range(0,  40):  "#888888",
                range(40, 70):  "#ffa502",
                range(70, 90):  "#00b894",
                range(90, 101): "#00f2ff",
            }

            def conf_color(c):
                for r, col in conf_colors.items():
                    if c in r:
                        return col
                return "#ffffff"

            sev_col = {"CRITICAL": "#ff0000", "HIGH": "#ff4757", "MEDIUM": "#ffa502", "LOW": "#00ff88"}

            for i, r in enumerate(reports):
                conf = int(r.get("confidence", 0))
                sev  = str(r.get("severity", "LOW")).upper()
                cc   = conf_color(conf)
                sc   = sev_col.get(sev, "#ffffff")
                cells = [
                    (str(r.get("id", "")),            cc),
                    (str(r.get("incident_id", "")),   cc),
                    (str(r.get("generated_at", ""))[:19], "#aaaaaa"),
                    (str(r.get("event_type", "")),    sc),
                    (str(r.get("source_ip", "")),     "#74b9ff"),
                    (sev,                             sc),
                    (f"{conf}%",                      cc),
                ]
                for j, (val, color) in enumerate(cells):
                    item = QTableWidgetItem(val)
                    item.setForeground(QColor(color))
                    self.reports_table.setItem(i, j, item)

            count = len(reports)
            self.lbl_report_status.setText(f"{count} report{'s' if count != 1 else ''} available")
        except Exception as e:
            print(f"[REPORTS TAB ERROR] {e}")

    def _show_report_detail(self):
        row = self.reports_table.currentRow()
        if row < 0 or row >= len(self._reports_data):
            return
        r = self._reports_data[row]

        sev = str(r.get("severity", "")).upper()
        sev_col = {"CRITICAL": "#ff0000", "HIGH": "#ff4757", "MEDIUM": "#ffa502", "LOW": "#00ff88"}
        color = sev_col.get(sev, "#ffffff")

        self.lbl_report_title.setText(
            f"Report #{r.get('id')}  |  {r.get('event_type', '')}  from  {r.get('source_ip', '')}"
        )
        self.lbl_report_title.setStyleSheet(f"font-size: 12px; color: {color}; font-weight: bold;")

        conf = int(r.get("confidence", 0))
        self.lbl_report_confidence.setText(f"Confidence: {conf}%  |  Model: {r.get('model', '')}")

        self.report_summary.setPlainText(r.get("attack_summary", "") or "No summary available.")

        mitre_text = ""
        if r.get("mitre_tactics"):
            mitre_text += f"Tactics:    {r['mitre_tactics']}\n"
        if r.get("mitre_techniques"):
            mitre_text += f"Techniques: {r['mitre_techniques']}"
        self.report_mitre.setPlainText(mitre_text.strip() or "No MITRE data.")

        self.report_iocs.setPlainText(r.get("iocs", "") or "No IOCs extracted.")

        actions = r.get("recommended_actions", "") or ""
        formatted = "\n".join(
            f"• {a.strip()}" for a in actions.split(";") if a.strip()
        )
        self.report_actions.setPlainText(formatted or "No actions available.")

    def _build_tab_blocklist(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.setContentsMargins(8, 8, 8, 8)
        tl.setSpacing(8)

        ctrl = QHBoxLayout(); ctrl.setSpacing(8)
        self.inp_block_ip     = QLineEdit()
        self.inp_block_ip.setPlaceholderText("IP address to block  (e.g. 203.0.113.5)")
        self.inp_block_reason = QLineEdit()
        self.inp_block_reason.setPlaceholderText("Reason (optional)")
        self.lbl_block_err = QLabel("")
        self.lbl_block_err.setStyleSheet("color:#ff4757; font-size:12px;")
        btn_block   = QPushButton("BLOCK IP");          btn_block.setObjectName("danger");    btn_block.setFixedWidth(100)
        btn_unblock = QPushButton("UNBLOCK SELECTED");  btn_unblock.setStyleSheet("background:#2e2e66;"); btn_unblock.setFixedWidth(160)
        btn_block.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_unblock.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_block.clicked.connect(self._manual_block)
        btn_unblock.clicked.connect(self._manual_unblock)
        ctrl.addWidget(self.inp_block_ip, 2)
        ctrl.addWidget(self.inp_block_reason, 3)
        ctrl.addWidget(self.lbl_block_err, 2)
        ctrl.addStretch()
        ctrl.addWidget(btn_block)
        ctrl.addWidget(btn_unblock)
        tl.addLayout(ctrl)

        self.blocklist_table = QTableWidget(0, 3)
        self.blocklist_table.setHorizontalHeaderLabels(["IP Address", "Reason", "Added At"])
        self.blocklist_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.blocklist_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.blocklist_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.blocklist_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.blocklist_table.setAlternatingRowColors(True)
        self.blocklist_table.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        tl.addWidget(self.blocklist_table)
        self.blocklist_table.viewport().setCursor(Qt.CursorShape.PointingHandCursor)

        hint = QLabel("Click a row to select · Shift+Click or Ctrl+Click for multiple · then press UNBLOCK SELECTED")
        hint.setStyleSheet("color:#555; font-size:12px;")
        tl.addWidget(hint)
        self.tabs.addTab(tab, "🚫 Blocklist")

    def _build_tab_rules(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.setContentsMargins(8, 8, 8, 8)
        tl.setSpacing(8)

        top = QHBoxLayout()
        lbl = QLabel("RULE ENGINE v2 — Multi-condition · Multi-action · Priority · Cooldown")
        lbl.setStyleSheet("font-size: 13px; color: #00f2ff; font-weight: bold; letter-spacing: 1px;")
        btn_new = QPushButton("＋ NEW RULE"); btn_new.setObjectName("success"); btn_new.setFixedWidth(120)
        btn_new.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_new.clicked.connect(self._new_rule)
        top.addWidget(lbl); top.addStretch(); top.addWidget(btn_new)
        tl.addLayout(top)

        self.rules_table = QTableWidget(0, 8)
        self.rules_table.setHorizontalHeaderLabels(
            ["Pri", "Name", "Conditions", "Thr/Win", "Actions", "Cooldown", "On", "Edit"]
        )
        hh = self.rules_table.horizontalHeader()
        # All columns user-resizable; set initial widths so nothing is invisible
        for col in range(8):
            hh.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        hh.setMinimumSectionSize(36)
        self.rules_table.setColumnWidth(0, 40)   # Pri
        self.rules_table.setColumnWidth(1, 160)  # Name
        self.rules_table.setColumnWidth(2, 300)  # Conditions (widest)
        self.rules_table.setColumnWidth(3, 80)   # Thr/Win
        self.rules_table.setColumnWidth(4, 130)  # Actions
        self.rules_table.setColumnWidth(5, 90)   # Cooldown
        self.rules_table.setColumnWidth(6, 44)   # On
        self.rules_table.setColumnWidth(7, 60)   # Edit
        self.rules_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rules_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.rules_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.rules_table.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.rules_table.setAlternatingRowColors(True)
        self.rules_table.cellDoubleClicked.connect(self._edit_rule_row)
        tl.addWidget(self.rules_table, 1)
        self.rules_table.viewport().setCursor(Qt.CursorShape.PointingHandCursor)

        btn_row = QHBoxLayout()
        btn_del  = QPushButton("DELETE SELECTED"); btn_del.setObjectName("danger"); btn_del.setFixedWidth(160)
        btn_edit = QPushButton("EDIT SELECTED");   btn_edit.setStyleSheet("background:#2e2e66;"); btn_edit.setFixedWidth(140)
        btn_del.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_edit.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_del.clicked.connect(self._delete_rule)
        btn_edit.clicked.connect(lambda: self._edit_rule_row(self.rules_table.currentRow(), 0))
        btn_row.addWidget(btn_edit); btn_row.addWidget(btn_del); btn_row.addStretch()
        tl.addLayout(btn_row)
        self.tabs.addTab(tab, "⚙️ Rule Engine")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_stat_card(self, title, value, color):
        card = QFrame(); card.setObjectName("Card"); card.setFixedSize(172, 96)
        vl = QVBoxLayout(card)
        vl.setContentsMargins(8, 8, 8, 8)
        vl.setSpacing(4)
        lbl_t = QLabel(title); lbl_t.setStyleSheet(f"font-size: 11px; color: {color};"); lbl_t.setAlignment(Qt.AlignmentFlag.AlignCenter); lbl_t.setWordWrap(True)
        lbl_v = QLabel(value); lbl_v.setStyleSheet(f"font-size: 26px; font-weight: bold; color: {color};"); lbl_v.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vl.addWidget(lbl_t); vl.addWidget(lbl_v)
        return card, lbl_v

    def _set_zoom(self, value):
        self.gui_zoom = max(8, min(18, int(value)))
        self._save_pref("gui_zoom", self.gui_zoom)
        self._apply_zoom()

    def _apply_zoom(self):
        font = QFont("Segoe UI", self.gui_zoom)
        for widget_name in ("table", "threat_table", "blocklist_table", "rules_table", "stats_table"):
            widget = getattr(self, widget_name, None)
            if widget:
                widget.setFont(font)
                widget.verticalHeader().setDefaultSectionSize(max(28, self.gui_zoom + 16))
        if hasattr(self, "detail_text"):
            self.detail_text.setFont(QFont("Consolas", self.gui_zoom))

    def _show_selected_alert_details(self):
        row = self.table.currentRow() if hasattr(self, "table") else -1
        if row < 0 or not hasattr(self, "detail_text"):
            return
        id_item  = self.table.item(row, 0)
        alert_id = id_item.data(Qt.ItemDataRole.UserRole) if id_item else None
        alert    = next((a for a in self._all_alerts if a.get("id") == alert_id), None)
        if not alert:
            return

        ip  = str(alert.get("source_ip", ""))
        sev = str(alert.get("severity", "LOW")).upper()
        with self._threat_lock:
            threat = self._threat_cache.get(ip, {})
        combined = max(
            int(alert.get("threat_score") or 0),
            int(alert.get("ai_score") or 0),
            int(threat.get("abuse_score") or 0),
        )

        sev_colors = {"CRITICAL": "#ff0000", "HIGH": "#ff4757", "MEDIUM": "#ffa502", "LOW": "#00ff88"}
        sev_bg     = {"CRITICAL": "#2e0000", "HIGH": "#2e1000", "MEDIUM": "#2e1e00", "LOW": "#002e10"}
        sc  = sev_colors.get(sev, "#ffffff")
        sbg = sev_bg.get(sev, "#1a1a2e")

        def e(s):
            return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

        def badge(text, color, bg):
            return (f'<span style="background:{bg};color:{color};padding:2px 8px;'
                    f'border-radius:4px;font-weight:bold;">{e(text)}</span>')

        def section(title, content_html, title_color="#00f2ff"):
            return (f'<div style="color:{title_color};font-size:10px;letter-spacing:1px;'
                    f'margin:6px 0 2px 0;">▶ {title}</div>'
                    f'<div style="padding-left:8px;margin-bottom:4px;">{content_html}</div>')

        # ── Fetch deepseek report (cache by ID — avoid repeated DB hits every 500ms) ──
        report = None
        if self.db_path and alert_id:
            if alert_id != self._last_report_id:
                # New selection: clear cache, will fetch below
                self._last_report_id = alert_id
                self._last_report    = None
            if self._last_report is None:
                try:
                    from core.ollama_reporter import get_report
                    fetched = get_report(self.db_path, alert_id)
                    if fetched:
                        self._last_report = fetched
                    report = fetched
                except Exception:
                    pass
            else:
                report = self._last_report

        # ── Build HTML ────────────────────────────────────────────────────────
        html = ['<div style="background:#0a0a1e;color:#fff;font-family:Consolas,monospace;font-size:11px;padding:6px;">']

        # Header strip
        status_color = {"Blocked":"#ff4757","Logged":"#74b9ff","Investigating":"#ffa502",
                        "Resolved":"#00ff88","Quarantined":"#fd79a8"}.get(alert.get("status","Logged"), "#aaa")
        html.append(
            f'<table width="100%" cellspacing="0" cellpadding="2" '
            f'style="border-bottom:1px solid #2e2e66;margin-bottom:6px;"><tr>'
            f'<td><span style="color:#888;font-size:10px;">ID&nbsp;</span>'
            f'<span style="color:#fff;font-weight:bold;">#{e(alert.get("id",""))}</span></td>'
            f'<td><span style="color:#888;font-size:10px;">TIME&nbsp;</span>'
            f'<span style="color:#aaa;">{e(str(alert.get("timestamp",""))[:19])}</span></td>'
            f'<td><span style="color:#888;font-size:10px;">FROM&nbsp;</span>'
            f'<span style="color:#74b9ff;font-weight:bold;">{e(ip)}</span></td>'
            f'<td align="right"><span style="color:{status_color};font-weight:bold;">'
            f'{e(alert.get("status",""))}</span></td>'
            f'</tr></table>'
        )

        # Event + severity badges + scores
        html.append(
            f'<div style="margin-bottom:8px;">'
            f'{badge(alert.get("event_type",""), sc, sbg)}&nbsp;&nbsp;'
            f'{badge(sev, sc, sbg)}&nbsp;&nbsp;'
            f'<span style="color:#888;font-size:10px;">Threat&nbsp;<b style="color:{sc};">{combined}</b>/100&nbsp;&nbsp;'
            f'AI&nbsp;<b style="color:#a29bfe;">{alert.get("ai_score",0)}</b>&nbsp;&nbsp;'
            f'VT&nbsp;<b style="color:#fd79a8;">{alert.get("vt_score",0)}</b>&nbsp;&nbsp;'
            f'Behavior&nbsp;<b style="color:#ffa502;">{alert.get("behavior_score",0)}</b></span>'
            f'</div>'
        )

        # ── DeepSeek report block ─────────────────────────────────────────────
        if report:
            conf      = int(report.get("confidence") or 0)
            conf_col  = "#00f2ff" if conf >= 80 else "#ffa502" if conf >= 50 else "#888"
            model_lbl = f'<span style="color:#555;font-size:10px;">{e(report.get("model",""))}&nbsp;·&nbsp;confidence&nbsp;<b style="color:{conf_col};">{conf}%</b></span>'

            summary_html = (
                f'<div style="background:#0d0d28;border-left:3px solid #6c5ce7;'
                f'padding:5px 8px;color:#e0e0e0;line-height:1.5;">'
                f'{e(report.get("attack_summary","No summary."))}</div>'
            )
            html.append(section(f"AI ANALYSIS  {model_lbl}", summary_html))

            if report.get("mitre_tactics") or report.get("mitre_techniques"):
                mitre_html = ""
                if report.get("mitre_tactics"):
                    tactics = " &nbsp;·&nbsp; ".join(
                        f'<span style="background:#1a1040;color:#a29bfe;padding:1px 6px;border-radius:3px;">{e(t.strip())}</span>'
                        for t in report["mitre_tactics"].split(";") if t.strip()
                    )
                    mitre_html += f'<div style="margin-bottom:3px;"><span style="color:#666;font-size:10px;">Tactics&nbsp;</span>{tactics}</div>'
                if report.get("mitre_techniques"):
                    techs = "<br>".join(
                        f'<span style="color:#a29bfe;">• {e(t.strip())}</span>'
                        for t in report["mitre_techniques"].split(";") if t.strip()
                    )
                    mitre_html += f'<div>{techs}</div>'
                html.append(section("MITRE ATT&amp;CK", mitre_html))

            # IOCs + Actions side by side
            ioc_items = [e(i.strip()) for i in (report.get("iocs") or "").split(";") if i.strip()]
            ioc_html  = "<br>".join(
                f'<span style="color:#ff4757;">⚑ {i}</span>' for i in ioc_items
            ) or '<span style="color:#555;">None identified</span>'

            action_items = [e(a.strip()) for a in (report.get("recommended_actions") or "").split(";") if a.strip()]
            act_html = "<br>".join(
                f'<span style="color:#00ff88;">• {a}</span>' for a in action_items
            ) or '<span style="color:#555;">No actions</span>'

            html.append(
                f'<table width="100%" cellspacing="0" cellpadding="0"><tr valign="top">'
                f'<td width="38%">{section("IOCs", ioc_html)}</td>'
                f'<td width="4px"></td>'
                f'<td>{section("RECOMMENDED ACTIONS", act_html)}</td>'
                f'</tr></table>'
            )

        else:
            # Heuristic summary while deepseek is generating
            heuristic = e(alert.get("ai_summary") or "No heuristic summary available.")
            html.append(section(
                "HEURISTIC ANALYSIS",
                f'<div style="background:#0d0d28;border-left:3px solid #2e2e66;'
                f'padding:5px 8px;color:#aaa;">{heuristic}</div>'
            ))

            beh = alert.get("behavior_alerts", "")
            if beh:
                beh_items = "<br>".join(
                    f'<span style="color:#ffa502;">⚡ {e(b.strip())}</span>'
                    for b in beh.split(";") if b.strip()
                )
                html.append(section("BEHAVIORAL ALERTS", beh_items))

            html.append(
                f'<div style="color:#555;font-size:10px;font-style:italic;margin-top:4px;">'
                f'⏳ AI report generating via deepseek-coder-v2:16b — updates automatically in ~30–60s</div>'
            )

        # ── Enrichment panel ──────────────────────────────────────────────────
        enrich_parts = []

        # VT file hash
        if alert.get("vt_hash"):
            vt_html = f'<span style="color:#fd79a8;">hash: {e(alert["vt_hash"])}</span>'
            if alert.get("vt_link"):
                vt_html += f'&nbsp;&nbsp;<a href="{e(alert["vt_link"])}" style="color:#6c5ce7;">VT ↗</a>'
            if alert.get("vt_score", 0):
                vt_html = f'<b style="color:#ff4757;">{alert["vt_score"]}/100</b>&nbsp;&nbsp;' + vt_html
            enrich_parts.append(("VIRUSTOTAL FILE", "#fd79a8", vt_html))

        # VT URL/domain
        if alert.get("vt_url_score", 0):
            vt_url_html = f'<b style="color:#ff4757;">{alert["vt_url_score"]}/100</b>'
            if alert.get("vt_url_link"):
                vt_url_html += f'&nbsp;&nbsp;<a href="{e(alert["vt_url_link"])}" style="color:#6c5ce7;">VT ↗</a>'
            enrich_parts.append(("VIRUSTOTAL URL/DOMAIN", "#fd79a8", vt_url_html))

        # Shodan
        if alert.get("shodan_score", 0) or alert.get("shodan_ports") or alert.get("shodan_vulns"):
            sh_score = alert.get("shodan_score", 0)
            col = "#ff4757" if sh_score >= 50 else "#ffa502" if sh_score >= 20 else "#74b9ff"
            ports = e(alert.get("shodan_ports", "") or "none")
            vulns = e(alert.get("shodan_vulns", "") or "none")
            sh_html = (
                f'<b style="color:{col};">score: {sh_score}/100</b>'
                f'&nbsp;&nbsp;<span style="color:#888;">open ports:</span> '
                f'<span style="color:#74b9ff;">{ports[:80]}</span>'
            )
            if alert.get("shodan_vulns"):
                sh_html += (
                    f'<br><span style="color:#888;">CVEs:</span> '
                    f'<span style="color:#ff4757;">{vulns[:120]}</span>'
                )
            enrich_parts.append(("SHODAN", col, sh_html))

        # GreyNoise
        if alert.get("greynoise_score", 0) or alert.get("greynoise_classification"):
            gn_class = (alert.get("greynoise_classification") or "unknown").upper()
            gn_score = alert.get("greynoise_score", 0)
            gn_col   = {"MALICIOUS": "#ff0000", "BENIGN": "#00ff88"}.get(gn_class, "#ffa502")
            gn_html  = (
                f'<b style="color:{gn_col};">{gn_class}</b>'
                f'&nbsp;&nbsp;<span style="color:#888;">score: {gn_score}/100</span>'
            )
            if gn_class == "BENIGN":
                gn_html += '&nbsp;&nbsp;<span style="color:#555;">(known benign infrastructure)</span>'
            enrich_parts.append(("GREYNOISE", gn_col, gn_html))

        # URLScan
        if alert.get("urlscan_score", 0) or alert.get("urlscan_verdict"):
            us_verdict = (alert.get("urlscan_verdict") or "unknown").upper()
            us_score   = alert.get("urlscan_score", 0)
            us_col     = "#ff4757" if us_verdict == "MALICIOUS" else "#00ff88" if us_verdict == "CLEAN" else "#ffa502"
            us_html    = f'<b style="color:{us_col};">{us_verdict}</b>&nbsp;&nbsp;<span style="color:#888;">score: {us_score}/100</span>'
            if alert.get("urlscan_link"):
                us_html += f'&nbsp;&nbsp;<a href="{e(alert["urlscan_link"])}" style="color:#6c5ce7;">Report ↗</a>'
            enrich_parts.append(("URLSCAN.IO SANDBOX", us_col, us_html))

        if enrich_parts:
            enrich_rows = "".join(
                f'<tr><td style="color:{tc};font-size:9px;letter-spacing:1px;'
                f'padding:3px 8px 3px 0;white-space:nowrap;vertical-align:top;">'
                f'▶ {title}</td>'
                f'<td style="padding:3px 0 3px 8px;">{content}</td></tr>'
                for title, tc, content in enrich_parts
            )
            html.append(
                f'<div style="background:#0c0c22;border:1px solid #2e2e66;border-radius:4px;'
                f'padding:6px 8px;margin:6px 0;">'
                f'<div style="color:#00f2ff;font-size:9px;letter-spacing:2px;margin-bottom:4px;">'
                f'THREAT ENRICHMENT</div>'
                f'<table width="100%" cellspacing="0" cellpadding="0">{enrich_rows}</table>'
                f'</div>'
            )
        elif any(k in alert for k in ("shodan_score","greynoise_score","urlscan_score","vt_url_score")):
            html.append(
                f'<div style="color:#333;font-size:10px;font-style:italic;margin:4px 0;">'
                f'⏳ Enrichment pending (Shodan / GreyNoise / URLScan) — updates automatically</div>'
            )

        # Raw log — always at the bottom
        raw = e(str(alert.get("raw_log") or "Raw log not stored for this incident."))
        html.append(
            f'<div style="color:#00f2ff;font-size:10px;letter-spacing:1px;margin:6px 0 2px 0;">▶ RAW LOG</div>'
            f'<div style="background:#080816;color:#555;font-size:10px;padding:4px 8px;'
            f'border-radius:4px;word-break:break-all;">{raw}</div>'
        )

        html.append('</div>')
        self.detail_text.setHtml("".join(html))

    def closeEvent(self, event):
        if hasattr(self, "alert_splitter"):
            self._save_pref("alert_split_sizes", self.alert_splitter.sizes())
        self._save_pref("gui_zoom", self.gui_zoom)
        super().closeEvent(event)

    # ══════════════════════════════════════════════════════════════════════════
    # SOC ASSIST — AI Chatbot Tab
    # ══════════════════════════════════════════════════════════════════════════

    def _build_tab_chat(self):
        self._chat_history  = []
        self._chat_typing   = False
        self._chat_reply_sig.connect(self._on_chat_reply)
        self._pdf_done_sig.connect(self._on_pdf_sig)

        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.setContentsMargins(8, 8, 8, 8)
        tl.setSpacing(8)

        # ── Header ────────────────────────────────────────────────────────────
        hdr = QHBoxLayout()
        lbl_title = QLabel("SOC ASSIST")
        lbl_title.setStyleSheet(
            "font-size:13px;color:#00f2ff;font-weight:bold;letter-spacing:1px;")
        model_name = os.getenv("OLLAMA_MODEL", "llama3.1")
        lbl_model = QLabel(f"powered by {model_name}")
        lbl_model.setStyleSheet("font-size:10px;color:#555580;padding-left:8px;")
        btn_clear = QPushButton("Clear Chat")
        btn_clear.setObjectName("danger")
        btn_clear.setFixedWidth(90)
        btn_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_clear.clicked.connect(self._chat_clear)
        hdr.addWidget(lbl_title)
        hdr.addWidget(lbl_model)
        hdr.addStretch()
        hdr.addWidget(btn_clear)
        tl.addLayout(hdr)

        # ── Splitter: chat area (left) + sidebar (right) ──────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left: chat history + input ────────────────────────────────────────
        chat_frame = QFrame(); chat_frame.setObjectName("Card")
        cv = QVBoxLayout(chat_frame)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.setSpacing(0)

        self._chat_browser = QTextBrowser()
        self._chat_browser.setObjectName("chat_browser")
        self._chat_browser.setOpenExternalLinks(False)
        self._chat_browser.setReadOnly(True)
        cv.addWidget(self._chat_browser, 1)

        self._chat_typing_lbl = QLabel("  SOC Assist is thinking...")
        self._chat_typing_lbl.setStyleSheet(
            "color:#555580;font-size:11px;padding:4px 14px;font-style:italic;")
        self._chat_typing_lbl.hide()
        cv.addWidget(self._chat_typing_lbl)

        inp_row = QHBoxLayout()
        inp_row.setContentsMargins(8, 6, 8, 8)
        inp_row.setSpacing(8)
        self._chat_input = QLineEdit()
        self._chat_input.setPlaceholderText(
            "Ask about the application, an incident, a log, or a threat...")
        self._chat_input.setMinimumHeight(36)
        self._chat_input.returnPressed.connect(self._chat_send)
        self._chat_send_btn = QPushButton("SEND")
        self._chat_send_btn.setFixedWidth(80)
        self._chat_send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._chat_send_btn.clicked.connect(self._chat_send)
        inp_row.addWidget(self._chat_input)
        inp_row.addWidget(self._chat_send_btn)
        cv.addLayout(inp_row)

        splitter.addWidget(chat_frame)

        # ── Right: sidebar ────────────────────────────────────────────────────
        sidebar = QFrame(); sidebar.setObjectName("Card")
        sv = QVBoxLayout(sidebar)
        sv.setContentsMargins(10, 10, 10, 10)
        sv.setSpacing(5)

        def _sidebar_section(text):
            lbl = QLabel(text)
            lbl.setStyleSheet(
                "font-size:11px;color:#00f2ff;font-weight:bold;letter-spacing:1px;"
                "padding-top:4px;")
            sv.addWidget(lbl)

        _sidebar_section("QUICK ACTIONS")
        for label, key in _CHAT_QUICK_ACTIONS:
            b = QPushButton(label)
            b.setObjectName("chat_quick")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _, k=key: self._chat_quick(k))
            sv.addWidget(b)

        sv.addSpacing(4)
        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background:#2e2e66;max-height:1px;")
        sv.addWidget(div)
        sv.addSpacing(4)

        _sidebar_section("PLAYBOOKS")
        for label, key in _CHAT_PLAYBOOKS:
            b = QPushButton(label)
            b.setObjectName("chat_quick")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _, k=key: self._chat_quick(k))
            sv.addWidget(b)

        sv.addSpacing(4)
        div2 = QFrame(); div2.setFrameShape(QFrame.Shape.HLine)
        div2.setStyleSheet("background:#2e2e66;max-height:1px;")
        sv.addWidget(div2)
        sv.addSpacing(4)

        _sidebar_section("SELECTED INCIDENT")
        self._chat_ctx_lbl = QLabel("No incident selected.\nSelect a row in\nLive Alerts tab.")
        self._chat_ctx_lbl.setStyleSheet(
            "color:#555580;font-size:10px;line-height:1.6;padding-top:2px;")
        self._chat_ctx_lbl.setWordWrap(True)
        sv.addWidget(self._chat_ctx_lbl)

        sv.addStretch()
        sidebar.setMinimumWidth(170)
        sidebar.setMaximumWidth(230)
        splitter.addWidget(sidebar)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 1)
        tl.addWidget(splitter, 1)

        self.tabs.addTab(tab, "SOC Assist")

        # Welcome message
        self._chat_history.append({"role": "assistant", "content": (
            "Hello. I'm **SOC Assist** — your AI analyst companion.\n\n"
            "I can help you:\n"
            "- **Navigate** this application (blocklist, rule engine, AI reports)\n"
            "- **Triage** incidents — should I block? what does this score mean?\n"
            "- **Interpret** raw logs and enrichment data\n"
            "- **Suggest** detection rules and response playbooks\n\n"
            "Select an incident in **Live Alerts** and click **Analyze Selected Incident** "
            "to start, or type any question below."
        )})
        self._chat_render()

    # ── Chat helpers ──────────────────────────────────────────────────────────

    def _chat_render(self):
        import re as _re

        def _esc(s):
            return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

        def _md(text):
            # Escape HTML in the full input first — neutralizes any injected tags
            # from attacker-controlled log content before we apply markdown patterns.
            # Backticks, asterisks, and MITRE T-numbers are unaffected by HTML escaping.
            text = _esc(text)
            # fenced code blocks (content already escaped)
            text = _re.sub(
                r'```[^\n]*\n?(.*?)```',
                lambda m: (
                    '<pre style="background:#0d0d28;border:1px solid #2e2e66;'
                    'border-radius:4px;padding:7px 10px;font-size:11px;'
                    'white-space:pre-wrap;margin:4px 0;">'
                    + m.group(1) + '</pre>'),
                text, flags=_re.DOTALL)
            # inline code (content already escaped)
            text = _re.sub(
                r'`([^`]+)`',
                lambda m: (
                    '<code style="background:#0d0d28;color:#00f2ff;'
                    'padding:1px 5px;border-radius:3px;font-size:11px;">'
                    + m.group(1) + '</code>'),
                text)
            # bold (content already escaped)
            text = _re.sub(r'\*\*(.+?)\*\*',
                           lambda m: '<strong style="color:#a29bfe;">' + m.group(1) + '</strong>',
                           text)
            # bullet lines (content already escaped)
            text = _re.sub(r'^[-•] (.+)$',
                           lambda m: '<span style="color:#555580;">&#x25B8;</span> ' + m.group(1),
                           text, flags=_re.MULTILINE)
            # MITRE technique IDs (safe alphanumeric pattern — no user data in capture group)
            text = _re.sub(r'\b(T\d{4}(?:\.\d{3})?)\b',
                           lambda m: '<span style="color:#fd79a8;">' + m.group(1) + '</span>',
                           text)
            # severity words (safe fixed strings — no user data)
            for word, col in (("CRITICAL","#ff4757"),("HIGH","#ffa502"),
                               ("MEDIUM","#f9ca24"),("LOW","#00ff88")):
                text = text.replace(word,
                    f'<span style="color:{col};font-weight:bold;">{word}</span>')
            text = text.replace("\n", "<br>")
            return text

        parts = [
            '<html><head><meta charset="utf-8"><style>'
            'body{margin:0;padding:8px 6px;background:#0b0b1a;}'
            '</style></head><body>'
        ]
        for msg in self._chat_history:
            role    = msg["role"]
            content = _md(msg.get("content",""))
            if role == "user":
                parts.append(
                    '<div style="margin:10px 0 10px 40px;text-align:right;">'
                    '<div style="font-size:10px;color:#6c5ce7;margin-bottom:3px;">'
                    'YOU</div>'
                    '<div style="display:inline-block;max-width:82%;background:#26184a;'
                    'border:1px solid #6c5ce7;border-radius:12px 12px 2px 12px;'
                    'padding:10px 14px;color:#e0d8ff;font-size:12px;'
                    'text-align:left;word-wrap:break-word;line-height:1.6;">'
                    f'{content}</div></div>')
            else:
                parts.append(
                    '<div style="margin:10px 40px 10px 0;">'
                    '<div style="font-size:10px;color:#00f2ff;margin-bottom:3px;'
                    'letter-spacing:1px;">SOC ASSIST</div>'
                    '<div style="max-width:90%;background:#131328;'
                    'border:1px solid #2e2e66;border-radius:12px 12px 12px 2px;'
                    'padding:10px 14px;color:#d0d0f0;font-size:12px;'
                    'word-wrap:break-word;line-height:1.6;">'
                    f'{content}</div></div>')
        parts.append("</body></html>")

        self._chat_browser.setHtml("".join(parts))
        sb = self._chat_browser.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _chat_send(self):
        text = self._chat_input.text().strip()
        if not text or self._chat_typing:
            return
        self._chat_input.clear()
        self._chat_history.append({"role": "user", "content": text})
        self._chat_render()
        self._chat_call_ollama()

    def _chat_call_ollama(self):
        self._chat_typing = True
        self._chat_typing_lbl.show()
        self._chat_send_btn.setEnabled(False)
        self._chat_input.setEnabled(False)

        messages = [{"role": "system", "content": _CHAT_SYSTEM}]
        for m in self._chat_history[-24:]:   # keep last 24 turns in context
            messages.append({"role": m["role"], "content": m["content"]})

        sig = self._chat_reply_sig

        def _worker():
            try:
                url   = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
                model = os.getenv("OLLAMA_MODEL", "llama3.1")
                resp  = requests.post(
                    f"{url}/api/chat",
                    json={"model": model, "messages": messages, "stream": False},
                    timeout=120)
                data    = resp.json()
                content = (data.get("message") or {}).get("content")
                if not content:
                    err = data.get("error", "")
                    if err:
                        content = f"Ollama error: {err}"
                        if "not found" in err or "pull" in err:
                            content += f"\n\nFix: run  ollama pull {model}"
                    else:
                        content = f"No content in Ollama response (HTTP {resp.status_code})."
            except Exception as exc:
                content = (
                    f"Could not reach Ollama: {exc}\n\n"
                    "Make sure Ollama is running: `ollama serve`")
            sig.emit(content)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_chat_reply(self, text):
        self._chat_typing = False
        self._chat_typing_lbl.hide()
        self._chat_send_btn.setEnabled(True)
        self._chat_input.setEnabled(True)
        self._chat_history.append({"role": "assistant", "content": text})
        self._chat_render()
        self._chat_input.setFocus()

    def _chat_clear(self):
        self._chat_history.clear()
        self._chat_render()

    def _chat_get_incident_ctx(self):
        """Return (context_string, label_text) for the selected incident, or (None, None)."""
        if not hasattr(self, "table"):
            return None, None
        row = self.table.currentRow()
        if row < 0:
            return None, None
        id_item  = self.table.item(row, 0)
        alert_id = id_item.data(Qt.ItemDataRole.UserRole) if id_item else None
        alert    = next((a for a in self._all_alerts if a.get("id") == alert_id), None)
        if not alert:
            return None, None

        ip  = str(alert.get("source_ip","?"))
        sev = str(alert.get("severity","?"))
        evt = str(alert.get("event_type","?"))
        ts  = str(alert.get("threat_score") or 0)
        bs  = str(alert.get("behavior_score") or 0)
        vts = str(alert.get("vt_score") or 0)
        raw = str(alert.get("raw_log",""))[:500]

        ctx = (
            f"INCIDENT #{alert.get('id','?')} | "
            f"{str(alert.get('timestamp','?'))[:19]}\n"
            f"Source IP: {ip} | Severity: {sev} | Status: {alert.get('status','?')}\n"
            f"Event Type: {evt}\n"
            f"Threat Score: {ts} | Behavior Score: {bs} | VT Score: {vts}\n"
            f"Shodan/Enrich: {alert.get('enrich_summary','none')}\n"
            f"Raw Log: {raw}"
        )
        label = (
            f"#{alert.get('id','?')} — {evt}\n"
            f"IP: {ip}\n"
            f"Severity: {sev}  Score: {ts}"
        )
        return ctx, label

    def _chat_update_ctx_label(self):
        """Called on each timer tick to keep sidebar context label fresh."""
        if not hasattr(self, "_chat_ctx_lbl"):
            return
        _, label = self._chat_get_incident_ctx()
        self._chat_ctx_lbl.setText(
            label if label else "No incident selected.\nSelect a row in\nLive Alerts tab.")

    def _chat_quick(self, action_key):
        if self._chat_typing:
            return
        ctx, _ = self._chat_get_incident_ctx()
        no_sel = "No incident is selected. Please click a row in the **Live Alerts** tab first."

        def _prompt():
            if action_key == "shift_summary":
                return self._chat_shift_summary()
            if action_key == "analyze_selected":
                return (f"{ctx}\n\nAnalyze this incident. What is happening, what is the "
                        f"threat level, and what should I do next?") if ctx else no_sel
            if action_key == "block_decision":
                return (f"{ctx}\n\nShould I block this source IP? Give a structured "
                        f"recommendation: Severity, Confidence, Recommended Action, Rationale."
                        ) if ctx else no_sel
            if action_key == "explain_log":
                return (f"{ctx}\n\nExplain what this log entry means and what the attacker "
                        f"is attempting to do.") if ctx else no_sel
            if action_key == "suggest_rule":
                return (f"{ctx}\n\nSuggest a detection rule for this attack pattern using "
                        f"the Rule Engine v2 format (field / operator / value conditions, "
                        f"AND or OR logic, recommended actions and cooldown).") if ctx else no_sel
            if action_key == "mitre_map":
                return (f"{ctx}\n\nMap this incident to MITRE ATT&CK. List relevant "
                        f"technique IDs and names.") if ctx else no_sel
            if action_key == "playbook_bruteforce":
                return ("Give me a step-by-step response playbook for a brute force attack "
                        "detected in SOC SIEM PRO. Include specific tab names and UI actions.")
            if action_key == "playbook_c2":
                return ("Give me a step-by-step response playbook for a C2 communication or "
                        "beaconing detection. Include specific tab names and UI actions.")
            if action_key == "playbook_portscan":
                return ("Give me a step-by-step response playbook for a port scan detection. "
                        "Include specific tab names and UI actions.")
            if action_key == "playbook_ddos":
                return ("Give me a step-by-step response playbook for a DDoS attack detection. "
                        "Include specific tab names and UI actions.")
            return None

        msg = _prompt()
        if not msg:
            return
        self._chat_history.append({"role": "user", "content": msg})
        self._chat_render()
        self._chat_call_ollama()

    def _chat_shift_summary(self):
        now    = datetime.now()
        cutoff = now - timedelta(hours=8)
        recent = [a for a in self._all_alerts
                  if str(a.get("timestamp","")) >= cutoff.strftime("%Y-%m-%d %H:%M")]
        if not recent:
            return ("No incidents in the last 8 hours. "
                    "Provide a brief all-clear shift handover note.")
        sev_counts  = Counter(a.get("severity","?")    for a in recent)
        type_counts = Counter(a.get("event_type","?")  for a in recent)
        high_risk   = [a for a in recent if int(a.get("threat_score") or 0) >= 70]
        blocked     = [a for a in recent if a.get("status") == "Blocked"]
        unresolved  = [a for a in recent if a.get("status") not in
                       ("Resolved","False Positive","Blocked")]
        return (
            f"SHIFT SUMMARY REQUEST — {now.strftime('%Y-%m-%d %H:%M')}\n"
            f"Period: last 8 hours\n"
            f"Total incidents: {len(recent)}\n"
            f"Severity breakdown: {dict(sev_counts)}\n"
            f"Top event types: {dict(type_counts.most_common(5))}\n"
            f"High-threat incidents (score ≥ 70): {len(high_risk)}\n"
            f"Auto-blocked IPs this shift: {len(blocked)}\n"
            f"Unresolved incidents: {len(unresolved)}\n\n"
            "Please write a structured shift handover brief. "
            "Highlight critical items requiring immediate follow-up."
        )

    def _on_action_taken(self, ip, action_str):
        self.lbl_action.setText(f"⚡ {action_str}  [{ip}]")
        QTimer.singleShot(5000, lambda: self.lbl_action.setText(""))
        self._refresh_blocklist_tab()

    def open_settings(self):
        dlg = SettingsDialog(self, self.settings, self.db_path)
        if dlg.exec():
            self.settings = dlg.get_settings()
            self.timer.setInterval(self.settings["refresh"])
            new_email_cfg = dlg.get_email_cfg()
            self.email_cfg = new_email_cfg
            if self.db_path:
                save_email_config(self.db_path, new_email_cfg)
            QMessageBox.information(self, "Settings", "Settings saved!")

    # ── Data Fetching ─────────────────────────────────────────────────────────

    def _api_headers(self):
        return {"X-API-Key": self._api_key} if self._api_key else {}

    def fetch_data(self):
        try:
            limit = self.settings.get("limit", 50)
            url   = f"http://{self.settings['host']}:{self.settings['port']}/incidents?limit={limit}"
            r = requests.get(url, headers=self._api_headers(), timeout=1)
            if r.status_code == 200:
                data = r.json()
                if data:
                    self.process_incoming_alerts(data)
        except Exception as e:
            print(f"[GUI FETCH ERROR] {e}")

    def geolocate_ip(self, ip):
        with self._geo_lock:
            if ip in self._geo_cache:
                return
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    with self._geo_lock:
                        self._geo_cache[ip] = {"country": d.get("country","Unknown"), "lat": d.get("lat",0), "lng": d.get("lon",0)}
                    return
        except:
            pass
        with self._geo_lock:
            self._geo_cache[ip] = {"country": "Unknown", "lat": 0, "lng": 0}

    # ── Threat Intel ──────────────────────────────────────────────────────────

    def _enrich_ip(self, ip):
        with self._threat_lock:
            already = ip in self._threat_cache
        if already:
            return
        def _cb(result):
            with self._threat_lock:
                self._threat_cache[ip] = result
            self._threat_ready.emit(ip)
            if self.db_path:
                threading.Thread(
                    target=self._run_rules,
                    args=(ip, "threat_check", "LOW", "", result.get("abuse_score", 0), 0, 0, 0.0),
                    daemon=True
                ).start()
        get_threat_score_async(self.db_path, ip, _cb)

    def _on_threat_ready(self, ip):
        self.filter_table()
        self._refresh_threat_tab()

    def _refresh_threat_tab(self):
        with self._threat_lock:
            snapshot = dict(self._threat_cache)
        alert_scores = {}
        for alert in self._all_alerts:
            ip = str(alert.get("source_ip", ""))
            if not ip: continue
            current = alert_scores.get(ip, {"threat_score": 0, "ai_score": 0, "ai_summary": ""})
            current["threat_score"] = max(current["threat_score"], int(alert.get("threat_score") or 0))
            current["ai_score"]     = max(current["ai_score"],     int(alert.get("ai_score") or 0))
            if alert.get("ai_summary"):
                current["ai_summary"] = str(alert.get("ai_summary"))
            alert_scores[ip] = current
        ips  = set(snapshot.keys()) | set(alert_scores.keys())
        rows = []
        for ip in ips:
            intel  = snapshot.get(ip, {"ip": ip})
            scores = alert_scores.get(ip, {})
            abuse  = int(intel.get("abuse_score") or 0)
            combined = max(abuse, int(scores.get("threat_score") or 0), int(scores.get("ai_score") or 0))
            row = dict(intel); row.update(scores); row["combined_score"] = combined
            rows.append(row)
        rows = sorted(rows, key=lambda x: x.get("combined_score", 0), reverse=True)
        self.threat_table.clearContents(); self.threat_table.setRowCount(len(rows))
        malicious = 0
        for i, info in enumerate(rows):
            score    = int(info.get("combined_score", 0))
            ai_score = int(info.get("ai_score") or 0)
            abuse    = int(info.get("abuse_score") or 0)
            label, color = score_to_label(score)
            if score >= 25: malicious += 1
            items = [
                QTableWidgetItem(info.get("ip","")),
                QTableWidgetItem(str(score)),
                QTableWidgetItem(str(ai_score)),
                QTableWidgetItem(str(abuse)),
                QTableWidgetItem(label),
                QTableWidgetItem(info.get("country","Unknown")),
                QTableWidgetItem(info.get("isp","Unknown")),
                QTableWidgetItem(str(info.get("ai_summary",""))[:180]),
            ]
            for j, item in enumerate(items):
                item.setForeground(QColor(color))
                self.threat_table.setItem(i, j, item)
        self.lbl_threats.setText(str(malicious))

    # ── Rule Engine v2 ────────────────────────────────────────────────────────

    def _run_rules(self, ip, event_type, severity, category,
                   threat_score, behavior_score, vt_score, anomaly_score):
        if not self.db_path:
            return
        actions = evaluate_rules_v2(
            self.db_path, ip, event_type, severity, category,
            threat_score, behavior_score, vt_score, anomaly_score,
            "", self.email_cfg,
        )
        for action in actions:
            self._action_signal.emit(ip, action)

    def _new_rule(self):
        dlg = RuleBuilderDialog(self)
        if dlg.exec():
            add_rule_v2(self.db_path, dlg.get_data())
            self._refresh_rules_tab()

    def _edit_rule_row(self, row, _col=0):
        if row < 0 or row >= len(getattr(self, "_rules_data", [])):
            return
        rule = self._rules_data[row]
        dlg  = RuleBuilderDialog(self, rule=rule)
        if dlg.exec():
            update_rule_v2(self.db_path, rule["id"], dlg.get_data())
            self._refresh_rules_tab()

    def _delete_rule(self):
        rows = {idx.row() for idx in self.rules_table.selectedIndexes()}
        if not rows:
            QMessageBox.warning(self, "Error", "Select a rule row first."); return
        for row in sorted(rows, reverse=True):
            if row < len(getattr(self, "_rules_data", [])):
                delete_rule_v2(self.db_path, self._rules_data[row]["id"])
        self._refresh_rules_tab()

    def _refresh_rules_tab(self):
        if not self.db_path:
            return
        rules = get_rules_v2(self.db_path)
        self._rules_data = rules

        # Remember which rule IDs were selected so we can restore after rebuild
        selected_ids = set()
        for idx in self.rules_table.selectedIndexes():
            row = idx.row()
            if row < len(self._rules_data):
                selected_ids.add(self._rules_data[row].get("id"))

        self.rules_table.clearContents()
        self.rules_table.setRowCount(len(rules))

        act_icons = {"action_block": "🚫", "action_email": "📧",
                     "action_quarantine": "🔒", "action_escalate": "⬆"}

        for i, r in enumerate(rules):
            try:
                conds = json.loads(r.get("conditions", "[]"))
                mode  = r.get("condition_mode", "AND")
                sep   = f" {mode} "
                cond_txt = sep.join(
                    f"{c['field']} {c['op']} {c['value']}" for c in conds
                ) or "(any)"
            except Exception:
                cond_txt = r.get("conditions", "")[:60]

            acts = " ".join(v for k, v in act_icons.items() if r.get(k))
            if r.get("action_webhook"):
                acts += " 🌐"

            cells = [
                str(r["priority"]),
                r["name"],
                cond_txt,
                f"{r['threshold']} / {r['window_sec']}s",
                acts or "—",
                f"{r['cooldown_sec']}s",
            ]
            pri_col = "#ff4757" if r["priority"] <= 20 else \
                      "#ffa502" if r["priority"] <= 50 else "#74b9ff"

            for j, val in enumerate(cells):
                item = QTableWidgetItem(val)
                item.setForeground(QColor(pri_col if j == 0 else
                                          "#00f2ff" if j == 1 else "#cccccc"))
                self.rules_table.setItem(i, j, item)

            chk = QCheckBox(); chk.setChecked(bool(r["enabled"]))
            rule_id = r["id"]
            chk.stateChanged.connect(
                lambda state, rid=rule_id: toggle_rule_v2(self.db_path, rid, bool(state))
            )
            self.rules_table.setCellWidget(i, 6, chk)

            btn = QPushButton("Edit")
            btn.setStyleSheet("background:#2e2e66; padding:2px 6px; font-size:10px;")
            btn.clicked.connect(lambda _, row=i: self._edit_rule_row(row))
            self.rules_table.setCellWidget(i, 7, btn)

        # Restore selection
        if selected_ids:
            self.rules_table.blockSignals(True)
            for i, r in enumerate(rules):
                if r.get("id") in selected_ids:
                    self.rules_table.selectRow(i)
            self.rules_table.blockSignals(False)

        self.rules_table.resizeColumnsToContents()
        self.rules_table.setColumnWidth(2, max(self.rules_table.columnWidth(2), 240))  # Conditions min width

    # ── Blocklist ─────────────────────────────────────────────────────────────

    def _validate_ip(self, ip: str) -> str:
        """Return empty string if valid, error message if invalid."""
        ip = ip.strip()
        if not ip:
            return "Enter an IP address."
        try:
            ipaddress.ip_address(ip)
            return ""
        except ValueError:
            return f"'{ip}' is not a valid IP address."

    def _manual_block(self):
        ip     = self.inp_block_ip.text().strip()
        reason = self.inp_block_reason.text().strip() or "Manual block"
        err    = self._validate_ip(ip)
        if err:
            self.lbl_block_err.setText(f"⚠ {err}")
            return
        self.lbl_block_err.setText("")
        block_ip(self.db_path, ip, reason)
        self.inp_block_ip.clear()
        self.inp_block_reason.clear()
        self._refresh_blocklist_tab()

    def _manual_unblock(self):
        selected_rows = {idx.row() for idx in self.blocklist_table.selectedIndexes()}
        if not selected_rows:
            QMessageBox.warning(self, "Unblock", "Select one or more rows first."); return
        for row in selected_rows:
            ip_item = self.blocklist_table.item(row, 0)
            if ip_item:
                unblock_ip(self.db_path, ip_item.text())
        self._refresh_blocklist_tab()

    def _refresh_blocklist_tab(self):
        if not self.db_path:
            return
        bl = get_blocklist(self.db_path)

        # Remember selected IPs before rebuilding
        selected_ips = set()
        for idx in self.blocklist_table.selectedIndexes():
            item = self.blocklist_table.item(idx.row(), 0)
            if item:
                selected_ips.add(item.text())

        self.blocklist_table.clearContents()
        self.blocklist_table.setRowCount(len(bl))
        for i, entry in enumerate(bl):
            for j, val in enumerate([
                entry.get("ip", ""),
                entry.get("reason", ""),
                str(entry.get("added_at", ""))[:19],
            ]):
                item = QTableWidgetItem(val)
                item.setForeground(QColor("#ff4757" if j == 0 else "#cccccc"))
                self.blocklist_table.setItem(i, j, item)

        # Restore selection
        if selected_ips:
            self.blocklist_table.blockSignals(True)
            for i, entry in enumerate(bl):
                if entry.get("ip") in selected_ips:
                    self.blocklist_table.selectRow(i)
            self.blocklist_table.blockSignals(False)

        self.lbl_blocked.setText(str(len(bl)))

    # ── Alert Processing ──────────────────────────────────────────────────────

    def process_incoming_alerts(self, data):
        self._all_alerts = data
        try:
            previous_ids  = set(self._prev_ids)
            new_ids       = {a.get("id") for a in data}
            new_criticals = [a for a in data if a.get("id") not in previous_ids
                             and str(a.get("severity","")).upper() == "CRITICAL"]
            if new_criticals and HAS_SOUND:
                threading.Thread(target=lambda: winsound.Beep(1000, 400), daemon=True).start()

            self.lbl_total.setText(str(len(data)))
            counts = Counter(str(a.get("event_type","")).upper() for a in data)
            for name, lbl in self.event_type_labels.items():
                lbl.setText(str(sum(1 for a in data if str(a.get("severity","")).upper()=="CRITICAL") if name=="CRITICAL" else counts.get(name,0)))

            has_critical = any(str(a.get("severity","")).upper() in ("CRITICAL","HIGH") for a in data)
            if has_critical:
                self.lbl_risk.setText("CRITICAL"); self.lbl_risk.setStyleSheet("font-size: 26px; color: #ff4757; font-weight: bold;")
            else:
                self.lbl_risk.setText("NORMAL");   self.lbl_risk.setStyleSheet("font-size: 26px; color: #00ff88; font-weight: bold;")

            self.trend_points.append(len(data))
            if len(self.trend_points) > 20: self.trend_points.pop(0)
            self.curve.setData(self.trend_points)

            sev_rank = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
            for alert in data:
                ip    = str(alert.get("source_ip","0.0.0.0"))
                sev   = str(alert.get("severity","LOW")).upper()
                etype = str(alert.get("event_type","System Event"))
                if ip == "0.0.0.0": continue
                self._all_ips.add(ip)
                if sev_rank.get(sev,0) > sev_rank.get(self._ip_severity.get(ip,"LOW"),0):
                    self._ip_severity[ip] = sev
                with self._geo_lock:
                    if ip not in self._geo_cache:
                        self._bg_pool.submit(self.geolocate_ip, ip)
                with self._threat_lock:
                    threat_missing = ip not in self._threat_cache
                if threat_missing:
                    self._bg_pool.submit(self._enrich_ip, ip)
                if alert.get("id") not in previous_ids and self.db_path:
                    self._bg_pool.submit(
                        self._run_rules,
                        ip, etype, sev,
                        str(alert.get("category", "")),
                        int(alert.get("threat_score") or 0),
                        int(alert.get("behavior_score") or 0),
                        int(alert.get("vt_score") or 0),
                        float(alert.get("anomaly_score") or 0),
                    )

            self._prev_ids = new_ids
            self.filter_table()
            self._refresh_threat_tab()
            self.update_stats_tab(data)
            self.update_timeline(data)
            self._refresh_reports_tab()
            self._refresh_blocklist_tab()
            self._refresh_rules_tab()
            self._show_selected_alert_details()  # re-render if deepseek report arrived
            self._chat_update_ctx_label()         # keep sidebar incident context fresh

        except Exception as e:
            print(f"!!! PROCESS ERROR: {e}")

    # ── Table ─────────────────────────────────────────────────────────────────

    def show_status_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0: return
        id_item = self.table.item(row, 0)
        if not id_item: return
        alert_id = id_item.data(Qt.ItemDataRole.UserRole)
        if not alert_id: return
        ip_item = self.table.item(row, 1)
        ip_val  = ip_item.text() if ip_item else ""
        menu = QMenu(self)
        for status in ["Logged","Investigating","Resolved","False Positive"]:
            action = menu.addAction(status)
            action.triggered.connect(lambda checked, s=status, aid=alert_id: self.set_status(aid, s))
        menu.addSeparator()
        block_action = menu.addAction("🚫 Block this IP")
        block_action.triggered.connect(lambda: self._quick_block(ip_val))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _quick_block(self, ip):
        if ip and self.db_path:
            block_ip(self.db_path, ip, "Manual block from alert table")
            self._refresh_blocklist_tab()
            self.lbl_action.setText(f"🚫 Blocked {ip}")
            QTimer.singleShot(4000, lambda: self.lbl_action.setText(""))

    def set_status(self, alert_id, status):
        try:
            url = f"http://{self.settings['host']}:{self.settings['port']}/incidents/{alert_id}/status"
            requests.patch(url, json={"status": status}, headers=self._api_headers(), timeout=2)
        except Exception as e:
            print(f"[STATUS UPDATE ERROR] {e}")

    def filter_table(self):
        search = self.search_bar.text().lower() if hasattr(self, "search_bar") else ""
        data   = self._all_alerts
        with self._geo_lock:    geo_snap    = dict(self._geo_cache)
        with self._threat_lock: threat_snap = dict(self._threat_cache)

        filtered = [a for a in data if
            search in str(a.get("source_ip","")).lower() or
            search in str(a.get("event_type","")).lower() or
            search in str(a.get("severity","")).lower() or
            search in str(a.get("status","")).lower() or
            search in (geo_snap.get(str(a.get("source_ip",""))) or {}).get("country","").lower() or
            search in score_to_label((threat_snap.get(str(a.get("source_ip",""))) or {}).get("abuse_score",-1))[0].lower()
        ]

        self.table.clearContents(); self.table.setRowCount(len(filtered))
        for i, alert in enumerate(filtered):
            ip_val   = str(alert.get("source_ip","0.0.0.0"))
            type_val = str(alert.get("event_type","Detection"))
            sev_val  = str(alert.get("severity","LOW"))
            ts_val   = str(alert.get("timestamp",""))[:19]
            status   = str(alert.get("status","Logged"))
            country  = (geo_snap.get(ip_val) or {}).get("country","Detecting...")
            color    = SEV_COLORS.get(sev_val.upper(),"#ffffff")
            t_info   = threat_snap.get(ip_val) or {}
            stored   = int(alert.get("threat_score") or 0)
            ai_s     = int(alert.get("ai_score") or 0)
            abuse_s  = int(t_info.get("abuse_score") if t_info.get("abuse_score") is not None else -1)
            t_score  = max(stored, ai_s, abuse_s)
            t_label, t_color = score_to_label(t_score)
            threat_text = f"{t_label} ({t_score})" if t_score >= 0 else "CHECKING..."
            if status in ("Resolved","False Positive"):
                color = t_color = "#555555"
            ts_item = QTableWidgetItem(ts_val)
            ts_item.setData(Qt.ItemDataRole.UserRole, alert.get("id"))
            cells = [
                (ts_item, color), (QTableWidgetItem(ip_val), color),
                (QTableWidgetItem(country), color), (QTableWidgetItem(type_val), color),
                (QTableWidgetItem(sev_val), color), (QTableWidgetItem(threat_text), t_color),
                (QTableWidgetItem(status), color),
            ]
            for j, (item, c) in enumerate(cells):
                item.setForeground(QColor(c)); self.table.setItem(i, j, item)

        if filtered:
            self.table.resizeColumnsToContents()
            self.table.horizontalHeader().setStretchLastSection(True)

    # ── Stats tab ─────────────────────────────────────────────────────────────

    def update_stats_tab(self, data):
        import math
        counts = Counter(a.get("event_type", "Unknown") for a in data)
        total  = len(data)
        CHART_COLORS = [
            "#ff4757","#ffa502","#ff6b81","#ff0000","#a29bfe",
            "#fd79a8","#00ff88","#74b9ff","#6c5ce7","#00cec9",
        ]

        # Pie chart
        self.pie_widget.clear()
        if total > 0:
            items  = counts.most_common()
            angle  = 0.0
            for idx, (etype, count) in enumerate(items):
                frac  = count / total
                sweep = frac * 360.0
                color = CHART_COLORS[idx % len(CHART_COLORS)]
                pts_x, pts_y = [0.0], [0.0]
                steps = max(3, int(sweep / 3))
                for s in range(steps + 1):
                    a = math.radians(angle + s * sweep / steps)
                    pts_x.append(math.cos(a)); pts_y.append(math.sin(a))
                pts_x.append(0.0); pts_y.append(0.0)
                r, g, b = int(color[1:3],16), int(color[3:5],16), int(color[5:7],16)
                poly = pg.PlotDataItem(pts_x, pts_y, fillLevel=0,
                                       brush=pg.mkBrush(r,g,b,200),
                                       pen=pg.mkPen("#0b0b1a", width=2))
                self.pie_widget.addItem(poly)
                if frac > 0.05:
                    mid_a = math.radians(angle + sweep / 2)
                    txt = pg.TextItem(f"{frac*100:.0f}%", color=color, anchor=(0.5, 0.5))
                    txt.setPos(math.cos(mid_a)*0.6, math.sin(mid_a)*0.6)
                    self.pie_widget.addItem(txt)
                angle += sweep
            for idx, (etype, count) in enumerate(items[:8]):
                color = CHART_COLORS[idx % len(CHART_COLORS)]
                legend_txt = pg.TextItem(f"■ {etype[:18]} ({count})", color=color, anchor=(0,0.5))
                legend_txt.setPos(1.15, 1.1 - idx * 0.28)
                self.pie_widget.addItem(legend_txt)
            self.pie_widget.setXRange(-1.1, 2.6, padding=0)
            self.pie_widget.setYRange(-1.2, 1.4, padding=0)

        # Severity bar chart
        self.sev_widget.clear()
        sev_order  = ["CRITICAL","HIGH","MEDIUM","LOW"]
        sev_colors = ["#ff0000","#ff4757","#ffa502","#00ff88"]
        sev_counts = [sum(1 for a in data if str(a.get("severity","")).upper()==s) for s in sev_order]
        bars = pg.BarGraphItem(x=range(4), height=sev_counts, width=0.5,
                               brushes=[pg.mkBrush(c) for c in sev_colors],
                               pen=pg.mkPen("#0b0b1a", width=1))
        self.sev_widget.addItem(bars)
        ax = self.sev_widget.getAxis("bottom")
        ax.setTicks([[(i, s) for i, s in enumerate(sev_order)]])
        ax.setTextPen("#00f2ff")
        self.sev_widget.getAxis("left").setTextPen("#00f2ff")
        for i, (cnt, color) in enumerate(zip(sev_counts, sev_colors)):
            if cnt > 0:
                lbl = pg.TextItem(str(cnt), color=color, anchor=(0.5, 1.0))
                lbl.setPos(i, cnt); self.sev_widget.addItem(lbl)

        # Heatmap
        self.heat_widget.clear()
        day_names = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
        heat = defaultdict(int)
        for alert in data:
            ts = alert.get("timestamp","")
            if ts:
                try:
                    dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
                    heat[(dt.weekday(), dt.hour)] += 1
                except: pass
        if heat:
            max_val = max(heat.values()) or 1
            for (day, hour), cnt in heat.items():
                intensity = cnt / max_val
                r = int(108 + 147 * intensity); g = int(92 - 92 * intensity); b = int(231 - 231 * intensity)
                size = 5 + int(16 * intensity)
                dot = pg.ScatterPlotItem(x=[hour], y=[day], size=size,
                                         brush=pg.mkBrush(r,g,b,200), pen=pg.mkPen(None))
                self.heat_widget.addItem(dot)
        ax_l = self.heat_widget.getAxis("left")
        ax_l.setTicks([[(i, d) for i, d in enumerate(day_names)]]); ax_l.setTextPen("#00f2ff")
        self.heat_widget.getAxis("bottom").setTextPen("#00f2ff")
        self.heat_widget.setYRange(-0.5, 6.5, padding=0)
        self.heat_widget.setXRange(-0.5, 23.5, padding=0)

        # Table
        self.stats_table.clearContents(); self.stats_table.setRowCount(len(counts))
        for i, (etype, count) in enumerate(counts.most_common()):
            pct   = f"{(count/total*100):.1f}%" if total > 0 else "0%"
            color = CHART_COLORS[i % len(CHART_COLORS)]
            for j, val in enumerate([etype, str(count), pct]):
                item = QTableWidgetItem(val)
                item.setForeground(QColor(color))
                self.stats_table.setItem(i, j, item)

    def update_timeline(self, data):
        try:
            hour_counts = defaultdict(int)
            for alert in data:
                ts = alert.get("timestamp","")
                if ts:
                    try:
                        hour_counts[datetime.strptime(ts[:19],"%Y-%m-%d %H:%M:%S").hour] += 1
                    except: pass
            hours  = list(range(24))
            counts = [hour_counts.get(h,0) for h in hours]
            self.timeline_widget.clear()
            bg = pg.BarGraphItem(x=hours, height=counts, width=0.6,
                                 brush="#6c5ce7", pen=pg.mkPen("#a29bfe"))
            self.timeline_widget.addItem(bg)
        except Exception as e:
            print(f"[TIMELINE ERROR] {e}")

    def update_world_map(self):
        try:
            m = folium.Map(location=[20,0], zoom_start=2, tiles="OpenStreetMap")
            with self._geo_lock:    geo_snap    = dict(self._geo_cache)
            with self._threat_lock: threat_snap = dict(self._threat_cache)
            for ip in self._all_ips:
                geo = geo_snap.get(ip) or {}
                lat, lng = geo.get("lat",0), geo.get("lng",0)
                if lat == 0 and lng == 0: continue
                sev    = self._ip_severity.get(ip,"LOW")
                t_score = threat_snap.get(ip,{}).get("abuse_score",-1)
                t_label,_ = score_to_label(t_score)
                popup_text = f"{ip} ({geo.get('country','?')})<br>Severity: {sev}<br>Threat: {t_label} ({t_score})"
                folium.Marker(
                    location=[lat,lng],
                    popup=folium.Popup(popup_text, max_width=200),
                    icon=folium.Icon(color=MAP_COLORS.get(sev,"blue"), icon="info-sign")
                ).add_to(m)
            buf = io.BytesIO(); m.save(buf, close_file=False)
            self.web_view.setHtml(buf.getvalue().decode())
        except Exception as e:
            print(f"[MAP ERROR] {e}")

    def generate_pdf_report(self):
        # ── Time range picker dialog ──────────────────────────────────────────
        dlg = QDialog(self)
        dlg.setWindowTitle("Generate Security Report")
        dlg.setStyleSheet(STYLE_SOC)
        dlg.setFixedSize(380, 200)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(10)

        lay.addWidget(QLabel("Select coverage window and output path:"))

        form = QFormLayout()
        spn_hours = QSpinBox()
        spn_hours.setRange(1, 720)
        spn_hours.setValue(24)
        spn_hours.setSuffix(" hours")
        form.addRow("Coverage:", spn_hours)

        inp_path = QLineEdit("Security_Report.pdf")
        form.addRow("Output file:", inp_path)
        lay.addLayout(form)

        note = QLabel("Ollama (deepseek-coder-v2:16b) will write the executive\n"
                      "summary. Generation takes ~60–90 seconds.")
        note.setStyleSheet("color:#6c5ce7; font-size:10px;")
        lay.addWidget(note)

        btns = QHBoxLayout()
        btn_ok  = QPushButton("GENERATE"); btn_ok.setObjectName("success")
        btn_can = QPushButton("CANCEL");   btn_can.setStyleSheet("background:#444;")
        btn_ok.clicked.connect(dlg.accept)
        btn_can.clicked.connect(dlg.reject)
        btns.addStretch(); btns.addWidget(btn_ok); btns.addWidget(btn_can)
        lay.addLayout(btns)

        if not dlg.exec():
            return

        hours       = spn_hours.value()
        output_path = inp_path.text().strip() or "Security_Report.pdf"

        # Show progress indicator
        self.btn_report.setEnabled(False)
        self.btn_report.setText("GENERATING...")
        self.lbl_action.setText("⏳ Building PDF with Ollama executive summary...")

        def _done(path, error):
            # Emit signal — safe cross-thread GUI update (QTimer.singleShot is unreliable
            # from daemon threads that have no Qt event loop)
            self._pdf_done_sig.emit(path or "", error or "", output_path)

        generate_pdf(
            db_path=self.db_path,
            output_path=output_path,
            operator=self.username,
            role=self.role,
            hours=hours,
            callback=_done,
        )

    def _on_pdf_done(self, path, error, output_path):
        self.btn_report.setEnabled(True)
        self.btn_report.setText("EXPORT PDF")
        self.lbl_action.setText("")
        if error:
            QMessageBox.critical(self, "PDF Failed", f"Generation failed:\n{error}")
        else:
            QMessageBox.information(self, "Report Ready",
                f"PDF saved to:\n{output_path}\n\n"
                "Contents:\n"
                "  • Cover page with risk level & executive summary\n"
                "  • Statistics (severity breakdown, top IPs, event types)\n"
                "  • Incident cards with AI analysis & MITRE ATT&CK\n"
                "  • Recommendations & immediate actions\n"
                "  • Blocked IP appendix")

    def _on_pdf_sig(self, path, error, output_path):
        """Slot for _pdf_done_sig — receives cross-thread PDF callback safely."""
        self._on_pdf_done(path or None, error or None, output_path)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SOCDashboard()
    window.show()
    sys.exit(app.exec())
