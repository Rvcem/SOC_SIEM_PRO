import sys, io, json, folium, requests, pyqtgraph as pg, threading
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWebEngineWidgets import QWebEngineView
from fpdf import FPDF
from collections import Counter, defaultdict
from datetime import datetime
from core.schema import get_app_config, set_app_config
from threat_intel import get_threat_score_async, score_to_label
from responder import (
    init_responder_tables, load_email_config, save_email_config,
    send_alert_async, block_ip, unblock_ip, get_blocklist,
    get_rules, add_rule, toggle_rule, delete_rule, evaluate_rules
)

try:
    import winsound
    HAS_SOUND = True
except ImportError:
    HAS_SOUND = False

STYLE_SOC = """
    QMainWindow { background-color: #0b0b1a; }
    QFrame#Card { background-color: #161633; border: 1px solid #2e2e66; border-radius: 12px; }
    QLabel { color: #ffffff; font-family: 'Segoe UI'; }
    QPushButton { background-color: #6c5ce7; color: white; border-radius: 8px; padding: 8px 15px; font-weight: bold; }
    QPushButton#danger { background-color: #ff4757; }
    QPushButton#success { background-color: #00b894; }
    QTableWidget { background-color: #161633; color: white; border: none; gridline-color: #2e2e66; }
    QHeaderView::section { background-color: #1c1c44; color: #00f2ff; padding: 5px; }
    QLineEdit { background-color: #1c1c44; color: white; border: 1px solid #2e2e66; border-radius: 6px; padding: 5px; }
    QTabWidget::pane { border: 1px solid #2e2e66; background-color: #0b0b1a; }
    QTabBar::tab { background-color: #161633; color: #aaaaaa; padding: 8px 20px; border-radius: 6px; margin: 2px; }
    QTabBar::tab:selected { background-color: #6c5ce7; color: white; }
    QSpinBox { background-color: #1c1c44; color: white; border: 1px solid #2e2e66; border-radius: 6px; padding: 4px; }
    QComboBox { background-color: #1c1c44; color: white; border: 1px solid #2e2e66; border-radius: 6px; padding: 5px; }
    QComboBox::drop-down { border: none; }
    QComboBox QAbstractItemView { background-color: #161633; color: white; selection-background-color: #6c5ce7; }
    QMenu { background-color: #161633; color: white; border: 1px solid #2e2e66; }
    QMenu::item:selected { background-color: #6c5ce7; }
    QCheckBox { color: white; }
"""

SEV_COLORS = {"CRITICAL": "#ff0000", "HIGH": "#ff4757", "MEDIUM": "#ffa502", "LOW": "#00ff88"}
MAP_COLORS = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "blue", "LOW": "green"}
EVENT_TYPES = [
    ("BRUTEFORCE", "#ff4757"), ("PORT SCAN", "#ffa502"), ("SQL INJECTION", "#ff6b81"),
    ("DDOS", "#ff0000"), ("MALWARE", "#a29bfe"), ("ANOMALY DETECTED", "#fd79a8"),
    ("SUCCESSFUL LOGIN", "#00ff88"), ("SYSTEM EVENT", "#74b9ff"), ("CRITICAL", "#ff0000"),
]


# ── Settings Dialog ───────────────────────────────────────────────────────────

class SettingsDialog(QDialog):
    def __init__(self, parent=None, settings=None, db_path=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setStyleSheet(STYLE_SOC)
        self.setFixedSize(460, 480)
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
        lbl_help.setStyleSheet("color: #ffa502; font-size: 10px;")
        lbl_help.setWordWrap(True)
        self.btn_test = QPushButton("SEND TEST EMAIL")
        self.btn_test.setObjectName("success")
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


# ── Main Dashboard ────────────────────────────────────────────────────────────

class SOCDashboard(QMainWindow):
    _threat_ready  = pyqtSignal(str)
    _action_signal = pyqtSignal(str, str)   # (ip, action_str) for live feedback

    def __init__(self, username="operator", role="analyst", db_path=None, api_key=None):
        super().__init__()
        self.username = username
        self.role     = role
        self.db_path  = db_path
        self._api_key = api_key
        self.setWindowTitle(f"SOC SIEM PRO  —  {username.upper()}  [{role.upper()}]")
        self.resize(1400, 900)
        self.setStyleSheet(STYLE_SOC)

        # State
        self.trend_points  = [0]
        self._all_alerts   = []
        self._all_ips      = set()
        self._geo_cache    = {}
        self._geo_lock     = threading.Lock()
        self._ip_severity  = {}
        self._prev_ids     = set()
        self._threat_cache = {}
        self._threat_lock  = threading.Lock()
        self.settings      = {"host": "127.0.0.1", "port": 5000, "refresh": 500, "limit": 50}
        self.email_cfg     = load_email_config(db_path) if db_path else {}
        self.gui_zoom      = self._load_int_pref("gui_zoom", 10)
        self.alert_split_sizes = self._load_json_pref("alert_split_sizes", [900, 520])

        if db_path:
            init_responder_tables(db_path)

        self._threat_ready.connect(self._on_threat_ready)
        self._action_signal.connect(self._on_action_taken)

        self._build_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.fetch_data)
        self.timer.start(self.settings["refresh"])
        QTimer.singleShot(1500, self.update_world_map)
        QTimer.singleShot(500,  self._refresh_blocklist_tab)
        QTimer.singleShot(500,  self._refresh_rules_tab)

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

        # Header
        header = QHBoxLayout()
        lbl_title = QLabel("SOC MONITORING ENGINE")
        lbl_title.setStyleSheet("font-size: 22px; font-weight: bold; color: #00f2ff;")
        lbl_user  = QLabel(f"👤 {self.username.upper()}  |  {self.role.upper()}")
        lbl_user.setStyleSheet("font-size: 11px; color: #6c5ce7; font-family: 'Courier New';")
        self.lbl_action = QLabel("")
        self.lbl_action.setStyleSheet("font-size: 10px; color: #00ff88; font-family: 'Courier New';")
        self.btn_settings = QPushButton("SETTINGS")
        self.btn_settings.setStyleSheet("background-color: #2e2e66;")
        self.btn_settings.clicked.connect(self.open_settings)
        self.btn_report = QPushButton("GENERATE REPORT (PDF)")
        self.btn_report.clicked.connect(self.generate_pdf_report)
        header.addWidget(lbl_title)
        header.addWidget(lbl_user)
        header.addWidget(self.lbl_action)
        header.addStretch()
        header.addWidget(self.btn_settings)
        header.addWidget(self.btn_report)
        layout.addLayout(header)

        # Stats bar
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFixedHeight(100)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet("""
            QScrollArea { border: none; background: transparent; }
            QScrollBar:horizontal { background: #0b0b1a; height: 6px; border-radius: 3px; }
            QScrollBar::handle:horizontal { background: #6c5ce7; border-radius: 3px; }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }
        """)
        scroll_widget = QWidget(); scroll_widget.setStyleSheet("background: transparent;")
        self.stats_bar = QHBoxLayout(scroll_widget)
        self.stats_bar.setSpacing(10); self.stats_bar.setContentsMargins(4,4,4,4)
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

        # Tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        self._build_tab_alerts()
        self._build_tab_stats()
        self._build_tab_timeline()
        self._build_tab_threat()
        self._build_tab_blocklist()
        self._build_tab_rules()

    def _build_tab_alerts(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        self.alert_splitter = QSplitter(Qt.Orientation.Horizontal)
        left_widget = QWidget(); left = QVBoxLayout(left_widget)
        self.graph_card = QFrame(); self.graph_card.setObjectName("Card")
        gv = QVBoxLayout(self.graph_card); gv.addWidget(QLabel("INCIDENT TREND (LIVE)"))
        self.graph_widget = pg.PlotWidget(); self.graph_widget.setBackground("#161633")
        self.curve = self.graph_widget.plot(pen=pg.mkPen(color="#00f2ff", width=3))
        gv.addWidget(self.graph_widget); left.addWidget(self.graph_card, 1)
        self.map_card = QFrame(); self.map_card.setObjectName("Card")
        mv = QVBoxLayout(self.map_card); mh = QHBoxLayout()
        mh.addWidget(QLabel("LIVE ATTACK MAP"))
        self.btn_refresh_map = QPushButton("REFRESH MAP"); self.btn_refresh_map.setFixedWidth(130)
        self.btn_refresh_map.clicked.connect(self.update_world_map)
        mh.addStretch(); mh.addWidget(self.btn_refresh_map); mv.addLayout(mh)
        self.web_view = QWebEngineView(); self.web_view.setFixedHeight(300)
        mv.addWidget(self.web_view); left.addWidget(self.map_card, 1)
        right_widget = QWidget(); right = QVBoxLayout(right_widget)
        self.risk_card = QFrame(); self.risk_card.setObjectName("Card")
        rv = QVBoxLayout(self.risk_card); rv.addWidget(QLabel("CURRENT RISK LEVEL"))
        self.lbl_risk = QLabel("NORMAL")
        self.lbl_risk.setStyleSheet("font-size: 35px; color: #00ff88; font-weight: bold;")
        rv.addWidget(self.lbl_risk, alignment=Qt.AlignmentFlag.AlignCenter)
        right.addWidget(self.risk_card)
        tools = QHBoxLayout()
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search by IP, country, event, severity, threat...")
        self.search_bar.textChanged.connect(self.filter_table)
        btn_zoom_out = QPushButton("-")
        btn_zoom_in = QPushButton("+")
        btn_zoom_out.setFixedWidth(34); btn_zoom_in.setFixedWidth(34)
        btn_zoom_out.clicked.connect(lambda: self._set_zoom(self.gui_zoom - 1))
        btn_zoom_in.clicked.connect(lambda: self._set_zoom(self.gui_zoom + 1))
        tools.addWidget(self.search_bar)
        tools.addWidget(btn_zoom_out)
        tools.addWidget(btn_zoom_in)
        right.addLayout(tools)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Timestamp","Source IP","Country","Type","Severity","Threat Score","Status"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_status_menu)
        self.table.itemSelectionChanged.connect(self._show_selected_alert_details)
        right.addWidget(self.table, 3)
        self.details_card = QFrame(); self.details_card.setObjectName("Card")
        dv = QVBoxLayout(self.details_card)
        dv.addWidget(QLabel("FULL INCIDENT DETAILS"))
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setMinimumHeight(150)
        self.detail_text.setStyleSheet("background-color:#101028; color:#ffffff; border:1px solid #2e2e66;")
        dv.addWidget(self.detail_text)
        right.addWidget(self.details_card, 1)
        self.alert_splitter.addWidget(left_widget)
        self.alert_splitter.addWidget(right_widget)
        self.alert_splitter.setSizes(self.alert_split_sizes)
        tl.addWidget(self.alert_splitter)
        self._apply_zoom()
        self.tabs.addTab(tab, "🔴 Live Alerts")

    def _build_tab_stats(self):
        tab = QWidget(); tl = QVBoxLayout(tab); tl.setSpacing(8)

        # ── Top row: Pie chart + Severity bar ──
        top_row = QHBoxLayout(); top_row.setSpacing(8)

        # Pie chart card
        pie_card = QFrame(); pie_card.setObjectName("Card")
        pie_vl = QVBoxLayout(pie_card)
        pie_title = QLabel("EVENT TYPE DISTRIBUTION")
        pie_title.setStyleSheet("color:#00f2ff; font-size:11px; font-weight:bold; letter-spacing:2px;")
        pie_vl.addWidget(pie_title)
        self.pie_widget = pg.PlotWidget()
        self.pie_widget.setBackground("#161633")
        self.pie_widget.setFixedHeight(280)
        self.pie_widget.hideAxis("left"); self.pie_widget.hideAxis("bottom")
        self.pie_widget.setAspectLocked(True)
        pie_vl.addWidget(self.pie_widget)
        top_row.addWidget(pie_card, 3)

        # Severity bar chart card
        sev_card = QFrame(); sev_card.setObjectName("Card")
        sev_vl = QVBoxLayout(sev_card)
        sev_title = QLabel("SEVERITY BREAKDOWN")
        sev_title.setStyleSheet("color:#00f2ff; font-size:11px; font-weight:bold; letter-spacing:2px;")
        sev_vl.addWidget(sev_title)
        self.sev_widget = pg.PlotWidget()
        self.sev_widget.setBackground("#161633")
        self.sev_widget.setFixedHeight(280)
        self.sev_widget.showGrid(y=True, alpha=0.3)
        sev_vl.addWidget(self.sev_widget)
        top_row.addWidget(sev_card, 2)
        tl.addLayout(top_row)

        # ── Heatmap card ──
        heat_card = QFrame(); heat_card.setObjectName("Card")
        heat_vl = QVBoxLayout(heat_card)
        heat_title = QLabel("ATTACK HEATMAP — DAY x HOUR")
        heat_title.setStyleSheet("color:#00f2ff; font-size:11px; font-weight:bold; letter-spacing:2px;")
        heat_vl.addWidget(heat_title)
        self.heat_widget = pg.PlotWidget()
        self.heat_widget.setBackground("#161633")
        self.heat_widget.setFixedHeight(200)
        self.heat_widget.setLabel("left", "Day", color="#00f2ff")
        self.heat_widget.setLabel("bottom", "Hour (0-23)", color="#00f2ff")
        heat_vl.addWidget(self.heat_widget)
        tl.addWidget(heat_card)

        # ── Bottom: event breakdown table ──
        tbl_card = QFrame(); tbl_card.setObjectName("Card")
        tbl_vl = QVBoxLayout(tbl_card)
        tbl_lbl = QLabel("DETAILED EVENT BREAKDOWN")
        tbl_lbl.setStyleSheet("color:#00f2ff; font-size:11px; font-weight:bold; letter-spacing:2px;")
        tbl_vl.addWidget(tbl_lbl)
        self.stats_table = QTableWidget(0, 3)
        self.stats_table.setHorizontalHeaderLabels(["Event Type", "Count", "% of Total"])
        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.stats_table.setFixedHeight(160)
        tbl_vl.addWidget(self.stats_table)
        tl.addWidget(tbl_card)

        self.tabs.addTab(tab, "📊 Statistics")

    def _build_tab_timeline(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.addWidget(QLabel("INCIDENTS PER HOUR (LAST 24H)"))
        self.timeline_widget = pg.PlotWidget(); self.timeline_widget.setBackground("#161633")
        self.timeline_widget.setLabel("left", "Count", color="#00f2ff")
        self.timeline_widget.setLabel("bottom", "Hour", color="#00f2ff")
        self.timeline_widget.showGrid(x=True, y=True, alpha=0.3)
        tl.addWidget(self.timeline_widget)
        self.tabs.addTab(tab, "📈 Timeline")

    def _build_tab_threat(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.addWidget(QLabel("THREAT INTELLIGENCE — AbuseIPDB + AI Analysis"))
        self.threat_table = QTableWidget(0, 8)
        self.threat_table.setHorizontalHeaderLabels(["IP","Combined","AI","AbuseIPDB","Risk Level","Country","ISP","AI Summary"])
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tl.addWidget(self.threat_table)
        self.tabs.addTab(tab, "🌐 Threat Intel")

    def _build_tab_blocklist(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        # Manual block controls
        ctrl = QHBoxLayout()
        self.inp_block_ip     = QLineEdit(); self.inp_block_ip.setPlaceholderText("IP to block (e.g. 1.2.3.4)")
        self.inp_block_reason = QLineEdit(); self.inp_block_reason.setPlaceholderText("Reason (optional)")
        btn_block   = QPushButton("BLOCK IP");   btn_block.setObjectName("danger")
        btn_unblock = QPushButton("UNBLOCK SELECTED"); btn_unblock.setStyleSheet("background-color:#2e2e66;")
        btn_refresh = QPushButton("REFRESH")
        btn_block.clicked.connect(self._manual_block)
        btn_unblock.clicked.connect(self._manual_unblock)
        btn_refresh.clicked.connect(self._refresh_blocklist_tab)
        ctrl.addWidget(self.inp_block_ip); ctrl.addWidget(self.inp_block_reason)
        ctrl.addWidget(btn_block); ctrl.addWidget(btn_unblock); ctrl.addWidget(btn_refresh)
        tl.addLayout(ctrl)
        self.blocklist_table = QTableWidget(0, 4)
        self.blocklist_table.setHorizontalHeaderLabels(["IP","Reason","Added At","Select"])
        self.blocklist_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tl.addWidget(self.blocklist_table)
        self.tabs.addTab(tab, "🚫 Blocklist")

    def _build_tab_rules(self):
        tab = QWidget(); tl = QVBoxLayout(tab)
        tl.addWidget(QLabel("CUSTOM RULE ENGINE — Auto-Block & Email Rules"))

        # Add rule form
        form_frame = QFrame(); form_frame.setObjectName("Card")
        ff = QHBoxLayout(form_frame)
        self.inp_rule_name  = QLineEdit(); self.inp_rule_name.setPlaceholderText("Rule name")
        self.inp_rule_cond  = QLineEdit(); self.inp_rule_cond.setPlaceholderText("Condition (e.g. bruteforce, ddos, threat_score)")
        self.inp_rule_thr   = QSpinBox();  self.inp_rule_thr.setRange(1, 9999); self.inp_rule_thr.setValue(5)
        self.inp_rule_win   = QSpinBox();  self.inp_rule_win.setRange(0, 3600); self.inp_rule_win.setValue(60); self.inp_rule_win.setSuffix("s")
        self.cmb_rule_act   = QComboBox(); self.cmb_rule_act.addItems(["block", "email"])
        btn_add = QPushButton("ADD RULE"); btn_add.setObjectName("success")
        btn_add.clicked.connect(self._add_rule)
        ff.addWidget(QLabel("Name:")); ff.addWidget(self.inp_rule_name)
        ff.addWidget(QLabel("Condition:")); ff.addWidget(self.inp_rule_cond)
        ff.addWidget(QLabel("Threshold:")); ff.addWidget(self.inp_rule_thr)
        ff.addWidget(QLabel("Window:")); ff.addWidget(self.inp_rule_win)
        ff.addWidget(QLabel("Action:")); ff.addWidget(self.cmb_rule_act)
        ff.addWidget(btn_add)
        tl.addWidget(form_frame)

        self.rules_table = QTableWidget(0, 7)
        self.rules_table.setHorizontalHeaderLabels(["ID","Name","Condition","Threshold","Window","Action","Enabled"])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        tl.addWidget(self.rules_table)

        btn_row = QHBoxLayout()
        btn_del    = QPushButton("DELETE SELECTED"); btn_del.setObjectName("danger")
        btn_reload = QPushButton("REFRESH RULES")
        btn_del.clicked.connect(self._delete_rule)
        btn_reload.clicked.connect(self._refresh_rules_tab)
        btn_row.addWidget(btn_del); btn_row.addWidget(btn_reload); btn_row.addStretch()
        tl.addLayout(btn_row)
        self.tabs.addTab(tab, "⚙️ Rule Engine")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_stat_card(self, title, value, color):
        card = QFrame(); card.setObjectName("Card"); card.setFixedSize(160, 80)
        vl = QVBoxLayout(card)
        lbl_t = QLabel(title); lbl_t.setStyleSheet(f"font-size: 10px; color: {color};"); lbl_t.setAlignment(Qt.AlignmentFlag.AlignCenter)
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
                widget.verticalHeader().setDefaultSectionSize(max(24, self.gui_zoom + 16))
        if hasattr(self, "detail_text"):
            self.detail_text.setFont(QFont("Consolas", self.gui_zoom))

    def _show_selected_alert_details(self):
        row = self.table.currentRow() if hasattr(self, "table") else -1
        if row < 0 or not hasattr(self, "detail_text"):
            return
        id_item = self.table.item(row, 0)
        alert_id = id_item.data(Qt.ItemDataRole.UserRole) if id_item else None
        alert = next((a for a in self._all_alerts if a.get("id") == alert_id), None)
        if not alert:
            return
        ip = str(alert.get("source_ip", ""))
        with self._threat_lock:
            threat = self._threat_cache.get(ip, {})
        combined = max(int(alert.get("threat_score") or 0), int(alert.get("ai_score") or 0), int(threat.get("abuse_score") or 0))
        lines = [
            f"ID: {alert.get('id')}",
            f"Time: {alert.get('timestamp')}",
            f"Source IP: {ip}",
            f"Event: {alert.get('event_type')} | Severity: {alert.get('severity')} | Category: {alert.get('category')}",
            f"Status: {alert.get('status')}",
            f"Combined Threat Score: {combined}",
            f"AI Score: {alert.get('ai_score', 0)} | AbuseIPDB: {threat.get('abuse_score', 'unknown')} | Anomaly: {alert.get('anomaly_score', 0)}",
            "",
            "AI Summary:",
            str(alert.get("ai_summary") or "No AI summary stored for this incident."),
            "",
            "Raw Log:",
            str(alert.get("raw_log") or "Raw log was not stored for this older incident."),
        ]
        self.detail_text.setPlainText("\n".join(lines))

    def closeEvent(self, event):
        if hasattr(self, "alert_splitter"):
            self._save_pref("alert_split_sizes", self.alert_splitter.sizes())
        self._save_pref("gui_zoom", self.gui_zoom)
        super().closeEvent(event)

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
        if self._api_key:
            return {"X-API-Key": self._api_key}
        return {}

    def fetch_data(self):
        try:
            limit = self.settings.get("limit", 50)
            url = f"http://{self.settings['host']}:{self.settings['port']}/incidents?limit={limit}"
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
            # Evaluate rules with threat score
            if self.db_path:
                threading.Thread(
                    target=self._run_rules, args=(ip, "threat_check", "LOW", result.get("abuse_score", 0)),
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
            if not ip:
                continue
            current = alert_scores.get(ip, {"threat_score": 0, "ai_score": 0, "ai_summary": ""})
            current["threat_score"] = max(current["threat_score"], int(alert.get("threat_score") or 0))
            current["ai_score"] = max(current["ai_score"], int(alert.get("ai_score") or 0))
            if alert.get("ai_summary"):
                current["ai_summary"] = str(alert.get("ai_summary"))
            alert_scores[ip] = current
        ips = set(snapshot.keys()) | set(alert_scores.keys())
        rows = []
        for ip in ips:
            intel = snapshot.get(ip, {"ip": ip})
            scores = alert_scores.get(ip, {})
            abuse = int(intel.get("abuse_score") or 0)
            combined = max(abuse, int(scores.get("threat_score") or 0), int(scores.get("ai_score") or 0))
            row = dict(intel)
            row.update(scores)
            row["combined_score"] = combined
            rows.append(row)
        rows = sorted(rows, key=lambda x: x.get("combined_score", 0), reverse=True)
        self.threat_table.clearContents(); self.threat_table.setRowCount(len(rows))
        malicious = 0
        for i, info in enumerate(rows):
            score = int(info.get("combined_score", 0))
            abuse = int(info.get("abuse_score") or 0)
            ai_score = int(info.get("ai_score") or 0)
            label, color = score_to_label(score)
            if score >= 25:
                malicious += 1
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

    # ── Rule Engine ───────────────────────────────────────────────────────────

    def _run_rules(self, ip, event_type, severity, threat_score):
        if not self.db_path:
            return
        actions = evaluate_rules(self.db_path, ip, event_type, severity, threat_score, self.email_cfg)
        for action in actions:
            self._action_signal.emit(ip, action)

    def _add_rule(self):
        name  = self.inp_rule_name.text().strip()
        cond  = self.inp_rule_cond.text().strip().lower()
        thr   = self.inp_rule_thr.value()
        win   = self.inp_rule_win.value()
        act   = self.cmb_rule_act.currentText()
        if not name or not cond:
            QMessageBox.warning(self, "Error", "Name and Condition are required."); return
        add_rule(self.db_path, name, cond, thr, win, act)
        self.inp_rule_name.clear(); self.inp_rule_cond.clear()
        self._refresh_rules_tab()

    def _delete_rule(self):
        selected = self.rules_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Error", "Select a rule row first."); return
        row = self.rules_table.currentRow()
        id_item = self.rules_table.item(row, 0)
        if id_item:
            delete_rule(self.db_path, int(id_item.text()))
            self._refresh_rules_tab()

    def _refresh_rules_tab(self):
        if not self.db_path:
            return
        rules = get_rules(self.db_path)
        self.rules_table.clearContents(); self.rules_table.setRowCount(len(rules))
        for i, r in enumerate(rules):
            enabled_chk = QCheckBox()
            enabled_chk.setChecked(bool(r["enabled"]))
            rule_id = r["id"]
            enabled_chk.stateChanged.connect(lambda state, rid=rule_id: toggle_rule(self.db_path, rid, bool(state)))
            items = [str(r["id"]), r["name"], r["condition"],
                     str(r["threshold"]), f"{r['window_sec']}s", r["action"]]
            for j, val in enumerate(items):
                item = QTableWidgetItem(val)
                color = "#00ff88" if r["action"] == "email" else "#ff4757"
                item.setForeground(QColor(color))
                self.rules_table.setItem(i, j, item)
            self.rules_table.setCellWidget(i, 6, enabled_chk)

    # ── Blocklist Tab ─────────────────────────────────────────────────────────

    def _manual_block(self):
        ip     = self.inp_block_ip.text().strip()
        reason = self.inp_block_reason.text().strip() or "Manual block"
        if not ip:
            QMessageBox.warning(self, "Error", "Enter an IP address."); return
        block_ip(self.db_path, ip, reason)
        self.inp_block_ip.clear(); self.inp_block_reason.clear()
        self._refresh_blocklist_tab()

    def _manual_unblock(self):
        for row in range(self.blocklist_table.rowCount()):
            chk = self.blocklist_table.cellWidget(row, 3)
            if chk and chk.isChecked():
                ip_item = self.blocklist_table.item(row, 0)
                if ip_item:
                    unblock_ip(self.db_path, ip_item.text())
        self._refresh_blocklist_tab()

    def _refresh_blocklist_tab(self):
        if not self.db_path:
            return
        bl = get_blocklist(self.db_path)
        self.blocklist_table.clearContents(); self.blocklist_table.setRowCount(len(bl))
        for i, entry in enumerate(bl):
            chk = QCheckBox()
            self.blocklist_table.setItem(i, 0, QTableWidgetItem(entry.get("ip","")))
            self.blocklist_table.setItem(i, 1, QTableWidgetItem(entry.get("reason","")))
            self.blocklist_table.setItem(i, 2, QTableWidgetItem(str(entry.get("added_at",""))[:19]))
            self.blocklist_table.setCellWidget(i, 3, chk)
            for j in range(3):
                item = self.blocklist_table.item(i, j)
                if item:
                    item.setForeground(QColor("#ff4757"))
        self.lbl_blocked.setText(str(len(bl)))

    # ── Alert Processing ──────────────────────────────────────────────────────

    def process_incoming_alerts(self, data):
        self._all_alerts = data
        try:
            previous_ids = set(self._prev_ids)
            new_ids = {a.get("id") for a in data}
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
                self.lbl_risk.setText("CRITICAL"); self.lbl_risk.setStyleSheet("font-size: 35px; color: #ff4757; font-weight: bold;")
            else:
                self.lbl_risk.setText("NORMAL"); self.lbl_risk.setStyleSheet("font-size: 35px; color: #00ff88; font-weight: bold;")

            self.trend_points.append(len(data))
            if len(self.trend_points) > 20: self.trend_points.pop(0)
            self.curve.setData(self.trend_points)

            sev_rank = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
            for alert in data:
                ip  = str(alert.get("source_ip","0.0.0.0"))
                sev = str(alert.get("severity","LOW")).upper()
                etype = str(alert.get("event_type","System Event"))
                if ip == "0.0.0.0": continue
                self._all_ips.add(ip)
                if sev_rank.get(sev,0) > sev_rank.get(self._ip_severity.get(ip,"LOW"),0):
                    self._ip_severity[ip] = sev
                with self._geo_lock:
                    if ip not in self._geo_cache:
                        threading.Thread(target=self.geolocate_ip, args=(ip,), daemon=True).start()
                with self._threat_lock:
                    threat_missing = ip not in self._threat_cache
                if threat_missing:
                    threading.Thread(target=self._enrich_ip, args=(ip,), daemon=True).start()
                # Run rule engine for new alerts only
                if alert.get("id") not in previous_ids and self.db_path:
                    with self._threat_lock:
                        t_score = self._threat_cache.get(ip, {}).get("abuse_score", 0)
                    threading.Thread(target=self._run_rules, args=(ip, etype, sev, t_score), daemon=True).start()

            self._prev_ids = new_ids
            self.filter_table()
            self._refresh_threat_tab()
            self.update_stats_tab(data)
            self.update_timeline(data)

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
        data = self._all_alerts
        with self._geo_lock:    geo_snap    = dict(self._geo_cache)
        with self._threat_lock: threat_snap = dict(self._threat_cache)

        filtered = [a for a in data if
            search in str(a.get("source_ip","")).lower() or
            search in str(a.get("event_type","")).lower() or
            search in str(a.get("severity","")).lower() or
            search in str(a.get("status","")).lower() or
            search in geo_snap.get(str(a.get("source_ip","")),{}).get("country","").lower() or
            search in score_to_label(threat_snap.get(str(a.get("source_ip","")),{}).get("abuse_score",-1))[0].lower()
        ]

        self.table.clearContents(); self.table.setRowCount(len(filtered))
        for i, alert in enumerate(filtered):
            ip_val   = str(alert.get("source_ip","0.0.0.0"))
            type_val = str(alert.get("event_type","Detection"))
            sev_val  = str(alert.get("severity","LOW"))
            ts_val   = str(alert.get("timestamp",""))[:19]
            status   = str(alert.get("status","Logged"))
            country  = geo_snap.get(ip_val,{}).get("country","Detecting...")
            color    = SEV_COLORS.get(sev_val.upper(),"#ffffff")
            t_info   = threat_snap.get(ip_val,{})
            stored_score = int(alert.get("threat_score") or 0)
            ai_score = int(alert.get("ai_score") or 0)
            abuse_score = int(t_info.get("abuse_score") if t_info.get("abuse_score") is not None else -1)
            t_score  = max(stored_score, ai_score, abuse_score)
            t_label, t_color = score_to_label(t_score)
            threat_text = f"{t_label} ({t_score})" if t_score >= 0 else "CHECKING..."
            if status in ("Resolved","False Positive"):
                color = t_color = "#555555"
            ts_item = QTableWidgetItem(ts_val)
            ts_item.setData(Qt.ItemDataRole.UserRole, alert.get("id"))
            cells = [(ts_item,color),(QTableWidgetItem(ip_val),color),(QTableWidgetItem(country),color),
                     (QTableWidgetItem(type_val),color),(QTableWidgetItem(sev_val),color),
                     (QTableWidgetItem(threat_text),t_color),(QTableWidgetItem(status),color)]
            for j,(item,c) in enumerate(cells):
                item.setForeground(QColor(c)); self.table.setItem(i,j,item)

    def update_stats_tab(self, data):
        import math
        counts = Counter(a.get("event_type", "Unknown") for a in data)
        total  = len(data)

        # ── Pie chart ──
        CHART_COLORS = [
            "#ff4757","#ffa502","#ff6b81","#ff0000","#a29bfe",
            "#fd79a8","#00ff88","#74b9ff","#6c5ce7","#00cec9",
        ]
        self.pie_widget.clear()
        if total > 0:
            items = counts.most_common()
            angle = 0.0
            legend_y = 1.2
            for idx, (etype, count) in enumerate(items):
                frac  = count / total
                sweep = frac * 360.0
                color = CHART_COLORS[idx % len(CHART_COLORS)]
                # Draw pie slice as filled arc approximation using polygon
                pts_x, pts_y = [0.0], [0.0]
                steps = max(3, int(sweep / 3))
                for s in range(steps + 1):
                    a = math.radians(angle + s * sweep / steps)
                    pts_x.append(math.cos(a))
                    pts_y.append(math.sin(a))
                pts_x.append(0.0); pts_y.append(0.0)
                r, g, b = int(color[1:3],16), int(color[3:5],16), int(color[5:7],16)
                fill = pg.mkBrush(r, g, b, 200)
                outline = pg.mkPen(color="#0b0b1a", width=2)
                poly = pg.PlotDataItem(pts_x, pts_y, fillLevel=0,
                                       brush=fill, pen=outline)
                self.pie_widget.addItem(poly)
                # Label on slice
                mid_a = math.radians(angle + sweep / 2)
                lx = math.cos(mid_a) * 0.6
                ly = math.sin(mid_a) * 0.6
                if frac > 0.05:
                    txt = pg.TextItem(f"{frac*100:.0f}%", color=color, anchor=(0.5, 0.5))
                    txt.setPos(lx, ly)
                    self.pie_widget.addItem(txt)
                angle += sweep
            # Legend on the right
            for idx, (etype, count) in enumerate(items[:8]):
                color = CHART_COLORS[idx % len(CHART_COLORS)]
                legend_txt = pg.TextItem(
                    f"■ {etype[:18]} ({count})", color=color, anchor=(0, 0.5)
                )
                legend_txt.setPos(1.15, 1.1 - idx * 0.28)
                self.pie_widget.addItem(legend_txt)
            self.pie_widget.setXRange(-1.1, 2.6, padding=0)
            self.pie_widget.setYRange(-1.2, 1.4, padding=0)

        # ── Severity bar chart ──
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
                lbl.setPos(i, cnt)
                self.sev_widget.addItem(lbl)

        # ── Heatmap (day × hour scatter) ──
        self.heat_widget.clear()
        day_names = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
        heat = defaultdict(int)
        for alert in data:
            ts = alert.get("timestamp","")
            if ts:
                try:
                    dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
                    heat[(dt.weekday(), dt.hour)] += 1
                except:
                    pass
        if heat:
            max_val = max(heat.values()) or 1
            for (day, hour), cnt in heat.items():
                intensity = cnt / max_val
                r = int(108 + 147 * intensity)
                g = int(92  - 92  * intensity)
                b = int(231 - 231 * intensity)
                size = 6 + int(18 * intensity)
                dot = pg.ScatterPlotItem(
                    x=[hour], y=[day],
                    size=size,
                    brush=pg.mkBrush(r, g, b, 200),
                    pen=pg.mkPen(None)
                )
                self.heat_widget.addItem(dot)
        ax_l = self.heat_widget.getAxis("left")
        ax_l.setTicks([[(i, d) for i, d in enumerate(day_names)]])
        ax_l.setTextPen("#00f2ff")
        self.heat_widget.getAxis("bottom").setTextPen("#00f2ff")
        self.heat_widget.setYRange(-0.5, 6.5, padding=0)
        self.heat_widget.setXRange(-0.5, 23.5, padding=0)

        # ── Table ──
        self.stats_table.clearContents(); self.stats_table.setRowCount(len(counts))
        for i,(etype,count) in enumerate(counts.most_common()):
            pct = f"{(count/total*100):.1f}%" if total>0 else "0%"
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
            bg = pg.BarGraphItem(x=hours,height=counts,width=0.6,brush="#6c5ce7",pen=pg.mkPen("#a29bfe"))
            self.timeline_widget.addItem(bg)
        except Exception as e:
            print(f"[TIMELINE ERROR] {e}")

    def update_world_map(self):
        try:
            m = folium.Map(location=[20,0],zoom_start=2,tiles="OpenStreetMap")
            with self._geo_lock:    geo_snap    = dict(self._geo_cache)
            with self._threat_lock: threat_snap = dict(self._threat_cache)
            for ip in self._all_ips:
                geo = geo_snap.get(ip,{})
                lat,lng = geo.get("lat",0),geo.get("lng",0)
                if lat==0 and lng==0: continue
                sev    = self._ip_severity.get(ip,"LOW")
                t_score= threat_snap.get(ip,{}).get("abuse_score",-1)
                t_label,_ = score_to_label(t_score)
                popup_text = f"{ip} ({geo.get('country','?')})<br>Severity: {sev}<br>Threat: {t_label} ({t_score})"
                folium.Marker(location=[lat,lng],
                    popup=folium.Popup(popup_text,max_width=200),
                    icon=folium.Icon(color=MAP_COLORS.get(sev,"blue"),icon="info-sign")
                ).add_to(m)
            buf = io.BytesIO(); m.save(buf,close_file=False)
            self.web_view.setHtml(buf.getvalue().decode())
        except Exception as e:
            print(f"[MAP ERROR] {e}")

    def generate_pdf_report(self):
        try:
            pdf = FPDF(); pdf.add_page()
            pdf.set_font("Arial","B",16)
            pdf.cell(200,10,"SOC SECURITY INCIDENT REPORT",ln=True,align="C")
            pdf.set_font("Arial",size=8)
            pdf.cell(200,6,f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Operator: {self.username}  |  Role: {self.role}",ln=True,align="C")
            pdf.ln(6); pdf.set_font("Arial","B",9)
            pdf.cell(0,8,"Timestamp | IP | Country | Event | Severity | Threat Score | Status",ln=True)
            pdf.set_font("Arial",size=8)
            for i in range(self.table.rowCount()):
                def _get(col): return self.table.item(i,col).text() if self.table.item(i,col) else "N/A"
                ts,ip,country,event,sev,threat,status = [_get(c) for c in range(7)]
                pdf.cell(0,7,f"[{ts}] {ip} | {country} | {event} | {sev} | {threat} | {status}",ln=True)
            pdf.output("Security_Report.pdf")
            QMessageBox.information(self,"Success","PDF Generated: Security_Report.pdf")
        except Exception as e:
            QMessageBox.critical(self,"Error",f"Failed: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SOCDashboard()
    window.show()
    sys.exit(app.exec())
