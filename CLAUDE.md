# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the application

```bash
# Full app (UDP engine + Flask API + PyQt6 GUI)
python start.py

# Send simulated attacks to a running instance
python test_siem.py

# Run regression tests
python -m pytest tests/test_regressions.py -v
```

The login screen appears first. The first-run admin password is printed to the console if `SOC_ADMIN_PASSWORD` is not set in `.env`. Alternatively the README says `admin` / `admin123` if the DB was seeded that way.

Ollama must be running before starting (`ollama serve`). The app degrades gracefully if it isn't — reports are silently skipped.

## Architecture

### Startup flow (`start.py`)
Three concurrent threads launched from `start.py`:
1. `siem_listener.start_listener()` — UDP socket on `:5555`, the full detection pipeline
2. Flask API (`backend/api.py`) on `:5000` — polled by the GUI every 500ms
3. PyQt6 GUI (`gui/app.py`) — `SOCDashboard` on the main thread after `LoginWindow`

### Per-event pipeline (`siem_listener.py`)
Every UDP packet flows through this sequence synchronously, then fires async workers:

```
extract_ip() → detect_event() → check_anomaly() → analyze_behavior()
→ scan_log_sync() [VT cache] → analyze_log() [heuristic+Ollama llama3.1]
→ INSERT incidents
→ [async] scan_log_async()          — live VT API, patches row
→ [async] enrich_incident_async()   — Shodan/GreyNoise/URLScan/VT-URL, patches row
→ [async] generate_report_async()   — SOC_REPORT_MODEL (default deepseek:latest), writes to reports table
```

### Detection layers (`core/`)
- `detector.py` — keyword/regex signature matching → (event_type, severity, category). Also `check_anomaly()` which runs a z-score on per-IP event rate.
- `behavioral.py` — in-memory sliding-window detectors: password spray, credential stuffing, distributed bruteforce, beaconing (CV of inter-arrival times), lateral movement, low-and-slow port scan, DNS tunneling.
- `ai_analyzer.py` — `analyze_log()`: heuristic scorer + optional Ollama llama3.1. Accepts `vt_score`, `behavior_score`, `shodan_score`, `greynoise_score`, `urlscan_score`, `vt_url_score` and folds them into a final 0-100 `threat_score`. Auto-block fires at `SOC_AUTO_BLOCK_SCORE` (default 90).
- `virustotal.py` — file hash extraction from logs + VT v3 API. Rate-limited to 4/min. Cache in `vt_cache` table.
- `threat_enrichment.py` — four external enrichment APIs, each cache-first + async live patch:
  - Shodan → port scan / recon events
  - GreyNoise → bruteforce / DDoS / port scan (Community API works without a key)
  - URLScan.io → C2 / web attack events (submits URLs, polls for verdict)
  - VT URL/domain → C2 / DNS tunneling events
- `ollama_reporter.py` — sends incident context to deepseek-coder-v2:16b, stores structured JSON (MITRE, IOCs, actions, confidence) in `reports` table. Skips LOW-severity events with score < 30.
- `pdf_report.py` — three-stage PDF: collect DB data → Ollama executive summary → fpdf2 layout (cover, stats, incident cards with deepseek analysis, recommendations, blocklist appendix).

### Rule engine v2 (`responder.py`)
`evaluate_rules_v2()` evaluates `rules_v2` DB table in priority order. Each rule has:
- JSON conditions array (field / op / value), AND or OR mode
- Matchable fields: `event_type`, `severity`, `category`, `source_ip`, `threat_score`, `behavior_score`, `vt_score`, `anomaly_score`, `raw_log`, `hour`, `day_of_week`
- Operators: `eq`, `neq`, `contains`, `regex`, `in`, `gt`, `lt`, `gte`, `lte`, `between`
- Actions: block, email, quarantine, escalate, webhook (any combination)
- Per-rule cooldown, priority, stop_on_match, CIDR exclusion list
- In-memory windows for threshold counting, in-memory cooldown tracker

Old v1 rule functions (`get_rules`, `add_rule`, etc.) are still present for backward compatibility but the GUI and engine exclusively use v2.

### Database (`incidents.db`)
Single SQLite file. Key tables:
- `incidents` — one row per event, patched async by enrichment workers
- `reports` — deepseek per-incident reports, linked by `incident_id`
- `rules_v2` — rule engine definitions
- `blocklist` — auto-blocked + manually blocked IPs
- `vt_cache`, `shodan_cache`, `greynoise_cache`, `urlscan_cache`, `vt_url_cache` — 24h TTL enrichment caches
- `threat_intel` — AbuseIPDB cache
- `quarantine`, `rule_triggers`, `sandbox_jobs` — SOAR audit tables

Schema migration is additive-only (`ALTER TABLE ADD COLUMN`) via `core/schema.py:ensure_incident_schema()`. Called at startup and by the Flask API on every request.

### GUI (`gui/app.py`)
`SOCDashboard` polls `GET /incidents` every 500ms. All tabs auto-refresh on the same timer tick — no manual refresh buttons. Key signals:
- `_threat_ready` — emitted by AbuseIPDB background thread, triggers threat tab refresh
- `_action_signal` — emitted by rule engine thread, updates action label and blocklist tab

Incident detail panel (`_show_selected_alert_details`) renders HTML via `QTextEdit.setHtml()`. It fetches the deepseek report from the DB on every selection and re-renders every timer tick while a row is selected, so the AI report appears automatically when it arrives.

`RuleBuilderDialog` — full multi-condition rule editor. `ConditionRow` widget dynamically adjusts operator dropdown based on field type (string vs numeric).

**Design target: 1920×1080.** Key QSS/sizing conventions to preserve:
- `STYLE_SOC` is the single stylesheet applied to the whole dashboard. All theme changes go there.
- Buttons: `padding: 8px 18px; min-height: 32px` — do not reduce below this.
- Table items: `min-height: 28px` — do not use `setFixedHeight` on row items.
- Scrollbars: 10px wide/tall with visible hover state — do not shrink back to 6px.
- QSplitter handles: styled in STYLE_SOC with 5px grab area and purple hover — do not remove.
- All interactive elements (buttons, table viewports, zoom buttons) must have `setCursor(Qt.CursorShape.PointingHandCursor)` applied in Python code — QSS cursor property is not used.
- Report detail panel TextEdits use `setMinimumHeight` + `Expanding` size policy — do not revert to `setFixedHeight` or the splitter cannot use the space.
- Stat cards are `172×96` — do not shrink back to `148×72`.
- `_make_stat_card` title labels: 11px. Value labels: 26px.
- All tab/section title labels: 13px `#00f2ff` bold.
- **Live attack map** (`self.web_view`): uses `setMinimumHeight(map_h)` (not `setFixedHeight`). Flex factor 2 vs trend chart's 1 — map always larger. Do not swap these.
- **Zoom buttons** next to the search bar are labeled `A−` / `A+` (font-size adjust). Width 48 px. Do not shrink back to 30 px or remove labels.
- **Rule engine table** (`self.rules_table`): 8 columns — `["Pri","Name","Conditions","Thr/Win","Actions","Cooldown","On","Edit"]`. All use `Interactive` resize mode with explicit `setColumnWidth` initial values. Column 7 header is `"Edit"` (not empty).
- **Live alerts table** (`self.table`): Uses `Interactive` resize mode with `setStretchLastSection(True)`. Do not revert to `Stretch` on all columns — that removes user resize ability.
- **Login password field** (`PasswordLineEdit`): subclass of `QLineEdit` with an embedded `_EyeButton` child positioned at the right edge. The eye paints itself via `QPainter`. There is no separate `btn_toggle` QPushButton. Do not re-add one.

## Key env vars

| Variable | Purpose |
|---|---|
| `SOC_AUTO_BLOCK_SCORE` | Threat score threshold for auto-block (default 90) |
| `SOC_REPORT_MODEL` | Ollama model for incident reports (default `deepseek:latest`) |
| `OLLAMA_MODEL` | Ollama model for real-time heuristic scoring (default `llama3.1`) |
| `SOC_ENABLE_REPORTS` | Set to `0` to disable report generation |
| `VT_API_KEY` | VirusTotal file hash + URL/domain lookups |
| `SHODAN_API_KEY` | Open ports + CVEs on source IPs (Port Scan / Recon events) |
| `GREYNOISE_API_KEY` | Mass-scanner classification — Community API works without a key |
| `URLSCAN_API_KEY` | URL sandbox for C2/web attack events |

## Commit rules

- Never append `Co-Authored-By: Claude ...` lines to commit messages.
