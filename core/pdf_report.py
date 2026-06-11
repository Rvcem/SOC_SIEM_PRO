"""
PDF report generator — Ollama-enhanced structured report.

Pipeline:
  1. Collect  — pull incidents + deepseek per-incident reports from DB
  2. Synthesise — ask deepseek to write an executive summary over the full digest
  3. Layout   — fpdf2 structured PDF with cover, stats, exec summary,
                incident cards (with MITRE / enrichment / actions), recommendations

Call generate_pdf(db_path, output_path, operator, role, hours=24)
It returns immediately — generation happens in a background thread.
The callback(path, error) is called when done (error is None on success).
"""

import os
import re
import sqlite3
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import requests
from fpdf import FPDF
from fpdf.enums import XPos, YPos

OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
REPORT_MODEL = os.getenv("SOC_REPORT_MODEL", "deepseek-coder-v2:16b")

# ── Colour palette ────────────────────────────────────────────────────────────
C_BG        = (11,  11,  26)
C_CARD      = (22,  22,  51)
C_ACCENT    = (0,   242, 255)
C_PURPLE    = (108, 92,  231)
C_RED       = (255, 0,   0)
C_ORANGE    = (255, 165, 0)
C_GREEN     = (0,   255, 136)
C_WHITE     = (255, 255, 255)
C_GREY      = (160, 160, 180)
C_DARKGREY  = (60,  60,  80)

SEV_COLORS  = {
    "CRITICAL": (255, 0,   0),
    "HIGH":     (255, 71,  87),
    "MEDIUM":   (255, 165, 0),
    "LOW":      (0,   255, 136),
}

# ── Data collection ───────────────────────────────────────────────────────────

def _collect(db_path: str, hours: int) -> dict:
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        incidents = [dict(r) for r in conn.execute("""
            SELECT * FROM incidents
            WHERE timestamp >= ?
            ORDER BY threat_score DESC, id DESC
        """, (since,)).fetchall()]

        report_map = {}
        for r in conn.execute("""
            SELECT r.*, i.timestamp as inc_ts
            FROM reports r JOIN incidents i ON r.incident_id = i.id
            WHERE i.timestamp >= ?
        """, (since,)).fetchall():
            row = dict(r)
            report_map[row["incident_id"]] = row

        blocklist = [dict(r) for r in conn.execute(
            "SELECT ip, reason, added_at FROM blocklist ORDER BY added_at DESC"
        ).fetchall()]

    # Attach reports to incidents
    for inc in incidents:
        inc["_report"] = report_map.get(inc["id"])

    # Stats
    total      = len(incidents)
    by_sev     = Counter(str(i.get("severity","LOW")).upper() for i in incidents)
    by_type    = Counter(str(i.get("event_type","Unknown")) for i in incidents)
    blocked    = sum(1 for i in incidents if i.get("status") == "Blocked")
    by_ip      = Counter(i.get("source_ip","?") for i in incidents)
    top_ips    = by_ip.most_common(10)
    avg_threat = (sum(i.get("threat_score",0) or 0 for i in incidents) / total) if total else 0

    critical_high = [i for i in incidents
                     if str(i.get("severity","")).upper() in ("CRITICAL","HIGH")]

    return {
        "incidents":    incidents,
        "critical_high": critical_high,
        "report_map":   report_map,
        "blocklist":    blocklist,
        "total":        total,
        "by_sev":       by_sev,
        "by_type":      by_type,
        "blocked":      blocked,
        "top_ips":      top_ips,
        "avg_threat":   avg_threat,
        "hours":        hours,
        "since":        since,
    }

# ── Ollama executive summary ──────────────────────────────────────────────────

def _build_digest(data: dict) -> str:
    lines = [
        f"Time window: last {data['hours']} hours",
        f"Total incidents: {data['total']}",
        f"Critical: {data['by_sev'].get('CRITICAL',0)}  High: {data['by_sev'].get('HIGH',0)}  "
        f"Medium: {data['by_sev'].get('MEDIUM',0)}  Low: {data['by_sev'].get('LOW',0)}",
        f"Auto-blocked IPs: {data['blocked']}",
        f"Average threat score: {data['avg_threat']:.1f}/100",
        "",
        "Top event types:",
    ]
    for etype, cnt in data["by_type"].most_common(8):
        lines.append(f"  {etype}: {cnt}")
    lines += ["", "Top source IPs:"]
    for ip, cnt in data["top_ips"][:8]:
        lines.append(f"  {ip}: {cnt} events")

    # Summarise up to 12 deepseek per-incident reports
    reports_used = [v for v in data["report_map"].values() if v.get("attack_summary")][:12]
    if reports_used:
        lines += ["", "Per-incident AI findings (sample):"]
        for r in reports_used:
            inc_id = r.get("incident_id","?")
            lines.append(
                f"  [{inc_id}] {r.get('attack_summary','')[:180]}"
                f" | MITRE: {r.get('mitre_tactics','')[:60]}"
            )
    return "\n".join(lines)


def _ollama_executive_summary(data: dict) -> dict:
    digest = _build_digest(data)
    prompt = f"""You are a senior SOC analyst writing an executive security report.
Below is a digest of security incidents from the last {data['hours']} hours.

{digest}

Respond with ONLY valid JSON (no markdown, no explanation) matching this schema exactly:
{{
  "executive_summary": "<3-5 sentence overview of the threat landscape and most significant findings>",
  "key_attack_patterns": ["<pattern 1>", "<pattern 2>", "<pattern 3>"],
  "risk_level": "<CRITICAL | HIGH | MEDIUM | LOW>",
  "risk_justification": "<1-2 sentences explaining the risk level>",
  "top_recommendations": ["<specific actionable recommendation>", ...],
  "immediate_actions": ["<action that should be taken right now>", ...]
}}"""

    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": REPORT_MODEL, "prompt": prompt, "stream": False},
            timeout=120,
        )
        if r.status_code != 200:
            return {}
        text = r.json().get("response", "")
        text = re.sub(r"```(?:json)?", "", text).strip().rstrip("`").strip()
        m = re.search(r'\{[\s\S]+\}', text)
        if m:
            import json
            return json.loads(m.group(0))
    except Exception as exc:
        print(f"[PDF] Ollama executive summary failed: {exc}")
    return {}

# ── PDF layout ────────────────────────────────────────────────────────────────

class _SOCReport(FPDF):
    def __init__(self, operator, role):
        super().__init__()
        self.operator = operator
        self.role     = role
        self.set_auto_page_break(auto=True, margin=14)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _rgb(self, triple):
        self.set_text_color(*triple)

    def _fill(self, triple):
        self.set_fill_color(*triple)

    def _draw(self, triple):
        self.set_draw_color(*triple)

    def _safe(self, text: str) -> str:
        """Strip characters fpdf Latin-1 can't encode."""
        return "".join(c if ord(c) < 256 else "?" for c in str(text or ""))

    def _wrap(self, text: str, width: int = 95) -> list:
        words = self._safe(text).split()
        lines, line = [], ""
        for w in words:
            if len(line) + len(w) + 1 <= width:
                line = (line + " " + w).strip()
            else:
                if line: lines.append(line)
                line = w
        if line: lines.append(line)
        return lines or [""]

    # ── Cover page ────────────────────────────────────────────────────────────

    def cover(self, data: dict, exec_summary: dict):
        self.add_page()
        # dark background
        self._fill(C_BG)
        self.rect(0, 0, 210, 297, "F")

        # top accent bar
        self._fill(C_PURPLE)
        self.rect(0, 0, 210, 3, "F")

        # logo / title block
        self.set_y(30)
        self._rgb(C_ACCENT)
        self.set_font("Courier", "B", 22)
        self.cell(0, 10, "SOC SIEM PRO", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self._rgb(C_WHITE)
        self.set_font("Courier", "B", 14)
        self.cell(0, 8, "SECURITY INCIDENT REPORT", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.ln(4)
        self._rgb(C_GREY)
        self.set_font("Courier", "", 9)
        self.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC  |  "
                         f"Operator: {self.operator.upper()}  |  Role: {self.role.upper()}  |  "
                         f"Coverage: last {data['hours']}h",
                  align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # horizontal rule
        self.ln(6)
        self._draw(C_PURPLE)
        self.set_draw_color(*C_PURPLE)
        self.line(20, self.get_y(), 190, self.get_y())
        self.ln(8)

        # risk badge
        risk = exec_summary.get("risk_level", "UNKNOWN")
        risk_col = SEV_COLORS.get(risk, C_GREY)
        self._fill(risk_col)
        self._rgb(C_BG if risk == "LOW" else C_WHITE)
        self.set_font("Courier", "B", 16)
        self.set_x(70)
        self.cell(70, 12, f"  OVERALL RISK: {risk}  ", align="C",
                  fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        if exec_summary.get("risk_justification"):
            self._rgb(C_GREY)
            self.set_font("Courier", "", 8)
            self.set_x(25)
            self.multi_cell(160, 5, self._safe(exec_summary["risk_justification"]), align="C")
        self.ln(8)

        # stat boxes row
        stats = [
            ("TOTAL EVENTS",    str(data["total"]),          C_ACCENT),
            ("CRITICAL",        str(data["by_sev"].get("CRITICAL",0)), C_RED),
            ("HIGH",            str(data["by_sev"].get("HIGH",0)),    (255,71,87)),
            ("AUTO-BLOCKED",    str(data["blocked"]),          (253,121,168)),
            ("AVG THREAT",      f"{data['avg_threat']:.0f}/100", C_ORANGE),
        ]
        box_w, box_h = 32, 20
        start_x = (210 - len(stats) * (box_w + 4)) / 2
        y0 = self.get_y()
        for idx, (label, value, col) in enumerate(stats):
            x = start_x + idx * (box_w + 4)
            self._fill(C_CARD)
            self._draw(col)
            self.set_draw_color(*col)
            self.set_line_width(0.5)
            self.rect(x, y0, box_w, box_h, "FD")
            self._rgb(col)
            self.set_font("Courier", "B", 13)
            self.set_xy(x, y0 + 2)
            self.cell(box_w, 7, value, align="C")
            self._rgb(C_GREY)
            self.set_font("Courier", "", 6)
            self.set_xy(x, y0 + 10)
            self.cell(box_w, 5, label, align="C")
        self.set_line_width(0.2)
        self.ln(box_h + 10)

        # executive summary box
        if exec_summary.get("executive_summary"):
            self._fill(C_CARD)
            bx, by, bw = 20, self.get_y(), 170
            # measure height first
            lines = self._wrap(exec_summary["executive_summary"], 95)
            bh = 10 + len(lines) * 5.5
            self.rect(bx, by, bw, bh, "F")
            self._rgb(C_ACCENT)
            self.set_font("Courier", "B", 8)
            self.set_xy(bx + 4, by + 3)
            self.cell(bw - 8, 5, "EXECUTIVE SUMMARY")
            self._rgb(C_WHITE)
            self.set_font("Courier", "", 8)
            self.set_xy(bx + 4, by + 8)
            self.multi_cell(bw - 8, 5.5, self._safe(exec_summary["executive_summary"]))
            self.set_y(by + bh + 6)

        # top recommendations preview
        recs = exec_summary.get("top_recommendations", [])
        if recs:
            self._rgb(C_ACCENT)
            self.set_font("Courier", "B", 8)
            self.cell(0, 6, "KEY RECOMMENDATIONS", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self._rgb(C_GREEN)
            self.set_font("Courier", "", 8)
            for rec in recs[:4]:
                self.cell(6, 5, "")
                self.multi_cell(160, 5, self._safe(f"* {rec}"))

        # bottom bar
        self._fill(C_PURPLE)
        self.rect(0, 292, 210, 5, "F")

    # ── Section header ────────────────────────────────────────────────────────

    def section(self, title: str):
        if self.get_y() > 260:
            self.add_page()
            self._fill(C_BG)
            self.rect(0, 0, 210, 297, "F")
        self.ln(4)
        self._fill(C_PURPLE)
        self.rect(14, self.get_y(), 182, 7, "F")
        self._rgb(C_WHITE)
        self.set_font("Courier", "B", 9)
        self.set_x(17)
        self.cell(0, 7, title.upper(), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    # ── Statistics page ───────────────────────────────────────────────────────

    def stats_page(self, data: dict):
        self.add_page()
        self._fill(C_BG)
        self.rect(0, 0, 210, 297, "F")
        self.section("1. STATISTICS OVERVIEW")

        # Severity table
        self._rgb(C_ACCENT)
        self.set_font("Courier", "B", 8)
        self.cell(0, 5, "Severity Breakdown", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW"):
            cnt = data["by_sev"].get(sev, 0)
            pct = (cnt / data["total"] * 100) if data["total"] else 0
            col = SEV_COLORS.get(sev, C_WHITE)
            # bar
            bar_w = max(1, int(pct * 1.2))
            self._fill(col)
            self.rect(14, self.get_y() + 1, bar_w, 4, "F")
            self._rgb(col)
            self.set_font("Courier", "B", 8)
            self.set_x(14)
            self.cell(28, 6, sev)
            self._rgb(C_WHITE)
            self.set_font("Courier", "", 8)
            self.cell(20, 6, str(cnt))
            self._rgb(C_GREY)
            self.cell(0, 6, f"{pct:.1f}%", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(4)

        # Top event types
        self.section("TOP EVENT TYPES")
        self._rgb(C_ACCENT)
        self.set_font("Courier", "B", 8)
        headers = ["Event Type", "Count", "% Share"]
        widths  = [100, 25, 30]
        for h, w in zip(headers, widths):
            self.cell(w, 6, h)
        self.ln()
        self._rgb(C_WHITE)
        self.set_font("Courier", "", 8)
        for etype, cnt in data["by_type"].most_common(15):
            pct = (cnt / data["total"] * 100) if data["total"] else 0
            self.cell(100, 5.5, self._safe(etype[:50]))
            self.cell(25,  5.5, str(cnt))
            self.cell(30,  5.5, f"{pct:.1f}%")
            self.ln()
        self.ln(4)

        # Top attacker IPs
        self.section("TOP ATTACKER IPs")
        self._rgb(C_ACCENT)
        self.set_font("Courier", "B", 8)
        for h, w in zip(["Source IP","Event Count","Threat Score"], [60,35,35]):
            self.cell(w, 6, h)
        self.ln()
        self._rgb(C_WHITE)
        self.set_font("Courier", "", 8)
        # Find max threat score per IP
        ip_score = {}
        for inc in data["incidents"]:
            ip = inc.get("source_ip","?")
            ip_score[ip] = max(ip_score.get(ip,0), inc.get("threat_score",0) or 0)
        for ip, cnt in data["top_ips"]:
            score = ip_score.get(ip, 0)
            col = SEV_COLORS["CRITICAL"] if score >= 80 else \
                  SEV_COLORS["HIGH"]     if score >= 55 else \
                  SEV_COLORS["MEDIUM"]   if score >= 30 else C_GREEN
            self._rgb(col)
            self.cell(60, 5.5, ip)
            self._rgb(C_WHITE)
            self.cell(35, 5.5, str(cnt))
            self._rgb(col)
            self.cell(35, 5.5, str(score))
            self.ln()

    # ── Incident card ─────────────────────────────────────────────────────────

    def incident_card(self, inc: dict):
        sev   = str(inc.get("severity","LOW")).upper()
        col   = SEV_COLORS.get(sev, C_WHITE)
        rep   = inc.get("_report")
        needed = 28 + (40 if rep else 0)
        if self.get_y() + needed > 274:
            self.add_page()
            self._fill(C_BG)
            self.rect(0, 0, 210, 297, "F")

        y0 = self.get_y()
        # card background
        self._fill(C_CARD)
        self._draw(col)
        self.set_draw_color(*col)
        self.set_line_width(0.4)

        # header row — darkened version of the severity colour
        self.set_fill_color(col[0]//3, col[1]//3, col[2]//3)
        self.rect(14, y0, 182, 7, "F")
        self._rgb(col)
        self.set_font("Courier", "B", 8)
        self.set_xy(16, y0 + 1)
        self.cell(60, 5, f"#{inc.get('id')}  {sev}")
        self._rgb(C_WHITE)
        self.cell(70, 5, self._safe(str(inc.get("event_type",""))[:35]))
        self._rgb(C_GREY)
        self.set_font("Courier", "", 7)
        self.cell(0, 5, str(inc.get("timestamp",""))[:19], align="R")
        self.ln(7)

        # meta row
        self._rgb(C_GREY)
        self.set_font("Courier", "", 7)
        self.set_x(16)
        self.cell(45, 4.5, f"IP: {inc.get('source_ip','?')}")
        self.cell(30, 4.5, f"Threat: {inc.get('threat_score',0)}/100")
        self.cell(30, 4.5, f"VT: {inc.get('vt_score',0)}")
        self.cell(35, 4.5, f"Behavior: {inc.get('behavior_score',0)}")
        self.cell(0,  4.5, f"Status: {inc.get('status','')}")
        self.ln(5)

        # enrichment badges inline
        enrichments = []
        if inc.get("greynoise_classification"):
            enrichments.append(f"GreyNoise:{inc['greynoise_classification']}")
        if inc.get("shodan_score",0):
            enrichments.append(f"Shodan:{inc['shodan_score']}/100")
        if inc.get("urlscan_verdict"):
            enrichments.append(f"URLScan:{inc['urlscan_verdict']}")
        if inc.get("vt_url_score",0):
            enrichments.append(f"VT-URL:{inc['vt_url_score']}/100")
        if enrichments:
            self._rgb(C_PURPLE)
            self.set_font("Courier", "", 7)
            self.set_x(16)
            self.cell(0, 4.5, "  ".join(enrichments), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(1)

        # deepseek report block
        if rep:
            if rep.get("attack_summary"):
                self._rgb(C_ACCENT)
                self.set_font("Courier", "B", 7)
                self.set_x(16)
                self.cell(0, 4.5, "AI Analysis:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self._rgb(C_WHITE)
                self.set_font("Courier", "", 7)
                self.set_x(20)
                self.multi_cell(172, 4, self._safe(rep["attack_summary"][:300]))

            if rep.get("mitre_tactics") or rep.get("mitre_techniques"):
                self._rgb((163, 155, 246))
                self.set_font("Courier", "", 7)
                self.set_x(16)
                tactics = self._safe((rep.get("mitre_tactics") or "")[:80])
                techs   = self._safe((rep.get("mitre_techniques") or "")[:80])
                self.cell(0, 4, f"MITRE: {tactics}  |  {techs}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            if rep.get("recommended_actions"):
                self._rgb(C_GREEN)
                self.set_font("Courier", "", 7)
                self.set_x(16)
                actions = "; ".join(
                    a.strip() for a in rep["recommended_actions"].split(";") if a.strip()
                )[:200]
                self.multi_cell(172, 4, self._safe(f"Actions: {actions}"))
        else:
            # fallback: heuristic summary
            if inc.get("ai_summary"):
                self._rgb(C_GREY)
                self.set_font("Courier", "", 7)
                self.set_x(16)
                self.multi_cell(172, 4, self._safe(str(inc["ai_summary"])[:200]))

        # bottom rule
        self._fill(C_DARKGREY)
        self.rect(14, self.get_y() + 1, 182, 0.3, "F")
        self.ln(4)
        self.set_line_width(0.2)

    # ── Recommendations page ──────────────────────────────────────────────────

    def recommendations_page(self, exec_summary: dict):
        self.add_page()
        self._fill(C_BG)
        self.rect(0, 0, 210, 297, "F")
        self.section("RECOMMENDATIONS & NEXT STEPS")

        sections = [
            ("IMMEDIATE ACTIONS",  exec_summary.get("immediate_actions",   []), C_RED),
            ("TOP RECOMMENDATIONS", exec_summary.get("top_recommendations", []), C_GREEN),
            ("KEY ATTACK PATTERNS", exec_summary.get("key_attack_patterns", []), C_ORANGE),
        ]
        for title, items, col in sections:
            if not items:
                continue
            self.ln(2)
            self._rgb(col)
            self.set_font("Courier", "B", 8)
            self.cell(0, 6, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self._rgb(C_WHITE)
            self.set_font("Courier", "", 8)
            for item in items:
                self.set_x(18)
                self.multi_cell(174, 5, self._safe(f"*  {item}"))
            self.ln(2)

    # ── Footer on every page ──────────────────────────────────────────────────

    def footer(self):
        self.set_y(-10)
        self._rgb(C_DARKGREY)
        self.set_font("Courier", "", 7)
        self.cell(0, 5, f"SOC SIEM PRO  |  Confidential  |  Page {self.page_no()}", align="C")


# ── Public entry point ────────────────────────────────────────────────────────

def _build_pdf(db_path: str, output_path: str, operator: str, role: str, hours: int) -> str:
    data = _collect(db_path, hours)

    # Stage 2: Ollama executive summary
    print("[PDF] Requesting executive summary from Ollama...")
    exec_summary = _ollama_executive_summary(data)
    if not exec_summary:
        exec_summary = {
            "executive_summary": (
                f"This report covers {data['total']} security incidents over the last {hours} hours. "
                f"Critical events: {data['by_sev'].get('CRITICAL',0)}. "
                f"Auto-blocked IPs: {data['blocked']}."
            ),
            "risk_level": "HIGH" if data["by_sev"].get("CRITICAL",0) > 0 else "MEDIUM",
            "risk_justification": "Based on incident volume and severity distribution.",
            "top_recommendations": ["Review and investigate all CRITICAL incidents.",
                                    "Verify blocklist is current.",
                                    "Check for lateral movement indicators."],
            "immediate_actions":   ["Investigate top attacker IPs immediately."],
            "key_attack_patterns": [t for t, _ in data["by_type"].most_common(3)],
        }

    # Stage 3: Layout
    print("[PDF] Building PDF layout...")
    pdf = _SOCReport(operator, role)
    pdf.set_margins(14, 14, 14)

    # Cover
    pdf.cover(data, exec_summary)

    # Statistics
    pdf.stats_page(data)

    # Incident cards — CRITICAL + HIGH first, then others up to 60 total
    cards = data["critical_high"][:40]
    remaining = [i for i in data["incidents"] if i not in cards]
    cards += remaining[:20]

    if cards:
        pdf.add_page()
        pdf._fill(C_BG)
        pdf.rect(0, 0, 210, 297, "F")
        pdf.section(f"2. INCIDENT DETAILS  ({len(cards)} of {data['total']} shown, prioritised by severity)")
        for inc in cards:
            pdf.incident_card(inc)

    # Recommendations
    if any(exec_summary.get(k) for k in ("immediate_actions","top_recommendations","key_attack_patterns")):
        pdf.recommendations_page(exec_summary)

    # Blocklist appendix
    if data["blocklist"]:
        pdf.add_page()
        pdf._fill(C_BG)
        pdf.rect(0, 0, 210, 297, "F")
        pdf.section(f"3. BLOCKED IP ADDRESSES  ({len(data['blocklist'])} total)")
        pdf._rgb(C_ACCENT)
        pdf.set_font("Courier", "B", 8)
        for h, w in zip(["IP Address","Reason","Blocked At"], [45,105,36]):
            pdf.cell(w, 6, h)
        pdf.ln()
        pdf._rgb(C_WHITE)
        pdf.set_font("Courier", "", 7)
        for entry in data["blocklist"][:80]:
            pdf._rgb((255, 71, 87))
            pdf.cell(45,  5, pdf._safe(entry.get("ip","")))
            pdf._rgb(C_GREY)
            pdf.cell(105, 5, pdf._safe(str(entry.get("reason",""))[:65]))
            pdf._rgb(C_DARKGREY)
            pdf.cell(36,  5, pdf._safe(str(entry.get("added_at",""))[:19]))
            pdf.ln()

    pdf.output(output_path)
    print(f"[PDF] Saved to {output_path}")
    return output_path


def generate_pdf(
    db_path: str,
    output_path: str,
    operator: str = "operator",
    role: str = "analyst",
    hours: int = 24,
    callback=None,
):
    """
    Non-blocking entry point. Runs generation in a background thread.
    callback(path, error) is called when done; error is None on success.
    """
    def _run():
        try:
            path = _build_pdf(db_path, output_path, operator, role, hours)
            if callback:
                callback(path, None)
        except Exception as exc:
            print(f"[PDF ERROR] {exc}")
            if callback:
                callback(None, str(exc))

    threading.Thread(target=_run, daemon=True).start()
