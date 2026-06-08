"""Behavioral analytics engine.

Detects attack patterns that require tracking state across multiple log events:

  - Password spraying     : 1 IP targeting many different usernames
  - Credential stuffing   : 1 IP, extremely high-volume auth attempts
  - Distributed bruteforce: many IPs targeting the same account
  - Beaconing             : periodic connections with low inter-arrival jitter
  - Lateral movement      : connections from one IP to many distinct internal hosts
  - DNS tunneling         : high-frequency DNS queries with abnormally long labels
  - Slow / low-and-slow scan: port scan spread over a long time window

All state is kept in bounded in-memory deques — no disk I/O in the hot path.
"""

import math
import re
import time
from collections import defaultdict, deque

# ── In-memory state ───────────────────────────────────────────────────────────

_ip_auth       = defaultdict(lambda: deque(maxlen=300))   # ip -> [{ts, user, success}]
_user_auth     = defaultdict(lambda: deque(maxlen=500))   # user -> [{ts, ip}]
_ip_conns      = defaultdict(lambda: deque(maxlen=400))   # ip -> [{ts, dest_ip, port}]
_ip_beacon_ts  = defaultdict(lambda: deque(maxlen=120))   # ip -> [ts, ...]
_ip_dns        = defaultdict(lambda: deque(maxlen=300))   # ip -> [{ts, domain, length}]
_ip_ports_seen = defaultdict(lambda: deque(maxlen=500))   # ip -> [{ts, port}]

# ── Field extractors ──────────────────────────────────────────────────────────

_USER_RE    = re.compile(r'(?:for(?:\s+invalid\s+user)?|user[=:\s])[\s]*([\w.\-@]+)', re.I)
_DEST_IP_RE = re.compile(r'(?:to|dst|dest(?:ination)?)[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})', re.I)
_PORT_RE    = re.compile(r'(?:port|dport|dst_port)[=:\s]+(\d{1,5})', re.I)
_DNS_RE     = re.compile(r'(?:query|dns\s+request|resolve)[=:\s]+([a-zA-Z0-9.\-]{8,})', re.I)


def _user(log: str):
    m = _USER_RE.search(log)
    return m.group(1).lower() if m else None


def _dest_ip(log: str):
    m = _DEST_IP_RE.search(log)
    return m.group(1) if m else None


def _port(log: str):
    m = _PORT_RE.search(log)
    try:
        return int(m.group(1)) if m else None
    except ValueError:
        return None


def _domain(log: str):
    m = _DNS_RE.search(log)
    return m.group(1).lower() if m else None


def _is_internal(ip: str) -> bool:
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.")
        or ip.startswith("fd")  # IPv6 ULA prefix (simplified)
    )

# ── Beaconing detector ────────────────────────────────────────────────────────

def _beacon_regularity(timestamps: list) -> float:
    """
    Coefficient-of-variation approach: low CV of inter-arrival times = regular = beaconing.
    Returns a 0.0-1.0 regularity score.  >= 0.75 is strong beaconing signal.
    """
    if len(timestamps) < 6:
        return 0.0
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    mean = sum(intervals) / len(intervals)
    if mean < 2:  # sub-2-second intervals are just floods, not beaconing
        return 0.0
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    cv = math.sqrt(variance) / mean  # coefficient of variation
    # CV < 0.10 → near-perfect regularity; scale to 0-1
    return max(0.0, min(1.0, 1.0 - (cv / 0.25)))

# ── Main entry point ──────────────────────────────────────────────────────────

def analyze_behavior(raw_log: str, source_ip: str, event_type: str, severity: str) -> dict:
    """
    Update behavioral state and evaluate detection rules for *source_ip*.

    Returns:
        {
            "alerts":         [str, ...],   # human-readable alert descriptions
            "behavior_score": int,          # 0-100 additive threat score
        }
    """
    now       = time.time()
    log_lower = raw_log.lower()
    alerts    = []
    score     = 0

    # ── Auth-based tracking ───────────────────────────────────────────────────
    is_fail = any(k in log_lower for k in (
        "failed password", "invalid user", "authentication failure",
        "login failed", "bad password", "access denied", "auth failure",
        "too many authentication failures", "account locked",
    ))
    is_ok = any(k in log_lower for k in (
        "accepted password", "session opened", "logged in",
        "authentication success", "login successful",
    ))

    if is_fail or is_ok:
        user = _user(raw_log) or "unknown"
        _ip_auth[source_ip].append({"ts": now, "user": user, "success": is_ok})
        _user_auth[user].append({"ts": now, "ip": source_ip})

        window_5m = [e for e in _ip_auth[source_ip] if now - e["ts"] <= 300]
        fails_5m  = [e for e in window_5m if not e["success"]]
        users_5m  = {e["user"] for e in fails_5m}

        # Password spraying: 1 IP → many different usernames, mostly failures
        if len(users_5m) >= 6 and len(fails_5m) >= 10:
            score += 40
            alerts.append(
                f"Password spray: {len(users_5m)} unique usernames targeted from {source_ip} in 5m"
            )

        # Credential stuffing: very high volume + many unique usernames
        if len(users_5m) >= 25 and len(fails_5m) >= 60:
            score += 20  # stacks on top of spraying
            alerts.append(
                f"Credential stuffing: {len(fails_5m)} attempts, {len(users_5m)} unique usernames"
            )

        # Distributed brute force: many IPs → same user
        if user != "unknown":
            user_window = [e for e in _user_auth[user] if now - e["ts"] <= 300]
            attacker_ips = {e["ip"] for e in user_window if not any(
                a["ip"] == e["ip"] and a["success"] for a in _ip_auth[e["ip"]]
            )}
            if len(attacker_ips) >= 5:
                score += 35
                alerts.append(
                    f"Distributed brute force: {len(attacker_ips)} IPs targeting user '{user}'"
                )

    # ── Connection & beaconing tracking ───────────────────────────────────────
    dest  = _dest_ip(raw_log)
    prt   = _port(raw_log)
    is_conn = any(k in log_lower for k in (
        "connect", "connection", "session", "established", "new flow",
    ))

    if dest or prt or is_conn:
        _ip_conns[source_ip].append({"ts": now, "dest_ip": dest, "port": prt})
        _ip_beacon_ts[source_ip].append(now)

    # Beaconing: regular periodic outbound connections
    beacon_ts = [t for t in _ip_beacon_ts[source_ip] if now - t <= 1800]
    if len(beacon_ts) >= 8:
        reg = _beacon_regularity(sorted(beacon_ts))
        if reg >= 0.75:
            score += 45
            alerts.append(
                f"Beaconing: regularity={reg:.2f} over {len(beacon_ts)} connections in 30m "
                f"(possible C2 check-in)"
            )
        elif reg >= 0.50:
            score += 20
            alerts.append(
                f"Suspicious periodic connections: regularity={reg:.2f} ({len(beacon_ts)} events)"
            )

    # Lateral movement: connections to many distinct internal hosts
    conn_10m = [e for e in _ip_conns[source_ip] if now - e["ts"] <= 600]
    internal_targets = {
        e["dest_ip"] for e in conn_10m
        if e["dest_ip"] and _is_internal(e["dest_ip"]) and e["dest_ip"] != source_ip
    }
    if len(internal_targets) >= 5:
        score += 40
        alerts.append(
            f"Lateral movement: {source_ip} connected to {len(internal_targets)} "
            f"distinct internal hosts in 10m"
        )

    # ── Port scan: slow / low-and-slow ───────────────────────────────────────
    if prt:
        _ip_ports_seen[source_ip].append({"ts": now, "port": prt})
    ports_1h = {e["port"] for e in _ip_ports_seen[source_ip] if now - e["ts"] <= 3600}
    if len(ports_1h) >= 20:
        score += 30
        alerts.append(
            f"Low-and-slow port scan: {len(ports_1h)} distinct ports probed over 1h from {source_ip}"
        )

    # ── DNS tunneling ─────────────────────────────────────────────────────────
    dom = _domain(raw_log)
    if dom:
        _ip_dns[source_ip].append({"ts": now, "domain": dom, "length": len(dom)})

    dns_1m = [e for e in _ip_dns[source_ip] if now - e["ts"] <= 60]
    if dns_1m:
        avg_len = sum(e["length"] for e in dns_1m) / len(dns_1m)
        if len(dns_1m) >= 15 and avg_len >= 40:
            score += 50
            alerts.append(
                f"DNS tunneling: {len(dns_1m)} queries/min, avg label length {avg_len:.0f} chars"
            )
        elif len(dns_1m) >= 30:
            score += 20
            alerts.append(f"High DNS query rate: {len(dns_1m)} queries in 60s from {source_ip}")

    return {
        "alerts":         alerts[:6],
        "behavior_score": min(100, score),
    }
