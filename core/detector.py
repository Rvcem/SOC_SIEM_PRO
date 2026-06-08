import re
from collections import defaultdict

import numpy as np

ip_event_counts = defaultdict(list)


def z_score(x, data):
    if len(data) < 2:
        return 0
    mean = np.mean(data)
    std  = np.std(data)
    if std == 0:
        return 0
    return (x - mean) / std


def check_anomaly(ip, count, event_type=None, severity=None):
    history = ip_event_counts[ip]
    score   = z_score(count, history) if history else 0
    history.append(count)
    if len(history) > 20:
        history.pop(0)
    return score


# ── SQL injection helper (handles obfuscation + NoSQL) ────────────────────────

def _is_sqli(log_lower: str) -> bool:
    # Classic relational SQL
    if (
        ("select" in log_lower and any(k in log_lower for k in ("union", "from", "where")))
        or ("drop" in log_lower and "table" in log_lower)
        or ("insert into" in log_lower and "values" in log_lower)
        or ("update" in log_lower and "set" in log_lower and "where" in log_lower)
        or ("delete from" in log_lower)
        or ("exec(" in log_lower or "execute(" in log_lower)
        or ("xp_cmdshell" in log_lower)
    ):
        return True

    # Blind / time-based
    if any(k in log_lower for k in (
        "sleep(", "waitfor delay", "benchmark(", "pg_sleep(",
        "and 1=1", "or 1=1", "and 1=2", "or 1=2",
        "' or '", "\" or \"",
        "1' or '1'='1", "admin'--",
    )):
        return True

    # Comment obfuscation with SQL keyword nearby
    if re.search(r'/\*.*?\*/', log_lower) and any(
        k in log_lower for k in ("select", "union", "drop", "insert")
    ):
        return True

    # URL-encoded / hex patterns
    if any(k in log_lower for k in ("%27", "%3d%3d", "char(", "concat(", "0x")):
        return True

    # NoSQL injection (MongoDB operators)
    if any(k in log_lower for k in ("$where", "$gt", "$ne", "$regex", "$exists", "$nin")):
        return True

    return False


# ── Main event classifier ─────────────────────────────────────────────────────

def detect_event(log: str) -> tuple:
    """
    Classify a raw log string.

    Returns (event_type: str, severity: str, category: str).
    """
    ll = log.lower()

    # ── Credential Theft (check before bruteforce — more specific) ────────────
    if any(k in ll for k in (
        "credential dump", "lsass", "sekurlsa", "hashdump",
        "ntlm hash", "kerberoast", "as-rep roast",
        "golden ticket", "silver ticket", "dcsync",
        "mimikatz", "credential access",
    )):
        return "Credential Theft", "CRITICAL", "Endpoint"

    # ── Brute Force ───────────────────────────────────────────────────────────
    if any(k in ll for k in (
        "failed password", "invalid user", "authentication failure",
        "login failed", "auth failure", "bad password",
        "account locked", "too many authentication failures",
        "repeated login failure",
    )):
        return "Bruteforce", "HIGH", "Auth"

    # ── Successful Login ──────────────────────────────────────────────────────
    if any(k in ll for k in (
        "accepted password", "session opened",
        "logged in successfully", "authentication success",
        "login successful",
    )):
        return "Successful Login", "LOW", "Auth"

    # ── C2 Communication ──────────────────────────────────────────────────────
    if any(k in ll for k in (
        "c2 server", "command and control", "cobalt strike",
        "metasploit", "meterpreter", "reverse shell", "bind shell",
        "c&c", "beacon callback", "empire framework",
        "sliver c2", "havoc c2", "brute ratel",
    )):
        return "C2 Communication", "CRITICAL", "Network"

    # ── Malware / Ransomware (before generic endpoint checks) ─────────────────
    if any(k in ll for k in (
        "malware", "trojan", "ransomware", "worm",
        "rootkit", "spyware", "keylogger", "botnet",
        "cryptominer", "coinminer", "emotet",
        "trickbot", "ryuk", "lockbit", "conti", "blackcat",
    )):
        return "Malware", "CRITICAL", "Endpoint"

    # ── Lateral Movement ──────────────────────────────────────────────────────
    if any(k in ll for k in (
        "psexec", "psexesvc", "wmic", "winrm",
        "pass-the-hash", "pass the hash", " pth ",
        "smb lateral", "remote execution", "impacket",
        "wmiexec", "smbexec", "atexec", "dcomexec",
    )):
        return "Lateral Movement", "HIGH", "Network"

    # ── Privilege Escalation ──────────────────────────────────────────────────
    if any(k in ll for k in (
        "privilege escalation", "sudo su", "su root",
        "seimpersonateprivilege", "setuid", "suid exploit",
        "chmod +s", "token impersonation",
        "bypass uac", "uac bypass", "juicypotato",
        "printspoofer", "dirty cow", "polkit",
    )):
        return "Privilege Escalation", "HIGH", "Endpoint"

    # ── Persistence ───────────────────────────────────────────────────────────
    if any(k in ll for k in (
        "crontab -e", "registry run key", "startup folder",
        "scheduled task", "schtasks", "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run",
        "autorun", "persistence mechanism", "rc.local", "init.d",
        ".bashrc modified", "profile modified",
    )):
        return "Persistence", "HIGH", "Endpoint"

    # ── Data Exfiltration ─────────────────────────────────────────────────────
    if any(k in ll for k in (
        "data exfil", "exfiltration", "data leak",
        "large upload", "unusual outbound",
        "dns exfil", "ftp upload suspicious", "mega upload",
        "unusual data transfer", "exfil detected",
    )):
        return "Data Exfiltration", "CRITICAL", "Network"

    # ── DNS Tunneling ─────────────────────────────────────────────────────────
    if any(k in ll for k in (
        "dns tunnel", "iodine", "dnscat", "dns exfil",
        "dns c2", "long dns query", "dns over https suspicious",
    )):
        return "DNS Tunneling", "HIGH", "Network"

    # ── Port Scan / Reconnaissance ────────────────────────────────────────────
    if any(k in ll for k in (
        "nmap", "scan detected", "port scan", "masscan",
        "zmap", "unicornscan", "syn scan", "fin scan",
        "xmas scan", "null scan", "os fingerprint",
        "service enum", "vulnerability scan",
        "nikto", "dirb", "gobuster", "ffuf", "feroxbuster",
        "network sweep", "host discovery",
    )):
        return "Port Scan", "HIGH", "Reconnaissance"

    # ── Web Attacks ───────────────────────────────────────────────────────────
    if _is_sqli(ll):
        return "SQL Injection", "CRITICAL", "Web Attack"

    if any(k in ll for k in (
        "<script", "javascript:", "onerror=", "onload=",
        "alert(", "document.cookie", "xss",
        "svg onload", "img src=x", "iframe src",
    )):
        return "XSS", "HIGH", "Web Attack"

    if any(k in ll for k in (
        "../", "..\\", "/etc/passwd", "/etc/shadow",
        "c:\\windows\\system32", "php://",
        "file:///", "local file inclusion", " lfi ",
        "/proc/self/", "../../../../",
    )):
        return "Path Traversal", "HIGH", "Web Attack"

    if any(k in ll for k in (
        "; /bin/sh", "| nc ", "| bash", "`id`",
        "$(whoami)", "cmd.exe /c", "powershell -enc",
        "os.system(", "eval(base64", "shell_exec(",
        "`cat /etc/passwd`", "system(", ";id;",
    )):
        return "Command Injection", "CRITICAL", "Web Attack"

    # ── DDoS / Flood ──────────────────────────────────────────────────────────
    if any(k in ll for k in (
        "ddos", "flood", "syn flood", "udp flood",
        "icmp flood", "amplification attack",
        "reflection attack", "dns amplification",
        "ntp amplification", "ssdp amplification",
        "http flood", "slowloris", "rudy attack",
    )):
        return "DDoS", "CRITICAL", "Network"

    # ── Catch-all ─────────────────────────────────────────────────────────────
    return "System Event", "LOW", "System"


def extract_ip(log: str) -> str:
    match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", log)
    return match.group(1) if match else "unknown"
