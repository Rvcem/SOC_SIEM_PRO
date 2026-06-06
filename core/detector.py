import re
from collections import defaultdict
import numpy as np

ip_event_counts = defaultdict(list)

def z_score(x, data):
    if len(data) < 2:
        return 0
    mean = np.mean(data)
    std = np.std(data)
    if std == 0:
        return 0
    return (x - mean) / std

def check_anomaly(ip, count, event_type=None, severity=None):
    history = ip_event_counts[ip]
    score = z_score(count, history) if history else 0
    history.append(count)
    if len(history) > 20:
        history.pop(0)
    return score

def detect_event(log):
    log_lower = log.lower()
    if "failed password" in log_lower or "invalid user" in log_lower or "authentication failure" in log_lower:
        return "Bruteforce", "HIGH", "Auth"
    elif "nmap" in log_lower or "scan detected" in log_lower or "port scan" in log_lower:
        return "Port Scan", "HIGH", "Reconnaissance"
    elif "select" in log_lower and ("union" in log_lower or "drop" in log_lower or "insert" in log_lower):
        return "SQL Injection", "CRITICAL", "Web Attack"
    elif "ddos" in log_lower or "flood" in log_lower or "syn flood" in log_lower:
        return "DDoS", "CRITICAL", "Network"
    elif "malware" in log_lower or "trojan" in log_lower or "ransomware" in log_lower:
        return "Malware", "CRITICAL", "Endpoint"
    elif "accepted password" in log_lower or "session opened" in log_lower:
        return "Successful Login", "LOW", "Auth"
    else:
        return "System Event", "LOW", "System"

def extract_ip(log):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", log)
    return match.group(1) if match else "unknown"
