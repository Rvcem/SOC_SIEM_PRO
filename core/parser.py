import re
from core.detector import detect_event, extract_ip


class LogParser:
    def __init__(self):
        self.ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    def parse_syslog(self, raw_log):
        """Returns: source_ip, event_type, severity, category"""
        source_ip = extract_ip(raw_log)
        if source_ip == "unknown":
            source_ip = "0.0.0.0"
        event_type, severity, category = detect_event(raw_log)
        return source_ip, event_type, severity, category
