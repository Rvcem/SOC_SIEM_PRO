import socket
import time
import random

# Configuration
TARGET_IP = "127.0.0.1"
TARGET_PORT = 5555

ATTACKS = [
    # Port Scan / Reconnaissance
    "nmap scan detected from {ip} - targeted ports 80, 443, 22",
    "port scan initiated from {ip} on subnet 10.0.0.0/24",
    "scan detected from {ip} sweeping ports 1-1024",

    # SQL Injection
    "Web request from {ip}: SELECT * FROM users UNION SELECT null,null--",
    "SQL attack from {ip}: DROP TABLE incidents;",
    "Malicious query from {ip}: INSERT INTO admin VALUES('hacker','1234')",

    # DDoS
    "DDoS attack detected from {ip} - 50000 packets/sec",
    "SYN flood from {ip} targeting port 443",
    "UDP flood detected from {ip}",

    # Malware
    "Malware detected on host {ip} - trojan.generic",
    "Ransomware activity from {ip} - files being encrypted",
    "Trojan callback detected from {ip} to C2 server",

    # Successful Login (LOW severity — normal event)
    "Accepted password for dev_user from {ip} port 51234 ssh2",
    "session opened for user root from {ip}",
]

FAKE_IPS = [
    "45.12.33.1",       # Europe
    "102.4.5.11",       # Africa
    "185.192.67.10",    # Russia
    "103.21.244.5",     # Asia
    "200.105.141.20",   # South America
    "91.108.4.33",      # Middle East
]

def send_packet(message, ip):
    payload = message.format(ip=ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(payload.encode('utf-8'), (TARGET_IP, TARGET_PORT))
    sock.close()
    print(f"[TEST] Sent: {payload}")

def send_attack(message):
    send_packet(message, random.choice(FAKE_IPS))

def trigger_anomaly():
    """Send rapid bursts from one IP to trigger ML z-score anomaly detection."""
    ip = random.choice(FAKE_IPS)
    print(f"\n[ANOMALY BURST] Flooding from {ip}...")
    for _ in range(12):
        msg = random.choice(ATTACKS)
        send_packet(msg, ip)
        time.sleep(0.2)
    print(f"[ANOMALY BURST] Done.\n")

if __name__ == "__main__":
    print("--- SIEM ATTACK SIMULATOR ---")
    print(f"Sending packets to {TARGET_IP}:{TARGET_PORT}...")
    print("Every ~60s an anomaly burst will fire to test ML detection.\n")

    last_anomaly = time.time()

    try:
        while True:
            # Regular random attack
            msg = random.choice(ATTACKS)
            send_attack(msg)

            # Trigger anomaly burst every ~60 seconds
            if time.time() - last_anomaly > 60:
                trigger_anomaly()
                last_anomaly = time.time()

            time.sleep(random.uniform(2, 5))

    except KeyboardInterrupt:
        print("\n[!] Stopping simulator.")
        