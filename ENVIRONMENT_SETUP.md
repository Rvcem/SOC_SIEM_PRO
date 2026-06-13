# Environment Setup Guide

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure your `.env` file

Copy `.env.example` to `.env` and fill in your API keys:

```bash
cp .env.example .env
```

Then open `.env` and add:

```
# VirusTotal (file hash + URL/domain lookups)
VT_API_KEY=your-api-key-from-virustotal.com

# AbuseIPDB (IP reputation)
ABUSEIPDB_API_KEY=your-api-key-from-abuseipdb.com

# Ollama (required for AI analysis — run `ollama serve` first)
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=deepseek:latest
SOC_REPORT_MODEL=deepseek:latest

# Threat enrichment (optional but recommended)
SHODAN_API_KEY=your-shodan-key
GREYNOISE_API_KEY=your-greynoise-key   # or leave blank — Community API works without a key
URLSCAN_API_KEY=your-urlscan-key
```

### 3. Install Ollama & models

Download Ollama from https://ollama.ai, then pull the model used by the app:

```bash
ollama pull deepseek:latest    # used for both chatbot and incident reports
ollama serve
```

If you have a powerful machine and want deeper analysis, you can use the larger model:
```bash
ollama pull deepseek-coder-v2:16b
```
Then set `SOC_REPORT_MODEL=deepseek-coder-v2:16b` in `.env` — expect 60–120s per report.

### 4. Start the system

```bash
python start.py
```

The SIEM will:
- Load `.env` variables automatically
- Start the UDP listener on port 5555
- Launch the web API on http://127.0.0.1:5000
- Open the GUI dashboard

---

## Environment Variables Reference

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `VT_API_KEY` | Optional | (none) | VirusTotal hash + URL/domain lookups |
| `ABUSEIPDB_API_KEY` | Optional | (none) | IP reputation (abuseipdb.com) |
| `SHODAN_API_KEY` | Optional | (none) | Open ports + CVEs on source IPs (Port Scan / Recon events) |
| `GREYNOISE_API_KEY` | Optional | (none) | Mass-scanner classification — Community API works without a key |
| `URLSCAN_API_KEY` | Optional | (none) | URL sandbox with screenshot (C2 / web attack events) |
| `OLLAMA_URL` | Optional | `http://127.0.0.1:11434` | Ollama local LLM endpoint |
| `OLLAMA_MODEL` | Optional | `deepseek:latest` | Model for SOC Assist chatbot |
| `SOC_REPORT_MODEL` | Optional | `deepseek:latest` | Model for per-incident AI reports |
| `SOC_ENABLE_OLLAMA` | Optional | `1` | Set to `0` to disable LLM analysis |
| `SOC_ENABLE_REPORTS` | Optional | `1` | Set to `0` to disable report generation |
| `SOC_AUTO_BLOCK_SCORE` | Optional | `90` | Threat score threshold for auto-block (0–100) |
| `SOC_ADMIN_PASSWORD` | Optional | (auto-generated) | First-run admin password — printed to console if not set |
| `SOC_DB_PATH` | Optional | `incidents.db` | Path to SQLite database |
| `SOC_API_KEY` | Optional | (auto-generated) | Bearer token for Flask REST API |

---

## Generating API Keys

### VirusTotal (Free Tier)
1. Go to https://www.virustotal.com/gui/home/upload
2. Create an account or log in
3. Click your profile → **API key** → copy the key
4. Add to `.env`: `VT_API_KEY=...`
5. **Rate limit:** 4 lookups per minute (free tier)

### AbuseIPDB (Free Tier)
1. Go to https://www.abuseipdb.com/register
2. Create an account
3. Go to **Account** → **API** → copy your API key
4. Add to `.env`: `ABUSEIPDB_API_KEY=...`
5. **Rate limit:** 1,000 lookups per day (free tier)

### Shodan (Free Tier)
1. Go to https://account.shodan.io/register
2. Create an account — the free plan gives 100 lookups/month
3. Copy your API key from the **Account** page
4. Add to `.env`: `SHODAN_API_KEY=...`
5. Triggered by: Port Scan and Reconnaissance events

### GreyNoise (Community API — no key required)
1. Leave `GREYNOISE_API_KEY=` blank to use the free Community API (basic mass-scanner classification)
2. For enhanced data, register at https://www.greynoise.io/plans/community
3. Add to `.env`: `GREYNOISE_API_KEY=...`
4. Triggered by: Port Scan, Bruteforce, DDoS, and Anomaly events

### URLScan.io (Free Tier)
1. Go to https://urlscan.io/user/signup
2. Create an account
3. Copy your API key from **Settings** → **API Key**
4. Add to `.env`: `URLSCAN_API_KEY=...`
5. **Rate limit:** 100 private scans per day (free tier)
6. Triggered by: C2 Communication, SQLi, XSS, Command Injection, Malware events

---

## Security Notes

⚠️ **NEVER commit `.env` to git** — it contains sensitive API keys.

The `.env` file is automatically excluded by `.gitignore`. To verify:
```bash
git status
# Should NOT show .env
```

If you accidentally committed it, regenerate all your API keys immediately.

---

## Testing the Setup

Send a test log to the SIEM:

```bash
python test_siem.py
```

This will simulate various attacks. Check the GUI to see detected incidents.

---

## Troubleshooting

### "VT_API_KEY is not set"
- Make sure `.env` exists in the project root
- Verify it has `VT_API_KEY=your-key` (no spaces)
- Restart your terminal/IDE

### "Ollama unavailable"
- Start Ollama: `ollama serve`
- Verify it's running: `curl http://127.0.0.1:11434/api/tags`
- Check `OLLAMA_URL` in `.env`

### ".env file not found"
- Create it: `cp .env.example .env`
- Fill in your API keys
- Save and restart the app

