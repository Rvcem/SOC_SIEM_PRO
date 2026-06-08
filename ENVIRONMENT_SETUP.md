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
# VirusTotal (required for malware detection)
VT_API_KEY=your-api-key-from-virustotal.com

# AbuseIPDB (optional, for IP reputation)
ABUSEIPDB_API_KEY=your-api-key-from-abuseipdb.com

# Ollama (required for AI analysis)
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.1
SOC_REPORT_MODEL=deepseek-coder-v2:16b
```

### 3. Install Ollama & models

Download Ollama from https://ollama.ai, then:

```bash
ollama pull llama3.1
ollama pull deepseek-coder-v2:16b
ollama serve
```

Keep Ollama running in the background while the SIEM is active.

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
| `VT_API_KEY` | Optional | (none) | VirusTotal hash lookups (get at virustotal.com) |
| `ABUSEIPDB_API_KEY` | Optional | (none) | IP reputation (get at abuseipdb.com) |
| `OLLAMA_URL` | Optional | `http://127.0.0.1:11434` | Ollama local LLM endpoint |
| `OLLAMA_MODEL` | Optional | `llama3.1` | Model for real-time analysis |
| `SOC_REPORT_MODEL` | Optional | `deepseek-coder-v2:16b` | Model for incident reports |
| `SOC_ENABLE_OLLAMA` | Optional | `1` | Set to `0` to disable LLM analysis |
| `SOC_ENABLE_REPORTS` | Optional | `1` | Set to `0` to disable report generation |
| `SOC_AUTO_BLOCK_SCORE` | Optional | `90` | Threat score threshold for auto-block (0-100) |
| `SOC_DB_PATH` | Optional | `incidents.db` | Path to SQLite database |

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

