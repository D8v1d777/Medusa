# Medusa — The Hacker's Interface

Version 1.0.0 | Stanford University Cybersecurity Research Division
**Bypassing the GUI: High-Performance CLI-Driven Exploitation.**

## CLI Quick Start (Linux-Style Tooling)

Medusa is now fully operable from the terminal. No Electron required. Optimized for speed, automation, and direct exploitation.

### Running a Scan
```bash
# 1. Activate environment
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# 2. Run a full web + network scan with exploitative POC generation
python -m medusa.engine.cli https://target.com -t all -p standard -x --report

# 3. Only network scanning with Nmap + CVE correlation
python -m medusa.engine.cli 192.168.1.0/24 -t network

# 4. Deep web scan with AI triage
python -m medusa.engine.cli https://api.target.internal -t web -p deep
```

### Options
- `-t, --type` : `web`, `network`, `all` (default: `all`)
- `-p, --policy` : `quick`, `standard`, `deep`, `api`, `cve`
- `-x, --exploit` : Enable **Hacker Mode** (generates real `curl` POCs for all findings)
- `--report` : Generate a professional PDF/JSON report after completion

## Structure

- `medusa/engine/cli.py` — **New CLI Entry Point**
- `medusa/engine/modules/web/injectors.py` — Exploitative payload generation
- `medusa/engine/core/` — Core persistent logic and DB models
- `medusa/app/` — Legacy GUI (deprecated in favor of CLI)

## Deployment

```bash
pip install -r requirements.txt
pip install -e ./medusa/engine
python -m medusa.engine.cli --help
```

---
**Restricted Distribution. Authorized engagements only.**
"We don't just find holes; we provide the keys."
