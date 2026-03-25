# Framework

Integrated security assessment platform. CLI-driven, modular, extensible.

## Quick Start

```bash
# Activate environment
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Full assessment
python -m medusa.engine.cli scan <target> -t all --report

# Network enumeration
python -m medusa.engine.cli scan 192.168.1.0/24 -t network

# Web assessment with deep policy
python -m medusa.engine.cli scan https://target.internal -t web -p deep
```

## CLI Reference

| Flag | Description |
|------|-------------|
| `-t, --type` | `web`, `network`, `ad`, `all` (default: `all`) |
| `-p, --policy` | `quick`, `standard`, `deep`, `api`, `cve` |
| `-x, --exploit` | Enable POC generation for findings |
| `--report` | Generate report after completion |
| `--no-ai` | Disable AI-assisted triage |

## Deployment

```bash
pip install -r requirements.txt
pip install -e ./medusa/engine
python -m medusa.engine.cli --help
```

---
**Authorized use only.**
