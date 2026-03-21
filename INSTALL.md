# Medusa Installation Guide

See **`requirements.txt`** at the repo root for the full Python dependency list and notes for Node.js, venv, and optional dev tools.

## Windows

1. Install Python 3.11+ from python.org
2. Install Node.js 18+ from nodejs.org
3. From the Medusa project root:

```text
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e ./medusa/engine
cd medusa/app
npm install
npm run build
npm start
```

## macOS / Linux

Same steps; use `source .venv/bin/activate`, `pip3`, and `python3` as needed.

## Configuration

Copy `config_medusa.yaml` and set:

- `engagement.name` — Engagement identifier
- `engagement.operator` — Analyst name
- `scope.domains` — In-scope domains
- `scope.ips` — In-scope IP ranges
- `ai.api_key_env` — Environment variable for OpenAI key
