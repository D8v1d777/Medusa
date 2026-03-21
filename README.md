# Medusa — Unified Security Research Framework

Version 1.0.0 | Stanford University Cybersecurity Research Division

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- pip packages: `fastapi uvicorn httpx pydantic sqlalchemy pyyaml`

### Run Engine (API only)

```bash
cd Medusa
set PYTHONPATH=%CD%
python -m uvicorn medusa.engine.main:app --host 127.0.0.1 --port 17432
```

Then open http://127.0.0.1:17432/api/health

### Run Full App (Electron + Engine)

```bash
cd medusa/app
npm install
npm run build
npm start
```

The Electron app spawns the Python engine automatically.

## Structure

- `medusa/engine/` — Python FastAPI backend
- `medusa/app/` — Electron + React GUI
- `config_medusa.yaml` — Configuration

## License

Restricted distribution. Government-authorized engagements only.
