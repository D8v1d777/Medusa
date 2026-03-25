# 🏛️ Medusa — Strategic Operation Guide (v2026)

Medusa is a sovereign, state-authorized offensive security framework designed for high-performance reconnaissance and weaponized exploitation. This guide documents the verified commands for the unified CLI interface.

---

## 1. Primary Engine: `scan`
The core module for vulnerability discovery and reconnaissance.

### Usage:
`.venv\Scripts\python.exe -m medusa.engine.cli scan <target> [options]`

### Arguments:
- `<target>` : The URL (Web), IP, or CIDR range to engage.
- `-t, --type {web, network, ad, all}` : Engagement scope. Defaults to `all`.
- `-p, --policy <name>` : Web-specific scan policy (e.g., `standard`, `api`, `fuzz`).
- `-x, --exploit` : **Enable Weaponization**. Automatically generates proof-of-concept payloads for findings.
- `--luna` : **Strategic Handoff**. Automatically transitions into an interactive session with Luna after the scan.
- `--report` : Generates a finalized PDF report of the engagement.

---

## 2. OSINT Engine: `onion` (DarkCrawler)
Native reconnaissance of hidden services using the stealthy DarkCrawler engine.

### Usage:
`.venv\Scripts\python.exe -m medusa.engine.cli onion [urls...] [-f url-file]`

### Features:
- **Stealth**: Routed entirely through Tor SOCKS5h.
- **Circuit Renewal**: Automated Tor identity shifts to bypass IP-based rate limiting.
- **Handoff**: Scraped content is automatically ingested into the Medusa finding database.

---

## 3. The AI Mastermind: `luna` & `ask`
Direct interaction with the Luna Neuro-Interface (State-Sponsored v5.0).

### Full REPL (Interactive):
`.venv\Scripts\python.exe -m medusa.engine.cli luna [--session <UUID>]`
- **Branding**: Stylized "Operative" interface with full long-term memory support.
- **Context**: Pass a session UUID to ground Luna in the findings of a specific scan.

### Tactical Query (Single-Shot):
`.venv\Scripts\python.exe -m medusa.engine.cli ask "<query>"`
- **Speed**: Immediate strategic guidance for a specific technical question.

---

## 4. Exploitation Core: `exploit-gen`
Weaponizes static findings into functional engagement scripts.

### Usage:
`.venv\Scripts\python.exe -m medusa.engine.cli exploit-gen <finding_id>`
- **Output**: Generates a standalone Python script designed to reproduce and demonstrate the impact of a specific vulnerability.

---

## 5. Deployment Shortcuts (Windows)
- `luna` : Launches the Luna interaction REPL directly (requires `luna.bat` in PATH or current dir).
- `luna --session <ID>` : Resumes a context-grounded engagement.

---
**Medusa | Authorized State-Sponsored Intelligence**
"Intention into Execution."
