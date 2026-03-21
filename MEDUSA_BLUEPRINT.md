# MEDUSA — Unified Security Research Framework
# Stanford University Cybersecurity Research Division
# Government-Authorized | Restricted Distribution | Not for Public Release
#
# Cursor AI: This is your complete build blueprint.
# Read every section before writing a single line of code.
# This is a professional research instrument, not a lab exercise.
# Build accordingly.

---

## Project Identity

Name:         Medusa
Version:      1.0.0
Purpose:      Unified offensive/defensive security research framework for
              authorized penetration testing and blue team detection validation.
Distribution: Stanford University Cybersecurity Research Division only.
Authorization: Government-approved engagement authorization on file.
Architecture: Full-stack desktop application — Electron GUI + Python backend.
Rating target: 9.2 / 10 real-world effectiveness.

---

## Core Design Philosophy

Two rules above all others:

1. Ease of use is not optional.
   A Stanford analyst should be able to run a full web + network + AD engagement
   from the GUI with zero terminal commands required. The CLI exists for automation
   and scripting. The GUI is the primary interface.

2. Red team and blue team outputs are equal citizens.
   Every offensive action produces a corresponding defensive artifact:
   detection rule, SIEM signature, log pattern, or hardening recommendation.
   A finding without a detection opportunity is an incomplete finding.

---

## Technology Stack — Language Selection

Cursor: use exactly these languages and frameworks. Each choice is deliberate.

FRONTEND (GUI):
  Electron 30+          Desktop app shell — cross-platform (Windows, macOS, Linux)
  React 18+             Component framework
  TypeScript 5+         Type safety across all frontend code
  TailwindCSS 3+        Styling — utility-first, no custom CSS files
  Recharts              Data visualisation — findings charts, CVSS distributions
  AG Grid Community     Results table — handles 10,000+ findings without lag
  Xterm.js              Embedded terminal for live scan output streaming
  shadcn/ui             Component library — consistent, accessible UI

BACKEND (Engine):
  Python 3.11+          Core engine, all security modules
  FastAPI               REST API bridging Electron ↔ Python engine
  SQLAlchemy 2.0        ORM — SQLite for local, PostgreSQL for team mode
  asyncio               All network operations are async
  litellm               AI provider abstraction (OpenAI, Anthropic, local Ollama)

COMMUNICATIONS:
  WebSocket             Live scan progress streaming to GUI
  REST (FastAPI)        Session management, findings retrieval, config
  IPC (Electron)        GUI ↔ local FastAPI process management

BUILD:
  electron-builder      Package into .dmg / .exe / .AppImage
  pyinstaller           Bundle Python backend into executable
  docker-compose        Test lab infrastructure

WHY THIS STACK:
  Electron gives Stanford analysts a native desktop app — no browser, no server to run.
  Double-click Medusa.app and it works. Python backend handles all security tooling
  because the ecosystem (impacket, scapy, playwright, nmap) is Python-native.
  FastAPI WebSocket streams live output to the terminal panel in real time.
  TypeScript prevents the class of bugs that make GUIs unreliable under load.

---

## Directory Structure

Cursor: create every directory and __init__.py / index.ts file upfront.

```
medusa/
├── app/                          # Electron + React frontend
│   ├── src/
│   │   ├── main/                 # Electron main process
│   │   │   ├── index.ts          # App entry, window management
│   │   │   ├── backend.ts        # Spawn/manage Python FastAPI process
│   │   │   └── updater.ts        # Auto-update logic
│   │   ├── renderer/             # React UI
│   │   │   ├── index.tsx         # React root
│   │   │   ├── App.tsx           # Router, layout
│   │   │   ├── pages/
│   │   │   │   ├── Dashboard.tsx         # Home — active sessions, stats
│   │   │   │   ├── NewEngagement.tsx     # Engagement wizard
│   │   │   │   ├── ScanControl.tsx       # Live scan view + terminal
│   │   │   │   ├── Findings.tsx          # AG Grid findings table
│   │   │   │   ├── FindingDetail.tsx     # Single finding deep view
│   │   │   │   ├── AttackChains.tsx      # AI chain visualiser
│   │   │   │   ├── BlueTeam.tsx          # Detection rules + SIEM exports
│   │   │   │   ├── Reports.tsx           # Report generation
│   │   │   │   └── Settings.tsx          # Config, AI keys, preferences
│   │   │   ├── components/
│   │   │   │   ├── SeverityBadge.tsx
│   │   │   │   ├── CvssGauge.tsx
│   │   │   │   ├── ModuleToggle.tsx
│   │   │   │   ├── ScanProgressBar.tsx
│   │   │   │   ├── LiveTerminal.tsx      # Xterm.js component
│   │   │   │   ├── FindingsChart.tsx     # Recharts severity distribution
│   │   │   │   ├── AttackGraph.tsx       # D3 force graph for chains
│   │   │   │   └── DetectionRuleCard.tsx
│   │   │   ├── hooks/
│   │   │   │   ├── useWebSocket.ts       # Live scan feed
│   │   │   │   ├── useFindings.ts        # Findings state management
│   │   │   │   └── useSession.ts         # Session lifecycle
│   │   │   └── lib/
│   │   │       ├── api.ts                # FastAPI client
│   │   │       ├── types.ts              # Shared TypeScript types
│   │   │       └── severity.ts           # CVSS → colour mapping
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   └── electron-builder.yml
│
├── engine/                       # Python FastAPI backend
│   ├── main.py                   # FastAPI app entry
│   ├── core/
│   │   ├── config.py
│   │   ├── scope_guard.py        # Built first — called everywhere
│   │   ├── session.py            # SQLAlchemy models
│   │   ├── logger.py
│   │   ├── rate_limiter.py
│   │   ├── ai_engine.py
│   │   ├── oob_listener.py
│   │   ├── analytics.py
│   │   ├── dependency_check.py
│   │   └── ws_broadcaster.py     # WebSocket live output to GUI
│   ├── modules/
│   │   ├── web/
│   │   │   ├── crawler.py
│   │   │   ├── injectors.py
│   │   │   ├── auth_tester.py
│   │   │   ├── api_fuzzer.py
│   │   │   ├── header_analyzer.py
│   │   │   ├── js_analyzer.py
│   │   │   ├── waf_detector.py
│   │   │   ├── waf_bypass.py
│   │   │   ├── waf_memory.py
│   │   │   ├── orm_hunter.py
│   │   │   ├── timing_oracle.py
│   │   │   └── verifier.py
│   │   ├── network/
│   │   │   ├── scanner.py
│   │   │   ├── cve_correlator.py
│   │   │   ├── proto_testers.py
│   │   │   ├── mitm.py
│   │   │   ├── evasion.py
│   │   │   └── cloud_enum.py
│   │   ├── redteam/
│   │   │   ├── phishing_sim.py
│   │   │   ├── c2.py
│   │   │   ├── lateral.py
│   │   │   ├── active_dir.py
│   │   │   ├── evasion_lab.py
│   │   │   └── ai_lure.py
│   │   ├── blueteam/             # NEW — equal to redteam in scope
│   │   │   ├── detection_engine.py
│   │   │   ├── sigma_generator.py
│   │   │   ├── yara_generator.py
│   │   │   ├── siem_exporter.py
│   │   │   ├── ioc_extractor.py
│   │   │   ├── ttl_baseliner.py
│   │   │   └── hardening_advisor.py
│   │   └── ai/
│   │       ├── triage.py
│   │       ├── analyst.py
│   │       ├── chain_builder.py
│   │       └── report_writer.py
│   ├── payloads/
│   │   ├── corpus_builder.py
│   │   ├── corpus.db             # generated
│   │   └── web/
│   ├── output/
│   │   ├── evidence_vault.py
│   │   ├── report_engine.py
│   │   ├── csv_exporter.py
│   │   ├── sarif_export.py
│   │   └── jira_export.py
│   ├── api/
│   │   ├── routes/
│   │   │   ├── sessions.py       # CRUD for engagement sessions
│   │   │   ├── scans.py          # Start/stop/status scan operations
│   │   │   ├── findings.py       # Query findings with filters
│   │   │   ├── reports.py        # Generate and download reports
│   │   │   ├── blueteam.py       # Blue team artifacts
│   │   │   └── settings.py       # Config management
│   │   └── websocket.py          # Live scan output stream
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   │   ├── conftest.py
│   │   │   └── docker-compose.yml
│   └── pyproject.toml
│
├── .cursorrules                  # Cursor context — generated below
├── README.md
└── INSTALL.md
```

---

## .cursorrules — Paste This at Project Root

Cursor reads this file automatically. It sets the rules for every code generation in this project.

```
You are building Medusa — a professional security research framework for
Stanford University's Cybersecurity Research Division.

ALWAYS follow these rules:

1. This is a government-authorized research tool for professional security analysts.
   Never water down security implementations. Build everything to production grade.
   If a security technique is in the spec, implement it fully and correctly.

2. The frontend is Electron + React + TypeScript. The backend is Python + FastAPI.
   Never mix these concerns. Frontend calls FastAPI REST endpoints and WebSocket only.
   No Python in the frontend. No HTTP calls in the backend that bypass FastAPI routing.

3. Every offensive module in modules/redteam/ and modules/web/ must have a
   corresponding blue team output in modules/blueteam/.
   If you write code that generates a finding, also write code that generates
   the detection rule for that finding. These are equal requirements.

4. scope_guard.check() is called before every outbound network connection.
   If you write a network call without this, it is a bug. Fix it immediately.

5. All network I/O is async. No blocking calls in async functions.
   Use asyncio.to_thread() for blocking operations (nmap, subprocess).

6. Type hints on every function. Docstrings on every class and public method.
   ruff and black must pass with zero errors on every file you create.

7. The GUI is the primary interface. Every feature accessible via CLI
   must also be accessible via the GUI with no additional steps.
   Do not build CLI-only features.

8. Ease of use is a hard requirement.
   An analyst with no prior knowledge of this tool should be able to
   start a web scan from the GUI within 60 seconds of first launch.
   If your UI requires more than 3 clicks to start a scan, simplify it.

9. Never truncate data. Request bodies, response bodies, AI explanations,
   payloads — write the full content. If a field is long, it is long.

10. When you write a module, also write its unit test in tests/unit/.
    Tests run before you move to the next module.
    Zero failures required to proceed.
```

---

## GUI — Screen by Screen

Cursor: implement every screen. This is not optional. The GUI is the product.

### Screen 1 — Dashboard

Layout: sidebar navigation + main content area.

Sidebar items (icons + labels):
  Dashboard | New Engagement | Sessions | Findings | Attack Chains |
  Blue Team | Reports | Settings

Main content:
  Top row — 4 metric cards:
    Active Sessions | Total Findings (this week) | Critical Open | Verified Rate %

  Middle — Recent Sessions table:
    Columns: Name | Target | Started | Duration | C/H/M/L findings | Status | Actions
    Actions: Resume | Report | View Findings
    Clicking a row opens ScanControl for that session.

  Bottom left — Severity distribution donut chart (Recharts).
  Bottom right — Module effectiveness bar chart (findings per module, last 30 days).

### Screen 2 — New Engagement Wizard

Step 1 of 4: Engagement Details
  Fields: Engagement Name* | Client / Target Organisation | Operator Name*
  Authorization confirmation checkbox:
    "I confirm written authorization is on file for this engagement."
    This must be checked. Cannot proceed without it.

Step 2 of 4: Scope Definition
  IP ranges (CIDR input with add/remove): e.g. 192.168.1.0/24
  Domains (input with add/remove): e.g. target.com, api.target.com
  Out-of-scope (input with add/remove): explicitly excluded IPs/domains
  Import from file button: accepts .txt, one entry per line.

Step 3 of 4: Module Selection
  Three toggle groups — each module has a toggle and a settings gear icon.

  Web Modules:
    [x] Header Analyzer    [x] WAF Detector      [x] Crawler
    [x] JS Analyzer        [x] Injection Engine  [x] Auth Tester
    [x] API Fuzzer         [x] ORM Hunter

  Network Modules:
    [x] Port Scanner       [x] CVE Correlator    [x] Cloud Enum
    [x] Protocol Testers   [ ] MITM Engine       [ ] Evasion

  Red Team (requires confirmation toggle at top of group):
    [ ] Phishing Sim       [ ] C2 Beacon         [ ] AD Attacks
    [ ] Evasion Lab

  Blue Team (always enabled — cannot be disabled):
    [x] Detection Rules    [x] SIGMA Generator   [x] YARA Generator
    [x] IOC Extractor      [x] Hardening Advisor

Step 4 of 4: AI Configuration
  Provider: dropdown (OpenAI GPT-4o | Anthropic Claude | Local Ollama)
  API Key: password input (stored in OS keychain via keytar, never in config file)
  Model: auto-populated based on provider
  Test Connection button: sends a test completion, shows green/red status

  Finish button → creates session → navigates to ScanControl.

### Screen 3 — Scan Control (Live View)

Three-panel layout:

LEFT PANEL — Module Queue (200px wide):
  List of enabled modules with status icons:
    Waiting (grey clock)
    Running (blue spinner)
    Complete (green check)
    Failed (red X)
  Click any module to jump to its output in the terminal.
  Progress bar per module showing % complete.

CENTER PANEL — Live Terminal (fills remaining width):
  Xterm.js terminal component.
  WebSocket streams live scan output here in real time.
  Colour coded:
    White:  normal output
    Green:  finding confirmed
    Yellow: warning / low confidence
    Red:    critical finding
    Cyan:   module start/end markers
  Search bar above terminal (Ctrl+F): searches terminal history.
  "Clear" button. "Copy All" button. "Save Log" button.

RIGHT PANEL — Live Findings Feed (300px wide):
  Real-time list of findings as they arrive.
  Each finding: severity badge + title + target (truncated).
  Clicking a finding opens FindingDetail modal.
  Filter buttons at top: ALL | CRITICAL | HIGH | VERIFIED

  Bottom of right panel:
    Scan controls:
      [Pause] [Resume] [Stop]
      Rate limiter slider: 1-10 req/s (adjustable live)

### Screen 4 — Findings Table

AG Grid with every finding column from the CSV spec.
This is the most data-dense screen. AG Grid handles it without lag.

Toolbar above grid:
  Search box (filters across all columns in real time)
  Severity filter: multi-select checkboxes
  Module filter: multi-select checkboxes
  Verified filter: All | Verified | Unverified
  Export buttons: [Export CSV] [Export SARIF] [Export JSON]
  Column picker: show/hide columns

Grid features:
  Row click: opens FindingDetail side panel (slides in from right, grid stays visible)
  Column sort: click header
  Column resize: drag header edge
  Row grouping: group by severity or module (right-click header → Group By)
  Colour-coded rows:
    Critical: very subtle red left border
    High: subtle orange left border
    Medium: subtle yellow left border
    Verified: subtle green checkmark in first column

### Screen 5 — Finding Detail

Full-width panel or modal. Tabbed layout.

Tab 1 — Overview:
  Title, severity badge, confidence badge, verified badge.
  Target URL (clickable), module, timestamp.
  CVSS gauge (visual arc from 0-10, colour coded).
  CVSS vector with each metric explained on hover.
  CWE IDs, CVE IDs, OWASP category, MITRE technique — all as clickable badges
  that open the external reference URL.

Tab 2 — Evidence:
  Split pane: Request (left) | Response (right)
  Syntax-highlighted HTTP (use Prism.js).
  Payload highlighted in yellow within request.
  Evidence of exploitation highlighted in yellow within response.
  Screenshot (if available): displayed inline, click to fullscreen.
  PCAP download button (if available).
  OOB callback evidence (if available): protocol, source IP, timestamp, data.

Tab 3 — AI Analysis:
  Technical explanation: full text, no truncation.
  Business impact: full text.
  Remediation steps: numbered list, monospace for code examples.
  AI confidence score: progress bar.
  References: clickable links.
  "Regenerate Analysis" button: re-runs AI analyst with fresher prompt.

Tab 4 — Blue Team:
  Detection opportunity section (from blueteam module).
  Generated SIGMA rule: syntax-highlighted YAML, copy button.
  Generated YARA rule: syntax-highlighted, copy button.
  IOCs extracted: table of IP, domain, hash, user-agent indicators.
  Log patterns: what this attack looks like in access logs / SIEM.
  Hardening recommendation: specific config changes to prevent this finding.

Tab 5 — Reproduction:
  Step-by-step numbered list.
  Each step: description + code block (curl command, Python snippet, or Burp steps).
  "Copy as curl" button for applicable findings.
  Environment requirements: what access/tools are needed.

### Screen 6 — Attack Chains

Left panel: list of generated attack chains.
  Each chain: name, likelihood percentage, step count, MITRE techniques.
  Clicking a chain loads it in the main panel.

Main panel: D3 force-directed graph.
  Nodes = findings (colour by severity).
  Edges = attack path connections.
  Node click: opens Finding Detail for that finding.
  Likelihood score displayed prominently.
  MITRE ATT&CK technique IDs on each edge.

Bottom panel: narrative description of the selected chain.
  AI-generated text explaining the chain in plain English.
  Step-by-step exploitation summary.
  Estimated time to exploit.
  Detection difficulty rating.

### Screen 7 — Blue Team

This screen is equal in depth to the entire offensive scan output.
Every offensive capability has a corresponding defensive artifact here.

Three sub-tabs:

Sub-tab 1 — Detection Rules:
  Table: Rule Name | Type (SIGMA/YARA) | Finding Source | Coverage | Actions
  Coverage = % of attack techniques in this engagement that this rule detects.
  Actions: View | Edit | Copy | Export to SIEM

  SIEM export targets (buttons):
    [Splunk SPL] [Elastic KQL] [Microsoft Sentinel KQL] [QRadar AQL] [Sumo Logic]
  Each generates the translated query for that specific SIEM platform.

Sub-tab 2 — IOC Dashboard:
  Summary cards: Total IOCs | Domains | IPs | Hashes | User Agents
  Table: IOC Value | Type | Source Finding | First Seen | Severity
  Export: [STIX 2.1] [MISP] [CSV] [Plain Text]
  Each IOC links back to the finding that generated it.

Sub-tab 3 — Hardening Report:
  Grouped by category: Network | Application | Identity | Cloud | Endpoint
  Each hardening item:
    Issue (what was found)
    Finding reference (links to the offensive finding)
    Recommended control (specific config or code change)
    Implementation effort: Low / Medium / High
    Priority score: based on CVSS of the finding it addresses
  Export as PDF (formatted hardening report, separate from pentest report).

### Screen 8 — Reports

Report type selector: Executive Summary | Technical Report | Hardening Report | Blue Team Report

For each type:
  Preview pane (rendered HTML): shows live preview as AI generates it.
  The preview updates word by word as the AI streams the narrative.
  This is the most impressive feature in the GUI — live report generation.

  Options panel:
    Include sections (checkboxes): adjust what goes in the report.
    Branding: organisation name, logo upload, analyst name.
    Classification marking: CONFIDENTIAL | RESTRICTED | INTERNAL

  Export buttons: [PDF] [HTML] [DOCX] [JSON Findings]

### Screen 9 — Settings

Tabs: General | AI | Network | Appearance | About

General:
  Evidence directory (folder picker)
  Reports directory (folder picker)
  Default rate limits per module
  Auto-verify findings toggle
  Session auto-save interval

AI:
  Provider selector
  API key management (stored in OS keychain)
  Model selector
  Temperature (slider 0.0-1.0)
  Max tokens per call
  "Test connection" button with latency display

Network:
  Proxy settings (HTTP/SOCKS5 support for routing through Burp)
  DNS server override
  Interface selector (for MITM module)
  Interactsh token

Appearance:
  Theme: Dark | Light | System
  Font size: Small | Medium | Large
  Terminal font family
  Colour scheme for severity levels

---

## Blue Team Module — Full Specification

Cursor: this module is equal in priority to the offensive modules.
Every method below is required. Build it completely.

### `engine/modules/blueteam/detection_engine.py`

```python
class DetectionEngine:
    """
    Runs after each offensive module completes.
    Converts findings into detection opportunities.
    Called automatically — analysts do not need to trigger it manually.
    """

    async def process_finding(self, finding: Finding) -> DetectionArtifact:
        """
        Route finding to appropriate detector based on finding type.
        Every finding type must have a detector. No finding goes unprocessed.

        Returns DetectionArtifact:
          sigma_rule: str           SIGMA rule YAML
          yara_rule: str | None     YARA rule if applicable
          iocs: list[IOC]           extracted indicators
          log_patterns: list[str]   what this looks like in logs
          detection_difficulty: Literal["easy", "medium", "hard", "unlikely"]
          false_positive_risk: str  what legitimate traffic could trigger this rule
          hardening: HardeningItem  specific mitigation
        """

    def _detect_sqli(self, finding: Finding) -> DetectionArtifact:
        """
        Log pattern: look for SQL keywords in access logs.
        SELECT|INSERT|UPDATE|DELETE|UNION|DROP in URL-decoded query params.

        SIGMA rule target: web server access log.
        Condition: URL contains SQL keywords AND response != 404.
        Caveat: high false positive risk — SQL keywords appear in legitimate URLs.
        Refine: flag only when combined with error responses or unusual response times.

        Hardening: parameterised queries, WAF rule, input validation whitelist.
        MITRE: T1190 Exploit Public-Facing Application.
        """

    def _detect_xss(self, finding: Finding) -> DetectionArtifact:
        """
        Log pattern: <script>, javascript:, onerror=, onload= in request params.
        SIGMA: web log with script tag in URL or POST body.
        IOC: the specific payload used as a YARA string for memory scanning.
        Hardening: CSP header, output encoding, X-XSS-Protection.
        """

    def _detect_ssrf(self, finding: Finding) -> DetectionArtifact:
        """
        Log pattern: outbound requests from web server to internal IP ranges.
        SIGMA: firewall log — source = web server IP, dest = 169.254.0.0/16
               or RFC1918 ranges not matching expected backend services.
        Detection difficulty: medium (requires egress firewall logging).
        Hardening: egress firewall rules, IMDS v2 enforcement (AWS), metadata endpoint restrictions.
        """

    def _detect_kerberoasting(self, finding: Finding) -> DetectionArtifact:
        """
        Log pattern: Windows Security Event ID 4769 (Kerberos service ticket request).
        SIGMA: multiple 4769 events from single source in short window.
               Encryption type = 0x17 (RC4) — modern accounts use AES.
               RC4 TGS requests are a strong Kerberoasting indicator.
        Detection difficulty: easy (built into Windows event log, well-known signature).
        Hardening: use AES-only service accounts, managed service accounts (gMSA).
        """

    def _detect_arp_poison(self, finding: Finding) -> DetectionArtifact:
        """
        Log pattern: gratuitous ARP replies not matching DHCP lease table.
        SIGMA: network log — ARP reply where sender MAC != expected MAC for that IP.
        Tool reference: XArp, arpwatch for continuous monitoring.
        Hardening: Dynamic ARP Inspection on managed switches, static ARP entries for gateways.
        Detection difficulty: easy with DAI enabled, hard without.
        """

    def _detect_ad_cs_abuse(self, finding: Finding) -> DetectionArtifact:
        """
        Log pattern: Windows Security Event 4886 (certificate request),
                     4887 (certificate issued), with unusual SANs or requestor.
        SIGMA: 4887 where certificate SAN != requestor UPN.
               This is the ESC1 signature — requestor supplied a different identity in SAN.
        Detection difficulty: medium (requires CA audit logging enabled).
        Hardening: disable EDITF_ATTRIBUTESUBJECTALTNAME2, require manager approval on templates.
        """
```

### `engine/modules/blueteam/sigma_generator.py`

```python
class SIGMAGenerator:
    """
    Generates SIGMA rules from findings.
    SIGMA is the vendor-neutral detection rule format.
    Rules are then translated to SIEM-specific query languages.
    """

    SIEM_BACKENDS = {
        "splunk":    "splunk",
        "elastic":   "es-ql",
        "sentinel":  "microsoft365defender",
        "qradar":    "qradar",
        "sumologic": "sumologic",
    }

    def generate(self, finding: Finding, detection: DetectionArtifact) -> str:
        """
        Generate a valid SIGMA rule YAML.
        Every generated rule must pass sigma validation:
          sigma check --target splunk rule.yml
        
        Required SIGMA fields:
          title, id (UUID), status (experimental), description,
          references, author, date, logsource (category + product),
          detection (selection + condition), falsepositives, level, tags
        
        tags must include:
          - attack.{mitre_technique}     from finding.mitre_technique
          - attack.{tactic}              mapped from technique
        
        Level mapping from CVSS:
          9.0-10.0: critical
          7.0-8.9:  high
          4.0-6.9:  medium
          0.1-3.9:  low
        
        After generating: validate YAML parses correctly.
        If SIGMA validation tool available: run it.
        """

    def translate(self, sigma_rule: str, target_siem: str) -> str:
        """
        Translate SIGMA YAML to target SIEM query language.
        Use sigma-cli Python library (pip install sigma-cli).
        
        If sigma-cli not available: use built-in translation templates.
        Provide templates for Splunk SPL and Elastic KQL at minimum.
        
        Return the translated query string ready to paste into the SIEM.
        """
```

### `engine/modules/blueteam/ioc_extractor.py`

```python
class IOCExtractor:
    """
    Extracts Indicators of Compromise from scan findings.
    Produces machine-readable IOC feeds for defensive tooling.
    """

    async def extract(self, session: Session) -> IOCReport:
        """
        For every finding in session, extract:
        
        NETWORK IOCS:
          IP addresses seen in scan (attacker-controlled OOB, callback sources)
          Domains used in payloads (OOB domains, C2 domains from redteam module)
          URLs of vulnerable endpoints
        
        HOST IOCS:
          File hashes if any files were dropped (redteam evasion_lab)
          Registry keys if AD attacks modified registry
          Process names from C2 module
          Named pipes used by C2
        
        WEB IOCS:
          User-Agent strings used during scan (for fingerprinting)
          Cookie names used by C2 beacons
          HTTP header patterns unique to Medusa scan traffic
        
        CREDENTIAL IOCS:
          Hashes found (Kerberoasting, MITM capture) — store hash only, never plaintext
          Usernames confirmed to exist via enumeration
          Service Principal Names enumerated
        
        Export formats:
          STIX 2.1: structured threat intelligence exchange
          MISP: threat sharing platform format
          Plain text: one IOC per line, type-prefixed
          CSV: type, value, confidence, source_finding_id, ts
        """
```

### `engine/modules/blueteam/hardening_advisor.py`

```python
class HardeningAdvisor:
    """
    Generates specific, actionable hardening recommendations.
    Not generic advice. Every recommendation maps to a confirmed finding.
    """

    async def advise(self, findings: list[Finding], session: Session) -> HardeningReport:
        """
        Group findings by root cause category.
        For each category, generate one hardening item:
        
        Structure of each HardeningItem:
          category: str             Network | Application | Identity | Cloud | Endpoint
          title: str                one-line description of the control
          finding_ids: list[str]    findings this addresses
          current_state: str        what was found (from finding evidence)
          recommended_control: str  exact config change, command, or code
          implementation_effort:    Low | Medium | High
          verification_method:      how to confirm the fix was applied
          priority_score: float     derived from max CVSS of associated findings
          compliance_mapping:       relevant CIS Control, NIST CSF, ISO 27001 control
        
        AI enhancement:
        For each hardening item, call ai_engine with:
        SYSTEM: "You are a defensive security architect. Write a specific, 
                 actionable hardening recommendation."
        USER: {finding evidence + current state}
        Ask for: exact commands, config file snippets, and verification steps.
        The output must be specific to the technology stack detected during the scan.
        Not generic. If the target runs nginx on Ubuntu 22.04, the recommendation
        includes the exact nginx.conf directive and the apt package to install.
        """
```

---

## FastAPI Backend — API Contract

Cursor: implement all routes. Frontend depends on these exact shapes.

```python
# engine/api/routes/sessions.py

POST   /api/sessions                    # Create new engagement session
GET    /api/sessions                    # List all sessions
GET    /api/sessions/{id}               # Get session detail
PUT    /api/sessions/{id}               # Update session (name, status)
DELETE /api/sessions/{id}               # Delete session + evidence
GET    /api/sessions/{id}/stats         # Finding counts, duration, module status

# engine/api/routes/scans.py

POST   /api/scans/start                 # Start scan (body: session_id, modules[])
POST   /api/scans/{session_id}/pause    # Pause running scan
POST   /api/scans/{session_id}/resume   # Resume paused scan
POST   /api/scans/{session_id}/stop     # Stop scan gracefully
GET    /api/scans/{session_id}/status   # Module status, progress percentages

# engine/api/routes/findings.py

GET    /api/findings?session_id=&severity=&module=&verified=&page=&limit=
GET    /api/findings/{id}               # Full finding detail
PUT    /api/findings/{id}               # Update (add notes, change severity)
GET    /api/findings/{id}/detection     # Blue team artifact for this finding
POST   /api/findings/{id}/verify        # Trigger manual re-verification

# engine/api/routes/reports.py

POST   /api/reports/generate            # Start AI report generation
GET    /api/reports/{id}/stream         # SSE stream of report text as AI generates it
GET    /api/reports/{id}/pdf            # Download generated PDF
GET    /api/reports/{id}/html           # Download generated HTML

# engine/api/routes/blueteam.py

GET    /api/blueteam/{session_id}/sigma         # All SIGMA rules for session
GET    /api/blueteam/{session_id}/sigma/{siem}  # Translated for specific SIEM
GET    /api/blueteam/{session_id}/iocs          # IOC report
GET    /api/blueteam/{session_id}/iocs/stix     # STIX 2.1 export
GET    /api/blueteam/{session_id}/hardening     # Hardening report
GET    /api/blueteam/{session_id}/hardening/pdf # PDF hardening report

# engine/api/websocket.py

WS     /ws/{session_id}                 # Live scan output stream
# Message types emitted:
# {type: "log",     data: {level, message, module, ts}}
# {type: "finding", data: Finding}
# {type: "progress",data: {module, percent, status}}
# {type: "complete",data: {session_id, summary}}
```

---

## WebSocket Live Stream — Implementation

```python
# engine/core/ws_broadcaster.py

class WSBroadcaster:
    """
    Singleton. Every module calls this to emit output.
    Frontend Xterm.js receives it and displays in real time.
    """

    async def log(self, session_id: str, level: str, message: str, module: str) -> None:
        """
        Broadcast a log line to all connected WebSocket clients for this session.
        Colour codes:
          DEBUG:    dim white
          INFO:     white
          SUCCESS:  green    (use for confirmed findings)
          WARNING:  yellow
          ERROR:    red
          CRITICAL: bright red bold
        Format terminal output with ANSI codes for Xterm.js rendering.
        """

    async def emit_finding(self, session_id: str, finding: Finding) -> None:
        """
        Broadcast a new finding. Frontend adds it to the live findings feed immediately.
        Also triggers a browser notification if the app is backgrounded and severity >= HIGH.
        """

    async def emit_progress(self, session_id: str, module: str, percent: int) -> None:
        """
        Update module progress bar in the left panel of ScanControl.
        percent: 0-100
        """
```

---

## Electron Main Process — Backend Management

```typescript
// app/src/main/backend.ts

/**
 * Cursor: implement this completely.
 * The Electron app spawns the Python FastAPI backend as a child process.
 * The analyst never sees a terminal. They just open Medusa.app.
 */

export class BackendManager {
  private process: ChildProcess | null = null;
  private port: number = 0;

  async start(): Promise<string> {
    /**
     * 1. Find a free port (start from 17432, increment if taken).
     * 2. Locate the bundled Python executable:
     *    - Development: python3 engine/main.py
     *    - Production: ./resources/engine/medusa-engine (pyinstaller bundle)
     * 3. Spawn process with: --port {port} --data-dir {userDataPath}
     * 4. Wait for FastAPI startup: poll GET /api/health every 200ms, timeout 15s.
     *    Show a loading screen during this wait.
     * 5. If startup fails: show error dialog with log output. Do not silently fail.
     * 6. Return the base URL: http://127.0.0.1:{port}
     */
  }

  async stop(): Promise<void> {
    /**
     * On app quit:
     * 1. POST /api/shutdown to FastAPI — triggers graceful scan pause and DB flush.
     * 2. Wait up to 3 seconds for graceful shutdown.
     * 3. If still running: SIGTERM. Wait 2s. SIGKILL.
     * 4. Never leave orphan Python processes.
     */
  }

  onCrash(callback: (log: string) => void): void {
    /**
     * If Python process exits unexpectedly:
     * Collect last 50 lines of stderr.
     * Call callback with the log.
     * Frontend shows an error dialog with "Restart Engine" button.
     */
  }
}
```

---

## Build Order for Cursor

Follow this exactly. Each phase has a completion test.

```
PHASE 1 — Foundation (no UI yet)
  engine/core/scope_guard.py         ← first file, every test passes before moving on
  engine/core/config.py
  engine/core/session.py             ← SQLAlchemy models
  engine/core/logger.py
  engine/core/rate_limiter.py
  engine/core/ai_engine.py
  engine/core/oob_listener.py
  engine/core/ws_broadcaster.py
  engine/core/dependency_check.py
  engine/payloads/corpus_builder.py  ← run it, verify corpus.db populated
  engine/main.py                     ← FastAPI app, health endpoint only
  Completion test: pytest tests/unit/ && curl http://localhost:17432/api/health

PHASE 2 — Web Engine
  (all modules/web/* files in order from spec)
  engine/api/routes/sessions.py
  engine/api/routes/scans.py
  engine/api/routes/findings.py
  engine/api/websocket.py
  Completion test: pytest tests/integration/test_web_dvwa.py

PHASE 3 — Network Engine
  (all modules/network/* files)
  Completion test: pytest tests/integration/test_network.py

PHASE 4 — Blue Team Engine  ← build before red team
  (all modules/blueteam/* files)
  engine/api/routes/blueteam.py
  Completion test: pytest tests/unit/test_blueteam.py

PHASE 5 — AI Module
  (all modules/ai/* files)
  Completion test: pytest tests/unit/test_ai_triage.py (mock AI calls)

PHASE 6 — Output Layer
  (all output/* files including csv_exporter.py)
  engine/api/routes/reports.py
  Completion test: pytest tests/integration/test_csv_export.py

PHASE 7 — Red Team Engine  ← last offensive module
  (all modules/redteam/* files)
  Confirmation gate: requires --confirm-auth in API call
  Completion test: pytest tests/unit/test_redteam_preflight.py

PHASE 8 — Electron GUI
  app/src/main/index.ts
  app/src/main/backend.ts
  app/src/renderer/App.tsx
  (all pages and components in order listed in directory structure)
  Completion test: electron-builder --dir && open the built app, run new engagement wizard

PHASE 9 — Integration
  Wire WebSocket broadcaster to all modules
  Wire csv_exporter to Session.add_finding()
  Wire blue team detection_engine to Session.add_finding()
  Wire verifier to post-module pipeline
  End-to-end test: full scan against DVWA via GUI, verify findings, CSV, SIGMA rules, PDF report

PHASE 10 — Package
  pyinstaller engine/main.py --onefile --name medusa-engine
  electron-builder --mac --win --linux
  Smoke test: install on clean machine, run full engagement, verify everything works
```

---

## Integration Test Targets

```yaml
# tests/integration/docker-compose.yml
version: '3.8'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports: ["4280:80"]
    networks: [medusa-test]
  juiceshop:
    image: bkimminich/juice-shop
    ports: ["4282:3000"]
    networks: [medusa-test]
  webgoat:
    image: webgoat/webgoat:v2023.4
    ports: ["4281:8080"]
    networks: [medusa-test]
  modsecurity:
    image: owasp/modsecurity-crs:nginx
    ports: ["4283:8080"]
    environment: [BACKEND=http://dvwa:80]
    networks: [medusa-test]
  openldap:
    image: osixia/openldap:1.5.0
    ports: ["4389:389"]
    environment:
      - LDAP_DOMAIN=medusa.test
      - LDAP_ADMIN_PASSWORD=admin
    networks: [medusa-test]
  neo4j:
    image: neo4j:5.18
    ports: ["7474:7474", "7687:7687"]
    environment: [NEO4J_AUTH=neo4j/medusa123]
    networks: [medusa-test]
  interactsh:
    image: projectdiscovery/interactsh-server
    ports: ["4080:80", "4053:53/udp"]
    networks: [medusa-test]
networks:
  medusa-test:
    ipam:
      config: [{subnet: 172.30.0.0/24}]
```

---

## Final Instruction to Cursor

You have the complete blueprint. Three previous spec files contain the module-level
implementation detail (PENTKIT_SPEC.md, PENTKIT_HARDENING.md, PENTKIT_PRECISION.md).
This file defines the GUI, the blue team module, the API contract, and the build order.

Read all four files before writing any code.
Cross-reference them. If this file and a spec file conflict: this file wins.

The target is a 9.2+ rated professional security research framework.
The audience is Stanford University Cybersecurity Research Division.
The distribution is restricted.
The authorization is documented.

Build Medusa to that standard. Nothing less.
```
