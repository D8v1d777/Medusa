# Medusa — The Hacker's Operation Guide (CLI v2026)

This document provides a technical breakdown and usage guide for the Medusa Security Framework. Medusa is a surgical, high-performance pentesting tool designed for automated vulnerability detection and weaponized exploit proof generation.

---

## 1. Core CLI — Medusa-CLI
The primary interface for all operations. Replaces the legacy GUI for scriptable, high-speed security research.

### Usage:
`python -m medusa.engine.cli <target> [options]`

### Primary Commands:
- `https://target.com` : Specify the target URL (Web) or IP/Subnet (Network).
- `-t, --type [web|network|all]` : Define the scope of the engagement.
- `-p, --policy [quick|standard|deep|api|cve]` : Select the intensity and depth of the scanner.
- `-x, --exploit` : **Enable Hacker Mode**. Generates `curl`-based exploit POCs for every finding.
- `-r, --rate <int>` : Requests per second. Crucial for bypassing simple rate-limiting and avoiding DoS.
- `--report` : Automates the generation of a professional PDF impact report.

---

## 2. Web Security Modules

### 🧪 Template Engine (ZAP/Nuclei Hybrid)
Natively runs **all 9,000+ Nuclei community templates** and custom Stanford research templates.
- **Strength**: Unbeatable coverage of known CVEs, misconfigurations, and panel exposures.
- **Hacker Mode**: Automatically extracts proof strings and URL reflections.

### 💀 Advanced Injectors (Weaponized)
Deep probing for SQLi, XSS, SSRF, XXE, and SSTI.
- **Hacker Era Standard**: Uses **Unicode Normalization** and **Multi-Layer Encoding** to bypass Cloudflare/AWS WAF.
- **Output**: Each injection produces a weaponized `curl` POC that mimics authenticated browser headers.

### 🤖 LLM Security Scanner (v2026 Ready)
Specifically targets AI-integrated applications.
- **Functions**: Detects **Prompt Injection**, **System Instruction Override**, and **Neural Data Leaks** (API keys, internal prompts).
- **Targeting**: Automatically fuzing common AI endpoints like `/api/chat`, `/v1/completions`, and `/ai/query`.

### 🕷️ Modern SPA Crawler
A Playwright-powered crawler that identifies hidden endpoints in React, Vue, and Angular SPAs.
- **API Discovery**: Identifies non-standard REST and GraphQL routes.

---

## 3. Network Security Modules

### 📡 Network Scanner
Nmap-driven orchestration for service enumeration and vulnerability correlation.
- **CVE Correlation**: Real-time lookup of CVEs and available exploits via the `cve_correlator`.
- **Protocol Testers**: Specialized checks for SMB (Ghostpack/EternalBlue), SNMP, and SSH misconfigurations.

---

## 4. Luna Rodriguez — The AI Mastermind (Tier 3)

Luna Rodriguez is the Medusa Hacker Subagent, a high-intelligence offensive AI powered by **Groq (LPU)** for ultra-fast inference. She is specialized in autonomous exploit weaponization and tactical mission guidance.

### Activation:
To activate Luna, you must set your personal Groq API key in your environment variables:
```bash
# Windows
set GROQ_API_KEY=your_key_here

# Linux/macOS
export GROQ_API_KEY=your_key_here
```

### Direct Interaction:
- `python -m medusa.engine.cli ask "query"` : Direct tactical mission guidance from Luna.
- `python -m medusa.engine.cli exploit-gen <id>` : Luna will weaponize the specified finding into a functional script.

---

## 5. Exploitation Workflows

### Standard Web Breach:
`python -m medusa.engine.cli https://target.internal -t web -p standard -x`

### Deep API Engagement (GraphQL/LLM focus):
`python -m medusa.engine.cli https://api.target.internal -t web -p api -x --rate 25`

### Network Discovery & CVE Audit:
`python -m medusa.engine.cli 10.0.0.0/24 -t network --report`

---
**Medusa | Authorized Engagement Tool**
"We don't just find holes; we provide the keys."
