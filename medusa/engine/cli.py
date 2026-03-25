"""
Engine CLI — Operator Interface.
High-performance terminal for security assessment operations.
"""
import argparse
import asyncio
import logging
import sys
import os
import json
import time
from typing import Optional, List, Dict, Any
from pathlib import Path

from medusa.engine.core.config import Config
from medusa.engine.core.session import Session
from medusa.engine.core.scope_guard import ScopeGuard
from medusa.engine.core.rate_limiter import TokenBucket
from medusa.engine.modules.web.active_scanner import ActiveScanner
from medusa.engine.modules.network.scanner import NetworkScanner
from medusa.engine.modules.ai.triage import AITriage
from medusa.engine.modules.ai.report_writer import ReportWriter
from medusa.engine.modules.ai.hacker_llm import HackerAI
from medusa.engine.core.models import FindingModel

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
for logger_name in ["httpx", "httpcore", "urllib3"]:
    logging.getLogger(logger_name).setLevel(logging.WARNING)

logger = logging.getLogger("cli")

# ── Color System ──────────────────────────────────────────────
class C:
    R = '\033[1;31m'    # Red
    G = '\033[1;92m'    # Green
    Y = '\033[1;93m'    # Yellow
    B = '\033[1;94m'    # Blue
    P = '\033[1;95m'    # Purple
    CY = '\033[1;96m'   # Cyan
    W = '\033[1;97m'    # White
    D = '\033[2m'       # Dim
    X = '\033[0m'       # Reset
    BG_R = '\033[41m'   # BG Red
    BG_Y = '\033[43m'   # BG Yellow

BANNER = rf"""
{C.CY}
   __  ___        __                  
  /  |/  /___ ___/ /__ __ _____ _     
 / /|_/ / -_) _  / // (_-</ _ `/     
/_/  /_/\__/\_,_/\_,_/___/\_,_/      
{C.X}"""

SEV_COLOR = {
    "critical": C.BG_R + C.W,
    "high": C.R,
    "medium": C.Y,
    "low": C.B,
    "info": C.D,
}

def sev_badge(severity: str) -> str:
    color = SEV_COLOR.get(severity.lower(), C.D)
    return f"{color}[{severity.upper():^8}]{C.X}"

def render_table(headers: List[str], rows: List[List[str]], col_widths: List[int] = None):
    """Render a formatted ASCII table to stdout."""
    if not rows:
        print(f"  {C.D}(no data){C.X}")
        return

    if col_widths is None:
        col_widths = []
        for i, h in enumerate(headers):
            max_w = len(h)
            for row in rows:
                if i < len(row):
                    max_w = max(max_w, len(str(row[i])))
            col_widths.append(min(max_w, 60))

    # Header
    header_line = "  "
    sep_line = "  "
    for i, h in enumerate(headers):
        w = col_widths[i]
        header_line += f"{C.CY}{h:<{w}}{C.X}  "
        sep_line += "─" * w + "──"
    print(sep_line)
    print(header_line)
    print(sep_line)

    # Rows
    for row in rows:
        line = "  "
        for i, cell in enumerate(row):
            w = col_widths[i] if i < len(col_widths) else 20
            cell_str = str(cell)[:w]
            line += f"{cell_str:<{w}}  "
        print(line)
    print(sep_line)

def render_findings(findings: List[FindingModel], title: str = "FINDINGS"):
    """Render all findings as a rich structured report."""
    if not findings:
        print(f"\n  {C.D}No findings recorded.{C.X}")
        return

    # Stats
    sev_counts = {}
    for f in findings:
        s = (f.severity or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    print(f"\n{C.CY}{'━'*70}")
    print(f"  {title}")
    print(f"{'━'*70}{C.X}")
    
    # Summary bar
    total = len(findings)
    parts = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in sev_counts:
            parts.append(f"{sev_badge(sev)} {sev_counts[sev]}")
    print(f"\n  {C.W}Total: {total}{C.X}  │  {'  '.join(parts)}\n")

    # Detail table
    headers = ["#", "SEVERITY", "MODULE", "TARGET", "TITLE"]
    rows = []
    for i, f in enumerate(findings, 1):
        sev = (f.severity or "info").lower()
        color = SEV_COLOR.get(sev, "")
        rows.append([
            str(i),
            f"{color}{sev.upper()}{C.X}",
            (f.module or "")[:18],
            (f.target or "")[:30],
            (f.title or "")[:40],
        ])
    render_table(headers, rows, [4, 10, 18, 30, 40])

    # Detailed evidence blocks for critical/high
    critical_high = [f for f in findings if (f.severity or "").lower() in ("critical", "high")]
    if critical_high:
        print(f"\n{C.R}{'━'*70}")
        print(f"  EVIDENCE — CRITICAL & HIGH SEVERITY FINDINGS")
        print(f"{'━'*70}{C.X}")
        for f in critical_high:
            print(f"\n  {sev_badge(f.severity)} {C.W}{f.title}{C.X}")
            print(f"  {C.D}Target:{C.X}  {f.target}")
            print(f"  {C.D}Module:{C.X}  {f.module}")
            if f.description:
                # Show first 300 chars of description
                desc = f.description[:300].replace('\n', '\n           ')
                print(f"  {C.D}Detail:{C.X}  {desc}")
            if f.payload:
                print(f"  {C.D}Payload:{C.X} {C.Y}{f.payload[:120]}{C.X}")
            if f.cve_ids:
                cves = f.cve_ids if isinstance(f.cve_ids, list) else json.loads(f.cve_ids) if f.cve_ids else []
                if cves:
                    print(f"  {C.D}CVEs:{C.X}    {C.R}{', '.join(cves[:5])}{C.X}")
            if f.ai_remediation:
                print(f"  {C.D}Fix:{C.X}     {C.G}{f.ai_remediation[:200]}{C.X}")
            if f.exploit_poc:
                print(f"  {C.D}POC:{C.X}     {C.R}{f.exploit_poc[:200]}{C.X}")
            print(f"  {C.D}{'─'*50}{C.X}")


# ── Scan Command ──────────────────────────────────────────────
async def run_scan(args):
    print(BANNER)
    logger.info(f"{C.CY}[*] Initializing assessment for target: {args.target}{C.X}")

    cfg = Config.load("config_medusa.yaml")

    scope_ips = args.scope_ips.split(",") if args.scope_ips else []
    scope_domains = args.scope_domains.split(",") if args.scope_domains else []

    import ipaddress
    try:
        ipaddress.ip_address(args.target)
        if args.target not in scope_ips: scope_ips.append(args.target)
    except ValueError:
        if args.target not in scope_domains: scope_domains.append(args.target)

    guard = ScopeGuard(
        ips=scope_ips,
        domains=scope_domains,
        cidrs=args.scope_cidrs.split(",") if args.scope_cidrs else [],
    )
    bucket = TokenBucket(rate=args.rate)
    session = Session(cfg=cfg, name=f"CLI-{args.target}")
    
    scan_start = time.time()
    logger.info(f"{C.D}  Session: {session.id}{C.X}")
    logger.info(f"{C.D}  Policy:  {args.type}/{getattr(args, 'policy', 'standard')}{C.X}")

    # ── Network Scan ──
    if args.type in ["all", "network"]:
        logger.info(f"\n{C.CY}[▶] NETWORK ENUMERATION{C.X}")
        net_scanner = NetworkScanner(guard, bucket)
        profiles = await net_scanner.run(args.target, session)
        
        if profiles:
            for host in profiles:
                print(f"\n  {C.W}Host: {host.ip}{C.X}", end="")
                if host.hostname:
                    print(f" ({host.hostname})", end="")
                if host.os_guess:
                    print(f"  │  OS: {host.os_guess}", end="")
                print()
                
                if host.ports:
                    headers = ["PORT", "STATE", "SERVICE", "VERSION", "CVEs"]
                    rows = []
                    for p in host.ports:
                        cve_str = ""
                        if p.cves:
                            cve_str = f"{len(p.cves)} CVE(s)"
                        rows.append([
                            f"{p.port}/{p.protocol}",
                            p.state,
                            p.service or "unknown",
                            f"{p.product} {p.version}".strip() or "-",
                            cve_str or "-",
                        ])
                    render_table(headers, rows, [12, 8, 16, 28, 14])
                else:
                    print(f"  {C.D}No open ports detected{C.X}")
        else:
            print(f"  {C.D}No hosts responded (target may be filtered or down){C.X}")

    # ── Active Directory ──
    if args.type in ["all", "ad"]:
        from medusa.engine.modules.redteam.active_dir import ActiveDirAttacks
        hacker = HackerAI(cfg.ai)
        ad_attacker = ActiveDirAttacks(guard, bucket, ai=hacker)
        logger.info(f"\n{C.CY}[▶] ACTIVE DIRECTORY ASSESSMENT{C.X}")
        domain = getattr(args, "domain", "TARGET.LOCAL")
        creds = {"username": args.user, "password": args.password} if hasattr(args, "user") and args.user else {}
        await ad_attacker.run(domain, args.target, creds, session)

    # ── Web Scan ──
    if args.type in ["all", "web"]:
        web_scanner = ActiveScanner(guard, bucket)
        logger.info(f"\n{C.CY}[▶] WEB VULNERABILITY ASSESSMENT (policy: {args.policy}){C.X}")
        if args.exploit:
            logger.info(f"  {C.R}⚡ Exploit generation ACTIVE{C.X}")
        
        result = await web_scanner.run(args.target, args.policy, None, session)
        
        if result:
            print(f"\n  {C.W}Web Scan Summary:{C.X}")
            print(f"  {C.D}Duration:{C.X}   {result.scan_duration:.1f}s")
            print(f"  {C.D}Modules:{C.X}    {', '.join(result.modules_run)}")
            print(f"  {C.D}Coverage:{C.X}   {result.coverage_score*100:.0f}%")
            print(f"  {C.D}Findings:{C.X}   {result.total_findings}")

    # ── Sovereign Scanner ──
    if args.type in ["all", "web", "network"]:
        from medusa.engine.modules.redteam.sovereign_scanner import run_sovereign
        logger.info(f"\n{C.CY}[▶] ADVANCED DETECTION ENGINE{C.X}")
        await run_sovereign(guard, bucket, args.target, session)

    # ── AI Triage ──
    if not args.no_ai:
        findings = session.findings
        if findings:
            logger.info(f"\n{C.CY}[▶] AI TRIAGE ({len(findings)} findings){C.X}")
            triage = AITriage()
            results = await triage.run(findings, session)
            fp = sum(1 for r in results if r.assessment.is_false_positive) if results else 0
            if results:
                print(f"  {C.G}Triaged: {len(results)} │ False positives removed: {fp}{C.X}")

    # ── Report Generation ──
    if args.report:
        report_writer = ReportWriter()
        report_format = getattr(args, 'report_format', 'json')
        report_path = await report_writer.write(session, format=report_format)
        logger.info(f"\n{C.G}[+] Report: {report_path}{C.X}")

    # ── Final Results ──
    elapsed = time.time() - scan_start
    all_findings = session.findings
    
    print(f"\n{C.CY}{'━'*70}")
    print(f"  ASSESSMENT COMPLETE — {elapsed:.1f}s elapsed")
    print(f"{'━'*70}{C.X}")

    render_findings(all_findings, f"ASSESSMENT RESULTS — {args.target}")

    # ── Interactive Handoff ──
    if hasattr(args, "luna") and args.luna:
        logger.info(f"\n{C.P}[*] Initializing interactive agent...{C.X}")
        from medusa.engine.modules.ai.chat import LunaChat
        await LunaChat().start(session_id=session.id)


# ── Onion Recon ───────────────────────────────────────────────
async def run_onion(args):
    from medusa.engine.modules.network import dark_crawler as dc

    print(BANNER)
    logger.info(f"{C.CY}[▶] TOR HIDDEN SERVICE RECONNAISSANCE{C.X}")

    from_cli = [u.strip() if u.strip().startswith('http') else 'http://' + u.strip() for u in args.urls if u and u.strip()]
    from_file = dc.load_urls_from_file(args.url_file) if args.url_file else dc.load_urls_from_file(dc.DEFAULT_URLS_FILE)

    seen = set()
    combined = []
    for u in from_cli + from_file:
        if u not in seen:
            seen.add(u)
            combined.append(u)

    if not combined:
        combined = [
            "http://flock4cvv5i2edtmeoy5o2jiso2uw5qpkep7ra3mdbfg3swvj5ydyxqd.onion",
            "http://7su7pr275vbrx7yh6rr7k5g7izm7drdui47sd3pm7wuqiacfz7wmnsqd.onion",
            "http://oniodtu6xudkiblcijrwwkduu2tdle3rav7nlszrjhrxpjtkg4brmgqd.onion",
        ]
        logger.info(f"  {C.D}Using built-in target list ({len(combined)} URLs){C.X}")

    session = dc.create_tor_session()
    
    # Verify Tor tunnel
    logger.info(f"  {C.D}Verifying Tor tunnel...{C.X}")
    is_tor = dc.check_tor_connectivity(session)
    if not is_tor:
        print(f"  {C.R}[!] Tor tunnel not active. Ensure Tor is running on port 9050.{C.X}")
        print(f"  {C.D}Install: https://www.torproject.org/download/{C.X}")
        return

    os.makedirs(dc.RESULTS_BASE_DIR, exist_ok=True)
    total_pages = 0

    for url in combined:
        if not dc.is_valid_onion_url(url):
            print(f"  {C.Y}[SKIP] Invalid onion URL: {url[:50]}...{C.X}")
            continue

        hostname = url.split("//")[1].split("/")[0][:16]
        logger.info(f"\n  {C.CY}[*] Crawling: {hostname}...{C.X}")

        try:
            site_data = await asyncio.to_thread(dc.crawl_site, url, session, tor_password=args.password)

            if site_data:
                res_dir = dc.get_result_dir_for_url(url)
                dc.save_results_json(site_data, os.path.join(res_dir, "crawl_results.json"))
                dc.save_results_csv(site_data, os.path.join(res_dir, "crawl_results.csv"))

                # Render results
                print(f"  {C.G}[+] Extracted {len(site_data)} page(s){C.X}")
                headers = ["#", "TITLE", "URL", "CONTENT_LENGTH"]
                rows = []
                for i, page in enumerate(site_data, 1):
                    rows.append([
                        str(i),
                        (page.get('title', 'N/A'))[:35],
                        (page.get('url', ''))[:40],
                        f"{len(page.get('text', ''))} chars",
                    ])
                render_table(headers, rows, [4, 35, 40, 14])
                total_pages += len(site_data)
                print(f"  {C.D}Results saved: {res_dir}/{C.X}")
            else:
                print(f"  {C.Y}[!] No pages extracted (site may be offline){C.X}")

        except Exception as e:
            print(f"  {C.R}[!] Crawl error: {e}{C.X}")

    print(f"\n{C.G}[+] Reconnaissance complete. {total_pages} total pages extracted.{C.X}")
    print(f"{C.D}    Results directory: {dc.RESULTS_BASE_DIR}/{C.X}\n")


# ── Cam Hunter ────────────────────────────────────────────────
async def run_cam_hunter(args):
    from medusa.engine.modules.recon.cam_hunter import CamHunter

    print(BANNER)
    logger.info(f"{C.CY}[▶] VISUAL RECONNAISSANCE ENGINE{C.X}")
    logger.info(f"  {C.D}Limit: {args.limit} per source{C.X}")

    cfg = Config.load("config_medusa.yaml")
    proxy = cfg.network.tor_proxy if cfg.network.use_tor else None

    hunter = CamHunter(proxy=proxy)
    results = await hunter.hunt(limit=args.limit)

    if results:
        headers = ["#", "SOURCE", "NAME", "TYPE", "STREAM/URL"]
        rows = []
        for i, res in enumerate(results, 1):
            stream = res.get('stream', res.get('snapshot', res.get('url', '-')))
            rows.append([
                str(i),
                res.get('site', 'N/A')[:12],
                res.get('name', 'N/A')[:25],
                res.get('type', 'N/A')[:10],
                stream[:45],
            ])
        render_table(headers, rows, [4, 12, 25, 10, 45])

        # Save results
        results_dir = os.path.join("breaches", "cam_footage")
        os.makedirs(results_dir, exist_ok=True)
        outfile = os.path.join(results_dir, "discovered_targets.json")
        with open(outfile, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n  {C.G}[+] {len(results)} targets discovered. Saved: {outfile}{C.X}")
    else:
        print(f"  {C.Y}[!] No results. Sources may be unavailable.{C.X}")


# ── AI Query ──────────────────────────────────────────────────
async def run_ask(args):
    print(BANNER)
    cfg = Config.load("config_medusa.yaml")
    hacker = HackerAI(cfg.ai)

    logger.info(f"{C.CY}[▶] AI TACTICAL QUERY{C.X}")
    logger.info(f"  {C.D}Model: {cfg.ai.model} via {cfg.ai.provider}{C.X}\n")
    
    resp = await hacker.provide_guidance(args.query)
    
    print(f"{C.CY}{'━'*60}")
    print(f"  RESPONSE")
    print(f"{'━'*60}{C.X}")
    print(resp)
    print(f"{C.CY}{'━'*60}{C.X}")


# ── Exploit Gen ───────────────────────────────────────────────
async def run_exploit_gen(args):
    print(BANNER)
    cfg = Config.load("config_medusa.yaml")
    session = Session(cfg=cfg, name="ExploitGen")
    hacker = HackerAI(cfg.ai)

    finding = session.db_session.query(FindingModel).filter_by(id=args.finding_id).first()
    if not finding:
        print(f"  {C.R}[!] Finding ID '{args.finding_id}' not found in database.{C.X}")
        return

    logger.info(f"{C.CY}[▶] EXPLOIT GENERATION{C.X}")
    logger.info(f"  {C.D}Target: {finding.title} @ {finding.target}{C.X}")
    
    exploit = await hacker.generate_exploit(finding)
    
    print(f"\n{C.R}{'━'*60}")
    print(f"  GENERATED EXPLOIT — {finding.title}")
    print(f"{'━'*60}{C.X}")
    print(exploit)
    print(f"{C.R}{'━'*60}{C.X}")


# ── Leak Lookup ───────────────────────────────────────────────
async def run_leak_lookup(args):
    from medusa.engine.modules.recon.leak_lookup import LeakLookup

    print(BANNER)
    cfg = Config.load("config_medusa.yaml")

    api_key = os.environ.get("LEAKLOOKUP_API_KEY") or cfg.ai.leak_lookup_api_key
    if not api_key:
        print(f"  {C.R}[!] LEAKLOOKUP_API_KEY not configured.{C.X}")
        return

    logger.info(f"{C.CY}[▶] CREDENTIAL INTELLIGENCE LOOKUP{C.X}")
    logger.info(f"  {C.D}Query: {args.query} (type: {args.type}){C.X}\n")
    
    lookup = LeakLookup(api_key=api_key)
    results = await lookup.search(args.query, args.type)

    if "error" in results and results["error"] != "false":
        print(f"  {C.R}[!] Error: {results.get('message', results.get('error'))}{C.X}")
    else:
        print(f"{C.G}[+] Intelligence recovered{C.X}")
        print(f"\n{C.CY}{'━'*60}")
        print(f"  BREACH DATA — {args.query}")
        print(f"{'━'*60}{C.X}")

        message = results.get("message", {})
        if isinstance(message, dict):
            total_records = 0
            for leak_name, records in message.items():
                record_count = len(records) if isinstance(records, list) else 1
                total_records += record_count
                print(f"\n  {C.R}[BREACH]{C.X} {C.W}{leak_name}{C.X} — {record_count} record(s)")
                if isinstance(records, list):
                    for record in records[:10]:  # Limit display to 10 per breach
                        if isinstance(record, dict):
                            for k, v in record.items():
                                print(f"    {C.D}{k}:{C.X} {v}")
                            print(f"    {C.D}{'─'*40}{C.X}")
                        else:
                            print(f"    • {record}")
                    if len(records) > 10:
                        print(f"    {C.D}... and {len(records) - 10} more records{C.X}")
                else:
                    print(f"    {records}")
            print(f"\n  {C.W}Total breaches: {len(message)} │ Total records: {total_records}{C.X}")
        else:
            print(f"  {message}")
        print(f"\n{C.CY}{'━'*60}{C.X}")


# ── Reverse Shell Gen ─────────────────────────────────────────
async def run_rev_gen(args):
    from medusa.engine.modules.payloads.rev_gen import ReverseShellGenerator

    print(BANNER)
    gen = ReverseShellGenerator()

    if args.list:
        print(f"{C.CY}[*] Available payload templates:{C.X}")
        for c in gen.list_commands():
            print(f"  {C.G}•{C.X} {c}")
        return

    if not args.ip or not args.port or not args.command_name:
        print(f"  {C.R}[!] Required: <ip> <port> <command_name>{C.X}")
        print(f"  {C.D}Use --list to see available templates{C.X}")
        return

    payload = gen.generate(args.ip, args.port, args.command_name, args.shell, args.encode)

    print(f"\n{C.R}{'━'*60}")
    print(f"  PAYLOAD — {args.command_name.upper()}")
    print(f"  LHOST: {args.ip}  LPORT: {args.port}")
    print(f"{'━'*60}{C.X}")
    print(payload)
    print(f"{C.R}{'━'*60}{C.X}")

    if args.save:
        filename = f"payload_{args.command_name}_{args.port}.txt"
        path = gen.save_to_downloads(payload, filename)
        print(f"\n  {C.G}[+] Saved: {path}{C.X}")


# ── Sovereign Scan (Standalone) ───────────────────────────────
async def run_sovereign_scan(args):
    from medusa.engine.modules.redteam.sovereign_scanner import run_sovereign

    print(BANNER)
    logger.info(f"{C.CY}[▶] ADVANCED DETECTION ENGINE — {args.target}{C.X}")

    cfg = Config.load("config_medusa.yaml")
    guard = ScopeGuard(ips=[args.target], domains=[], cidrs=[])
    bucket = TokenBucket(rate=10)
    session = Session(cfg=cfg, name=f"SOVEREIGN-{args.target}")

    await run_sovereign(guard, bucket, args.target, session)

    render_findings(session.findings, f"INTELLIGENCE REPORT — {args.target}")


# ── Report Format ─────────────────────────────────────────────
async def run_report_format(args):
    """Generate report from saved session data."""
    print(BANNER)
    cfg = Config.load("config_medusa.yaml")
    
    from medusa.engine.core.models import init_db, SessionModel
    db = init_db(cfg.database_url)
    
    sessions = db.query(SessionModel).order_by(SessionModel.started_at.desc()).all()
    if not sessions:
        print(f"  {C.Y}[!] No sessions found in database.{C.X}")
        return
    
    print(f"{C.CY}[*] Saved Sessions:{C.X}\n")
    headers = ["#", "ID", "NAME", "STATUS", "STARTED", "FINDINGS"]
    rows = []
    for i, s in enumerate(sessions, 1):
        finding_count = db.query(FindingModel).filter_by(session_id=s.id).count()
        rows.append([
            str(i),
            str(s.id)[:12] + "...",
            (s.name or "N/A")[:20],
            s.status or "unknown",
            str(s.started_at)[:19] if s.started_at else "-",
            str(finding_count),
        ])
    render_table(headers, rows, [4, 15, 20, 10, 19, 8])


# ── Main Parser ───────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Security Assessment Framework CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Scan
    scan_p = subparsers.add_parser("scan", help="Run vulnerability assessment")
    scan_p.add_argument("target", help="Target URL or IP address")
    scan_p.add_argument("-t", "--type", choices=["web", "network", "ad", "all"], default="all")
    scan_p.add_argument("-p", "--policy", default="standard", help="Scan policy")
    scan_p.add_argument("-r", "--rate", type=int, default=10, help="Rate limit (req/sec)")
    scan_p.add_argument("-x", "--exploit", action="store_true", help="Enable POC generation")
    scan_p.add_argument("-u", "--user", help="Username for AD/Auth")
    scan_p.add_argument("-w", "--password", help="Password for AD/Auth")
    scan_p.add_argument("-d", "--domain", default="TARGET.LOCAL", help="Domain for AD")
    scan_p.add_argument("--report", action="store_true", help="Generate report")
    scan_p.add_argument("--scope-ips", help="Whitelisted IPs (comma-separated)")
    scan_p.add_argument("--scope-domains", help="Whitelisted domains")
    scan_p.add_argument("--scope-cidrs", help="Whitelisted CIDRs")
    scan_p.add_argument("--no-ai", action="store_true", help="Disable AI triage")
    scan_p.add_argument("--luna", action="store_true", help="Interactive agent after scan")
    scan_p.add_argument("--report-format", default="json", choices=["json", "html", "pdf"])

    # Luna
    luna_p = subparsers.add_parser("luna", help="Interactive AI agent")
    luna_p.add_argument("--session", help="Session ID for context")

    # Ask
    ask_p = subparsers.add_parser("ask", help="Tactical AI query")
    ask_p.add_argument("query", help="Question for AI")

    # Exploit Gen
    eg_p = subparsers.add_parser("exploit-gen", help="Generate exploit script for finding")
    eg_p.add_argument("finding_id", type=int, help="Finding ID")

    # Onion Recon
    onion_p = subparsers.add_parser("onion", help="Hidden service reconnaissance")
    onion_p.add_argument("urls", nargs="*", help=".onion URLs to crawl")
    onion_p.add_argument("-f", "--url-file", help="File with .onion URLs")
    onion_p.add_argument("--password", help="Tor ControlPort password")

    # Cam Hunter
    cam_p = subparsers.add_parser("cam-hunter", help="Visual reconnaissance")
    cam_p.add_argument("--limit", type=int, default=10, help="Max results per source")

    # Leak Lookup
    leak_p = subparsers.add_parser("leak-lookup", help="Credential intelligence search")
    leak_p.add_argument("query", help="Search query")
    leak_p.add_argument("-t", "--type", default="email_address",
                        choices=["email_address", "username", "ipaddress", "phone", "domain", "password", "fullname"])

    # Rev Gen
    rev_p = subparsers.add_parser("rev-gen", help="Reverse shell payload generation")
    rev_p.add_argument("ip", nargs="?", help="LHOST IP")
    rev_p.add_argument("port", nargs="?", help="LPORT")
    rev_p.add_argument("command_name", nargs="?", help="Payload template name")
    rev_p.add_argument("-s", "--shell", default="/bin/bash", help="Shell path")
    rev_p.add_argument("-e", "--encode", default="none", choices=["none", "url", "base64"])
    rev_p.add_argument("-l", "--list", action="store_true", help="List available payloads")
    rev_p.add_argument("--save", action="store_true", help="Save payload to Downloads")

    # Sovereign Scan
    sov_p = subparsers.add_parser("sovereign-scan", help="Advanced detection engine")
    sov_p.add_argument("target", help="Target URL or IP")

    # Sessions
    sess_p = subparsers.add_parser("sessions", help="List saved assessment sessions")

    args = parser.parse_args()

    try:
        if args.command == "scan":
            asyncio.run(run_scan(args))
        elif args.command == "ask":
            asyncio.run(run_ask(args))
        elif args.command == "exploit-gen":
            asyncio.run(run_exploit_gen(args))
        elif args.command == "luna":
            from medusa.engine.modules.ai.chat import LunaChat
            asyncio.run(LunaChat().start(session_id=args.session))
        elif args.command == "onion":
            asyncio.run(run_onion(args))
        elif args.command == "cam-hunter":
            asyncio.run(run_cam_hunter(args))
        elif args.command == "leak-lookup":
            asyncio.run(run_leak_lookup(args))
        elif args.command == "rev-gen":
            asyncio.run(run_rev_gen(args))
        elif args.command == "sovereign-scan":
            asyncio.run(run_sovereign_scan(args))
        elif args.command == "sessions":
            asyncio.run(run_report_format(args))
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Interrupted.{C.X}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"\n{C.R}[!] Fatal: {e}{C.X}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
