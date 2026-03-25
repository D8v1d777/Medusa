"""
Medusa CLI — The Hacker's Interface.
A Linux-style command line interface for high-performance pentesting.
Replaces the GUI for efficient, automated, and exploitative operations.
"""
import argparse
import asyncio
import logging
import sys
import os
from typing import Optional
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

# Setup logging to console
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
# Aggressive Silencing of HTTP internal loggers
for logger_name in ["httpx", "httpcore", "urllib3"]:
    logging.getLogger(logger_name).setLevel(logging.WARNING)

logger = logging.getLogger("medusa-cli")

BANNER = r"""
  __  __ _____ _____  _    _  _____         
 |  \/  |  ___|  __ \| |  | |/ ____|   /\   
 | \  / | |__ | |  | | |  | | (___    /  \  
 | |\/| |  __|| |  | | |  | |\___ \  / /\ \ 
 | |  | | |___| |__| | |__| |____) |/ ____ \
 |_|  |_|_____|_____/ \____/|_____//_/    \_\
    >> The Medusa Security Framework <<
"""

async def run_scan(args):
    """Orchestrates a scan from the CLI."""
    print(BANNER)
    logger.info(f"[*] Initializing session for target: {args.target}")
    
    # Setup core components
    cfg = Config.load("config_medusa.yaml")
    
    # Auto-include target in scope
    scope_ips = args.scope_ips.split(",") if args.scope_ips else []
    scope_domains = args.scope_domains.split(",") if args.scope_domains else []
    
    # Try to determine if target is IP or Domain
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
    
    # 1. Run Network Scan (if enabled or default)
    if args.type in ["all", "network"]:
        net_scanner = NetworkScanner(guard, bucket)
        logger.info(f"[*] Starting Network Enumeration...")
        await net_scanner.run(args.target, session)

    # 2. Run AD Scan (Active Directory)
    if args.type in ["all", "ad"]:
        from medusa.engine.modules.redteam.active_dir import ActiveDirAttacks
        hacker = HackerAI(cfg.ai)
        ad_attacker = ActiveDirAttacks(guard, bucket, ai=hacker)
        logger.info(f"[*] Starting Active Directory Attack Suite...")
        # DC IP is target, domain and credentials can be provided via args
        domain = getattr(args, "domain", "MEDUSA.LOCAL")
        creds = {"username": args.user, "password": args.password} if hasattr(args, "user") else {}
        await ad_attacker.run(domain, args.target, creds, session)

    # 3. Run Web Scan
    if args.type in ["all", "web"]:
        web_scanner = ActiveScanner(guard, bucket)
        logger.info(f"[*] Starting Web Vulnerability Scan (Policy: {args.policy})...")
        if args.exploit:
            logger.info("[!] EXPLOIT MODE ENABLED: Generating POCs for all findings.")
        
        await web_scanner.run(args.target, args.policy, None, session)

    # 4. Run Sovereign Expert Scanner
    if args.type in ["all", "web", "network"]:
        from medusa.engine.modules.redteam.sovereign_scanner import run_sovereign
        logger.info(f"[*] DEPLOYING SOVEREIGN_EXPERTISE: Analyzing advanced redteam markers...")
        await run_sovereign(guard, bucket, args.target, session)

    # 3. AI Triage & Analysis
    if not args.no_ai:
        logger.info("[*] Running AI Triage and Analysis...")
        triage = AITriage()
        await triage.run(session.findings, session)

    # 4. Generate Report
    if args.report:
        report_writer = ReportWriter()
        report_path = await report_writer.write(session, format=args.report_format)
        logger.info(f"[+] Report generated at: {report_path}")

    # Summary Output
    logger.info("\n[+] Scan Complete.")
    logger.info(f"[+] Total Findings: {len(session.findings)}")
    for f in session.findings:
        color = "\033[91m" if f.severity in ["critical", "high"] else "\033[93m"
        reset = "\033[0m"
        logger.info(f"  - {color}[{f.severity.upper()}]{reset} {f.title} ({f.target})")
        if args.exploit and hasattr(f, "exploit_poc") and f.exploit_poc:
            logger.info(f"    [!] POC: {f.exploit_poc}")

    # 5. Strategic Handoff (optional)
    if hasattr(args, "luna") and args.luna:
        logger.info("\n[*] HANDOFF: Initializing Sovereign Offensive Interface...")
        from medusa.engine.modules.ai.chat import LunaChat
        await LunaChat(user_name="David").start(session_id=session.id)

async def run_onion(args):
    """Executes the original DarkCrawler reconnaissance engine."""
    from medusa.engine.modules.network import dark_crawler as dc
    
    dc.print_banner()
    
    # 1) Resolve URLs (Mirroring original parse_args logic)
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
        dc.logging.info("No URLs specified; utilizing built-in LUNA Intelligence list.")

    # 2) Initialize Original Procedural Engine
    session = dc.create_tor_session()
    os.makedirs(dc.RESULTS_BASE_DIR, exist_ok=True)

    for url in combined:
        if not dc.is_valid_onion_url(url):
            dc.logging.warning(f"Invalid .onion URL skipped: {url}")
            continue
        
        dc.logging.info(f"[*] DEPLOYING ONION_RECON: {url}")
        try:
            # Running synchronous original crawl_site logic
            site_data = await asyncio.to_thread(dc.crawl_site, url, session, tor_password=args.password)

            res_dir = dc.get_result_dir_for_url(url)
            dc.save_results_json(site_data, os.path.join(res_dir, "darkweb_crawl_results.json"))
            dc.save_results_csv(site_data, os.path.join(res_dir, "darkweb_crawl_results.csv"))
        except Exception as e:
            dc.logging.error(f"[!] RECON FAILURE on {url}: {e}")

    print(f"\n{dc.Colors.NEON_GREEN}Reconnaissance complete! Results saved in {dc.RESULTS_BASE_DIR}/ (one folder per URL).{dc.Colors.RESET}\n")

async def run_cam_hunter(args):
    """Orchestrates a visual reconnaissance mission across global cam portals."""
    from medusa.engine.modules.recon.cam_hunter import CamHunter
    
    logger.info(rf"""
    {BANNER}
    [*] INITIALIZING CAM_HUNTER RECON...
    """)
    
    cfg = Config.load("config_medusa.yaml")
    proxy = cfg.network.tor_proxy if cfg.network.use_tor else None
    
    hunter = CamHunter(proxy=proxy)
    results = await hunter.hunt(limit=args.limit)
    
    # Store results as findings or just log them
    logger.info(f"[+] Hunt Complete. Discovered {len(results)} active visual targets.")
    
    # Create the cam_footage directory if it doesn't exist
    results_dir = os.path.join("breaches", "cam_footage")
    os.makedirs(results_dir, exist_ok=True)
    
    # Save results to tactical vault
    import json
    with open(os.path.join(results_dir, "discovered_cams.json"), "w") as f:
        json.dump(results, f, indent=4)
        
    for res in results:
        logger.info(f"  - [{res['site']}] {res['name']} ({res['type']})")
        logger.info(f"    Source: {res['url']}")
        if 'stream' in res: logger.info(f"    Stream: {res['stream']}")
        if 'snapshot' in res: logger.info(f"    Snapshot: {res['snapshot']}")
        
    logger.info(f"\n[+] Tactical intel committed to: {results_dir}")


async def run_ask(args):
    """Invokes the Hacker AI for tactical guidance."""
    print(BANNER)
    cfg = Config.load("config_medusa.yaml")
    hacker = HackerAI(cfg.ai)
    
    logger.info(f"[*] Querying Hacker AI (Model: {cfg.ai.model})...")
    resp = await hacker.provide_guidance(args.query)
    print("\n" + "="*40 + "\n HACKER AI STRATEGIC GUIDANCE \n" + "="*40)
    print(resp)
    print("="*40)

async def run_exploit_gen(args):
    """Generates an exploit script for a specific finding."""
    print(BANNER)
    cfg = Config.load("config_medusa.yaml")
    session = Session(cfg=cfg, name="CLI-ExploitGen")
    hacker = HackerAI(cfg.ai)
    
    finding = session.db_session.query(FindingModel).filter_by(id=args.finding_id).first()
    if not finding:
        logger.error(f"[!] Finding ID '{args.finding_id}' not found.")
        return

    logger.info(f"[*] Generating weaponized exploit for: {finding.title}...")
    exploit = await hacker.generate_exploit(finding)
    print("\n" + "="*40 + "\n WEAPONIZED EXPLOIT SCRIPT \n" + "="*40)
    print(exploit)
    print("="*40)

async def run_leak_lookup(args):
    """Searches for compromised data via Leak-Lookup.com."""
    from medusa.engine.modules.recon.leak_lookup import LeakLookup
    
    print(BANNER)
    cfg = Config.load("config_medusa.yaml")
    
    # Priority: Environment variable > Config File
    api_key = os.environ.get("LEAKLOOKUP_API_KEY") or cfg.ai.leak_lookup_api_key
    
    if not api_key:
        logger.error("[!] Error: LEAKLOOKUP_API_KEY not found in environment or config.")
        return

    logger.info(f"[*] INITIALIZING LEAK_LOOKUP ({args.type}: {args.query})...")
    lookup = LeakLookup(api_key=api_key)
    results = await lookup.search(args.query, args.type)
    
    if "error" in results and results["error"] != "false":
        logger.error(f"[!] Leak-Lookup Error: {results.get('message', results.get('error'))}")
    else:
        logger.info(f"[+] Operational Intel Recovered!")
        print("\n" + "="*60)
        print(f" LEAK LOOKUP RESULTS: {args.query}")
        print("="*60)
        
        # Results are usually in result.message for successes
        message = results.get("message", {})
        if isinstance(message, dict):
            for leak_name, records in message.items():
                print(f"\n[!] DATASET: {leak_name}")
                if isinstance(records, list):
                    for record in records:
                        print(f"   - {record}")
                else:
                    print(f"   - {records}")
        else:
            print(message)
        print("\n" + "="*60)

async def run_rev_gen(args):
    """Generates a reverse shell payload."""
    from medusa.engine.modules.payloads.rev_gen import ReverseShellGenerator
    
    print(BANNER)
    gen = ReverseShellGenerator()
    
    if args.list:
        print("[*] AVAILABLE REVERSE SHELL COMMANDS:")
        for c in gen.list_commands():
            print(f"  - {c}")
        return

    if not args.ip or not args.port or not args.command_name:
        print("[!] Missing arguments. Usage: medusa rev-gen <ip> <port> <command_name> [-s shell] [-e encode]")
        return

    payload = gen.generate(args.ip, args.port, args.command_name, args.shell, args.encode)
    
    print("\n" + "="*60)
    print(f" WEAPONIZED REVERSE SHELL: {args.command_name.upper()}")
    print("="*60)
    print(payload)
    print("="*60)

    if args.save:
        filename = f"rev_{args.command_name}_{args.port}.txt"
        path = gen.save_to_downloads(payload, filename)
        print(f"[+] Operational payload committed to: {path}")

async def run_sovereign_scan(args):
    """Standalone Sovereign Expert Scan."""
    from medusa.engine.modules.redteam.sovereign_scanner import run_sovereign
    print(BANNER)
    logger.info(f"[*] INITIALIZING SOVEREIGN_SCAN for target: {args.target}")
    
    cfg = Config.load("config_medusa.yaml")
    # Auto-include target in scope
    guard = ScopeGuard(ips=[args.target], domains=[], cidrs=[])
    bucket = TokenBucket(rate=10)
    session = Session(cfg=cfg, name=f"SOVEREIGN-{args.target}")
    
    await run_sovereign(guard, bucket, args.target, session)
    
    print("\n" + "="*60)
    print(" SOVEREIGN INTELLIGENCE RECOVERED")
    print("="*60)
    for f in session.findings:
        print(f"\n[!] {f.title.upper()}")
        print(f"    SEVERITY: {f.severity.upper()}")
        print(f"    DETAILS: \n{f.description}")
    print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(description="Medusa CLI — Advanced Pentesting Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Scan Command
    scan_p = subparsers.add_parser("scan", help="Run a new vulnerability scan")
    scan_p.add_argument("target", help="Target URL or IP address")
    scan_p.add_argument("-t", "--type", choices=["web", "network", "ad", "all"], default="all", help="Scan type")
    scan_p.add_argument("-p", "--policy", default="standard", help="Web scan policy")
    scan_p.add_argument("-r", "--rate", type=int, default=10, help="Rate limit (req/sec)")
    scan_p.add_argument("-x", "--exploit", action="store_true", help="Enable exploitative POC generation")
    scan_p.add_argument("-u", "--user", help="Username for AD/Auth")
    scan_p.add_argument("-w", "--password", help="Password for AD/Auth")
    scan_p.add_argument("-d", "--domain", default="MEDUSA.LOCAL", help="Domain for AD operations")
    scan_p.add_argument("--report", action="store_true", help="Generate final report")
    scan_p.add_argument("--scope-ips", help="Whitelisted IPs")
    scan_p.add_argument("--scope-domains", help="Whitelisted domains")
    scan_p.add_argument("--scope-cidrs", help="Whitelisted CIDR ranges")
    scan_p.add_argument("--no-ai", action="store_true", help="Disable AI processing")
    scan_p.add_argument("--luna", action="store_true", help="Drop into Luna Chat after scan")

    # Luna Interaction Commands
    luna_p = subparsers.add_parser("luna", help="Launch interactive chat with Luna Rodriguez")
    luna_p.add_argument("--session", help="Resume from specific session ID for context")

    # Ask Command
    ask_p = subparsers.add_parser("ask", help="Direct tactical query for Luna")
    ask_p.add_argument("query", help="The question or command for the AI subagent")

    # Exploit Gen Command
    exploit_gen_p = subparsers.add_parser("exploit-gen", help="Generate an exploit script for a specific finding")
    exploit_gen_p.add_argument("finding_id", type=int, help="ID of the finding to generate an exploit for")

    # DarkCrawler Command
    onion_p = subparsers.add_parser("onion", help="Stealthy .onion reconnaissance via Tor")
    onion_p.add_argument("urls", nargs="*", help="Direct .onion URLs to crawl")
    onion_p.add_argument("-f", "--url-file", help="File with .onion URLs")
    onion_p.add_argument("--password", help="Tor ControlPort password (optional)")

    # CamHunter Command
    cam_p = subparsers.add_parser("cam-hunter", help="Visual reconnaissance of live global cams")
    cam_p.add_argument("--limit", type=int, default=10, help="Max results per portal")

    # LeakLookup Command
    leak_p = subparsers.add_parser("leak-lookup", help="Search for compromised data via Leak-Lookup.com")
    leak_p.add_argument("query", help="The search query (email, username, etc.)")
    leak_p.add_argument("-t", "--type", default="email_address", 
                        choices=["email_address", "username", "ipaddress", "phone", "domain", "password", "fullname"], 
                        help="The type of data being searched")

    # RevShell Gen Command
    rev_p = subparsers.add_parser("rev-gen", help="Generate a weaponized reverse shell payload")
    rev_p.add_argument("ip", nargs="?", help="LHOST IP address")
    rev_p.add_argument("port", nargs="?", help="LPORT number")
    rev_p.add_argument("command_name", nargs="?", help="The payload template (e.g., unix_bash)")
    rev_p.add_argument("-s", "--shell", default="/bin/bash", help="Shell to use (e.g., /bin/sh)")
    rev_p.add_argument("-e", "--encode", default="none", choices=["none", "url", "base64"], help="Encoding type")
    rev_p.add_argument("-l", "--list", action="store_true", help="List available payloads")
    rev_p.add_argument("--save", action="store_true", help="Commit payload to local Downloads folder")

    # Sovereign Scan Command
    sov_p = subparsers.add_parser("sovereign-scan", help="Run standalone expert-level vulnerability detection")
    sov_p.add_argument("target", help="Target URL or IP address")

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
            asyncio.run(LunaChat(user_name="David").start(session_id=args.session))
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
        else:
            parser.print_help()
    except KeyboardInterrupt:
        logger.info("\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"\n[!] Critical Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
