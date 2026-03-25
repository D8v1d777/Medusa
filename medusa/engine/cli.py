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
    guard = ScopeGuard(
        ips=args.scope_ips.split(",") if args.scope_ips else [],
        domains=args.scope_domains.split(",") if args.scope_domains else [],
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
