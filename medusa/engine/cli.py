"""
Medusa CLI — The Hacker's Interface.
A Linux-style command line interface for high-performance pentesting.
Replaces the GUI for efficient, automated, and exploitative operations.
"""
import argparse
import asyncio
import logging
import sys
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
    )
    bucket = TokenBucket(rate=args.rate, capacity=args.rate * 2)
    session = Session(cfg=cfg, name=f"CLI-{args.target}")
    
    # 1. Run Network Scan (if enabled or default)
    if args.type in ["all", "network"]:
        net_scanner = NetworkScanner(guard, bucket)
        logger.info(f"[*] Starting Network Enumeration...")
        await net_scanner.run(args.target, session)

    # 2. Run Web Scan
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
    scan_p.add_argument("-t", "--type", choices=["web", "network", "all"], default="all", help="Scan type")
    scan_p.add_argument("-p", "--policy", default="standard", help="Web scan policy")
    scan_p.add_argument("-r", "--rate", type=int, default=10, help="Rate limit (req/sec)")
    scan_p.add_argument("-x", "--exploit", action="store_true", help="Enable exploitative POC generation")
    scan_p.add_argument("--report", action="store_true", help="Generate final report")

    # Luna Interaction Commands
    luna_p = subparsers.add_parser("luna", help="Launch interactive chat with Luna Rodriguez")

    # Ask Command

    # Exploit Gen Command
    exp_p = subparsers.add_parser("exploit-gen", help="Generate an exploit script for a finding")
    exp_p.add_argument("finding_id", help="The UUID of the finding to weaponize")

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
            asyncio.run(LunaChat(user_name="David").start())
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
