"""Operational Interface — v5.0"""
import os
import sys
import subprocess
import time
import argparse
import asyncio

class Colors:
    RED = '\033[1;31m'
    NEON_GREEN = '\033[1;92m'
    CYAN = '\033[1;96m'
    BLUE = '\033[1;94m'
    PURPLE = '\033[1;95m'
    YELLOW = '\033[1;93m'
    WHITE = '\033[1;97m'
    DIM = '\033[2m'
    RESET = '\033[0m'

BANNER = rf"""
{Colors.CYAN}
   __  ___        __                  
  /  |/  /___ ___/ /__ __ _____ _     
 / /|_/ / -_) _  / // (_-</ _ `/     
/_/  /_/\__/\_,_/\_,_/___/\_,_/      
{Colors.DIM}
    ┌─────────────────────────────────────────────┐
    │  INTEGRATED SECURITY ASSESSMENT FRAMEWORK   │
    │  Build: 5.0.0  │  Status: AUTHORIZED        │
    └─────────────────────────────────────────────┘
{Colors.RESET}"""

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

from medusa.engine import cli

def run_cmd(args):
    """Direct bridge to the engine CLI."""
    cmd_name = args[0]
    print(f"\n{Colors.CYAN}{'━'*50}")
    print(f"  Executing: {cmd_name} {' '.join(args[1:])}")
    print(f"{'━'*50}{Colors.RESET}\n")

    try:
        old_argv = sys.argv
        sys.argv = ["medusa"] + args
        cli.main()
        sys.argv = old_argv
    except SystemExit:
        pass
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")

    input(f"\n{Colors.DIM}[Press Enter to return]{Colors.RESET}")

def print_menu():
    """Render the command center menu."""
    clear()
    print(BANNER)
    
    modules = [
        ("1", "VULNERABILITY SCAN", "Web / Network / AD assessment", Colors.NEON_GREEN),
        ("2", "INTERACTIVE AGENT", "AI-assisted strategy session", Colors.NEON_GREEN),
        ("3", "HIDDEN SERVICE RECON", "Tor-routed .onion crawling", Colors.NEON_GREEN),
        ("4", "AI QUERY", "Tactical guidance engine", Colors.NEON_GREEN),
        ("5", "EXPLOIT GENERATOR", "POC weaponization from findings", Colors.YELLOW),
        ("6", "VISUAL RECON", "Global stream reconnaissance", Colors.YELLOW),
        ("7", "CREDENTIAL INTEL", "Breach data correlation", Colors.YELLOW),
        ("8", "PAYLOAD FACTORY", "Reverse shell generation", Colors.YELLOW),
        ("9", "EXPERT SCAN", "Advanced detection engine", Colors.PURPLE),
    ]
    
    for key, title, desc, color in modules:
        print(f"  {color}[{key}]{Colors.WHITE} {title:<24}{Colors.DIM}{desc}{Colors.RESET}")
    
    print(f"\n  {Colors.RED}[0]{Colors.WHITE} DISCONNECT{Colors.RESET}")
    print(f"\n{Colors.DIM}{'─'*50}{Colors.RESET}")

def get_input(prompt):
    """Styled input prompt."""
    return input(f"{Colors.CYAN}  ▸ {prompt}: {Colors.RESET}").strip()

def main():
    while True:
        print_menu()
        choice = input(f"\n{Colors.CYAN}  ┌──({Colors.WHITE}operator{Colors.CYAN})\n  └──▸ {Colors.RESET}")

        if choice == "1":
            target = get_input("Target URL/IP")
            if not target:
                continue
            stype = get_input("Type (all/web/network/ad)") or "all"
            run_cmd(["scan", target, "-t", stype])

        elif choice == "2":
            session = get_input("Session ID (optional)")
            args = ["luna"]
            if session: args += ["--session", session]
            run_cmd(args)

        elif choice == "3":
            target = get_input("Onion URL(s) [blank=default list]")
            args = ["onion"]
            if target:
                args.extend(target.split())
            run_cmd(args)

        elif choice == "4":
            query = get_input("Query")
            if query:
                run_cmd(["ask", query])

        elif choice == "5":
            fid = get_input("Finding ID (UUID)")
            if fid:
                run_cmd(["exploit-gen", fid])

        elif choice == "6":
            limit = get_input("Result limit (default 10)") or "10"
            run_cmd(["cam-hunter", "--limit", limit])

        elif choice == "7":
            query = get_input("Search query (email/user/IP)")
            if not query:
                continue
            stype = get_input("Type (email_address/username/ipaddress/phone/domain)") or "email_address"
            run_cmd(["leak-lookup", query, "-t", stype])

        elif choice == "8":
            print(f"\n{Colors.CYAN}  Available payload templates:{Colors.RESET}")
            try:
                from medusa.engine.modules.payloads.rev_gen import ReverseShellGenerator
                gen = ReverseShellGenerator()
                for c in gen.list_commands():
                    print(f"    {Colors.DIM}• {c}{Colors.RESET}")
            except Exception:
                print(f"    {Colors.DIM}(payload directory not initialized){Colors.RESET}")

            ip = get_input("LHOST IP")
            port = get_input("LPORT")
            pname = get_input("Payload name")
            if ip and port and pname:
                run_cmd(["rev-gen", ip, port, pname, "--save"])

        elif choice == "9":
            target = get_input("Target")
            if target:
                run_cmd(["sovereign-scan", target])

        elif choice == "0":
            print(f"\n{Colors.PURPLE}  Session terminated.{Colors.RESET}")
            time.sleep(0.5)
            break

if __name__ == "__main__":
    main()
