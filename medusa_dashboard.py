"""
Medusa — Operational Dashboard v5.0
Author: David
Branding: SOVEREIGN OFFENSIVE INTELLIGENCE
"""
import os
import sys
import subprocess
import time
import argparse
import asyncio

class Colors:
    RED = '\033[1;31m'
    NEON_GREEN = '\033[1;92m'
    BLUE = '\033[1;94m'
    PURPLE = '\033[1;95m'
    RESET = '\033[0m'

BANNER = rf"""
{Colors.PURPLE}   __  __ _____ _____  _    _  _____         
  |  \/  |  ___|  __ \| |  | |/ ____|   /\   
  | \  / | |__ | |  | | |  | | (___    /  \  
  | |\/| |  __|| |  | | |  | |\___ \  / /\ \ 
  | |  | | |___| |__| | |__| |____) |/ ____ \
  |_|  |_|_____|_____/ \____/|_____//_/    \_\
{Colors.BLUE}
     >> MEDUSA SECURITY FRAMEWORK v5.0 <<
     >> AUTHOR: DAVID | STATUS: AUTHORIZED <<
{Colors.RESET}
"""

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

import asyncio
from medusa.engine import cli

def run_cmd(args):
    """Direct bridge to the medusa-cli motor (Optimized for .exe)."""
    parser = argparse.ArgumentParser() # Just a dummy to avoid sys.exit on error if needed
    
    # Mirroring cli.main() branching but calling functions directly for speed
    class DummyArgs:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)
    
    cmd_name = args[0]
    sub_args = args[1:]
    
    # Re-parsing for the specific command to match what cli.py expects
    print(f"{Colors.BLUE}[*] Launching: {cmd_name} {sub_args}{Colors.RESET}")
    
    try:
        # This is a bit of a hack to reuse cli.py's parser logic without spawning sub-processes
        # We'll just temporarily monkey-patch sys.argv
        old_argv = sys.argv
        sys.argv = ["medusa"] + args
        cli.main()
        sys.argv = old_argv
    except SystemExit:
        pass # Expected when parser finishes
    except Exception as e:
        print(f"{Colors.RED}[!] Execution Error: {e}{Colors.RESET}")
    
    input(f"\n{Colors.BLUE}[*] Press Enter to return to Command Center...{Colors.RESET}")

def main():
    while True:
        clear()
        print(BANNER)
        print(f"{Colors.NEON_GREEN}[1]{Colors.RESET} VULNERABILITY SCAN (Web/Network/AD)")
        print(f"{Colors.NEON_GREEN}[2]{Colors.RESET} LUNA CHAT (Interactive Strategy)")
        print(f"{Colors.NEON_GREEN}[3]{Colors.RESET} DARK CRAWLER (Onion Recon)")
        print(f"{Colors.NEON_GREEN}[4]{Colors.RESET} ASK LUNA (Tactical Query)")
        print(f"{Colors.NEON_GREEN}[5]{Colors.RESET} EXPLOIT GEN (Weaponize Finding)")
        print(f"{Colors.RED}[0]{Colors.RESET} DISCONNECT")
        print(f"\033[90m" + "─"*50 + "\033[0m")
        
        choice = input(f"{Colors.BLUE}[David@Medusa]{Colors.RESET} > ")

        if choice == "1":
            target = input(f"{Colors.NEON_GREEN}Target URL/IP: {Colors.RESET}")
            stype = input(f"{Colors.NEON_GREEN}Type (all/web/network/ad): {Colors.RESET}") or "all"
            run_cmd(["scan", target, "-t", stype, "--luna"])
            
        elif choice == "2":
            session = input(f"{Colors.NEON_GREEN}Session ID (optional): {Colors.RESET}")
            args = ["luna"]
            if session: args += ["--session", session]
            run_cmd(args)

        elif choice == "3":
            target = input(f"{Colors.NEON_GREEN}Onion URL(s): {Colors.RESET}")
            run_cmd(["onion", target])

        elif choice == "4":
            query = input(f"{Colors.NEON_GREEN}Tactical Query: {Colors.RESET}")
            run_cmd(["ask", query])

        elif choice == "5":
            fid = input(f"{Colors.NEON_GREEN}Finding ID (UUID): {Colors.RESET}")
            run_cmd(["exploit-gen", fid])

        elif choice == "0":
            print(f"\n{Colors.PURPLE}[*] Terminating Operational Session... Safe travels, David.{Colors.RESET}")
            time.sleep(1)
            break

if __name__ == "__main__":
    main()
