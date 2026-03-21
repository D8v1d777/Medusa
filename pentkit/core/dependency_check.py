from __future__ import annotations
import importlib.metadata
import logging
import sys
import shutil
import subprocess
from typing import Dict, Tuple, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class DependencyReport:
    all_ok: bool
    issues: List[str]
    install_commands: List[str]

REQUIRED = {
    "impacket":        ("0.12.0", "pip install impacket==0.12.0"),
    "certipy-ad":      ("4.8.2",  "pip install certipy-ad==4.8.2"),
    "bloodhound":      ("1.6.1",  "pip install bloodhound==1.6.1"),
    "scapy":           ("2.5.0",  "pip install scapy==2.5.0"),
    "playwright":      ("1.43.0", "playwright install chromium"),
    "semgrep":         ("1.70.0", "pip install semgrep==1.70.0"),
    "litellm":         ("1.40.0", "pip install litellm==1.40.0"),
    "python-nmap":     ("0.7.1",  "pip install python-nmap==0.7.1"),
    "python-json-logger": ("2.0.0", "pip install python-json-logger==2.0.0"),
    "pydantic":        ("2.0.0",  "pip install pydantic>=2.0.0"),
    "pydantic-settings": ("2.0.0", "pip install pydantic-settings>=2.0.0"),
    "PyYAML":          ("6.0.0",  "pip install PyYAML>=6.0.0"),
    "SQLAlchemy":      ("2.0.0",  "pip install SQLAlchemy>=2.0.0"),
    "httpx":           ("0.24.0", "pip install httpx[asyncio]>=0.24.0"),
}

def check_all() -> DependencyReport:
    """
    Check all required dependencies and return a report.
    """
    issues = []
    install_commands = []
    
    for pkg, (min_ver, install_cmd) in REQUIRED.items():
        try:
            # Check version
            ver = importlib.metadata.version(pkg)
            if ver < min_ver:
                issues.append(f"Package {pkg} version {ver} is below minimum {min_ver}.")
                install_commands.append(install_cmd)
        except importlib.metadata.PackageNotFoundError:
            # Try to find via binary if not found as python package
            if pkg == "certipy-ad" and shutil.which("certipy"):
                # Check version via subprocess
                try:
                    result = subprocess.run(["certipy", "--version"], capture_output=True, text=True)
                    if min_ver not in result.stdout:
                        issues.append(f"Binary certipy version mismatch. Required: {min_ver}")
                        install_commands.append(install_cmd)
                except Exception:
                    issues.append(f"Package {pkg} not found.")
                    install_commands.append(install_cmd)
            elif pkg == "playwright" and shutil.which("playwright"):
                # Check for chromium
                try:
                    from playwright.sync_api import sync_playwright
                    with sync_playwright() as p:
                        if not p.chromium.executable_path:
                            issues.append("Playwright chromium not installed.")
                            install_commands.append("python -m playwright install chromium")
                except Exception:
                    issues.append(f"Package {pkg} not found.")
                    install_commands.append(install_cmd)
            else:
                issues.append(f"Package {pkg} not found.")
                install_commands.append(install_cmd)

    # Impacket specific checks (often breaks between patch versions)
    if "impacket" not in [i.split()[1] for i in issues if "Package" in i]:
        try:
            import impacket.smbconnection
            import impacket.krb5
            import impacket.ldap
            import impacket.examples.utils
            import impacket.dcerpc.v5
        except ImportError as e:
            issues.append(f"Impacket installation is broken: {e}")
            install_commands.append("pip install --force-reinstall impacket==0.12.0")

    all_ok = len(issues) == 0
    return DependencyReport(all_ok, issues, install_commands)

def run_checks_and_exit_if_failed():
    """Run all checks and exit if any issues found."""
    report = check_all()
    if not report.all_ok:
        print("\n[!] FATAL: Dependency issues found.")
        print("-" * 40)
        for issue in report.issues:
            print(f"[-] {issue}")
        print("\n[+] To fix, run these commands:")
        print("-" * 40)
        for cmd in report.install_commands:
            print(f"    {cmd}")
        print("-" * 40)
        sys.exit(1)

__all__ = ["check_all", "run_checks_and_exit_if_failed"]
