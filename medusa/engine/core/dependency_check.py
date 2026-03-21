"""Dependency version checks at startup."""
from __future__ import annotations

import importlib.metadata
import shutil
import sys
from dataclasses import dataclass

__all__ = ["check_all", "run_checks_and_exit_if_failed", "DependencyReport"]

REQUIRED: dict[str, tuple[str, str]] = {
    "impacket": ("0.12.0", "pip install impacket>=0.12.0"),
    "scapy": ("2.5.0", "pip install scapy>=2.5.0"),
    "playwright": ("1.43.0", "pip install playwright>=1.43.0 && playwright install chromium"),
    "litellm": ("1.40.0", "pip install litellm>=1.40.0"),
    "python-nmap": ("0.7.1", "pip install python-nmap>=0.7.1"),
    "httpx": ("0.24.0", "pip install httpx[asyncio]>=0.24.0"),
    "pydantic": ("2.0.0", "pip install pydantic>=2.0.0"),
    "sqlalchemy": ("2.0.0", "pip install SQLAlchemy>=2.0.0"),
    "fastapi": ("0.100.0", "pip install fastapi>=0.100.0"),
    "uvicorn": ("0.22.0", "pip install uvicorn>=0.22.0"),
}


@dataclass
class DependencyReport:
    """Dependency check result."""

    all_ok: bool
    issues: list[str]
    install_commands: list[str]


def _version_cmp(a: str, b: str) -> int:
    """Compare version strings. Returns -1 if a < b, 0 if equal, 1 if a > b."""

    def parse(v: str) -> list[int]:
        parts = []
        for x in v.replace("-", ".").split(".")[:5]:
            if x.isdigit():
                parts.append(int(x))
            else:
                parts.append(0)
        return parts or [0]
    pa, pb = parse(a), parse(b)
    for i in range(max(len(pa), len(pb))):
        va = pa[i] if i < len(pa) else 0
        vb = pb[i] if i < len(pb) else 0
        if va < vb:
            return -1
        if va > vb:
            return 1
    return 0


def check_all() -> DependencyReport:
    """Check all required dependencies."""
    issues: list[str] = []
    install_commands: list[str] = []

    for pkg, (min_ver, install_cmd) in REQUIRED.items():
        pkg_import = pkg.replace("-", "_").lower()
        try:
            ver = importlib.metadata.version(pkg_import)
            if _version_cmp(ver, min_ver) < 0:
                issues.append(f"{pkg} {ver} < required {min_ver}")
                install_commands.append(install_cmd)
        except importlib.metadata.PackageNotFoundError:
            if pkg == "certipy-ad" and shutil.which("certipy"):
                continue
            issues.append(f"Package {pkg} not found")
            install_commands.append(install_cmd)

    if "impacket" not in [i.split()[1] for i in issues if "Package" in i]:
        try:
            import impacket.smbconnection  # noqa: F401
            import impacket.krb5  # noqa: F401
        except ImportError as e:
            issues.append(f"Impacket broken: {e}")
            install_commands.append("pip install --force-reinstall impacket>=0.12.0")

    return DependencyReport(
        all_ok=len(issues) == 0,
        issues=issues,
        install_commands=install_commands,
    )


def run_checks_and_exit_if_failed() -> None:
    """Run checks and exit if any issues found."""
    report = check_all()
    if not report.all_ok:
        print("\n[!] Dependency issues found:")
        for issue in report.issues:
            print(f"  - {issue}")
        print("\nFix with:")
        for cmd in report.install_commands:
            print(f"  {cmd}")
        sys.exit(1)
