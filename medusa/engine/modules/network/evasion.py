"""Scan evasion modifiers."""
from __future__ import annotations


__all__ = ["EvasionModifiers"]

EVASION_FLAGS = {
    "fragment": "-f",
    "decoy": "-D RND:10",
    "ttl": "ttl_manipulation",
    "timing": "-T1",
    "source-port": "--source-port 53",
    "randomize": "--randomize-hosts",
}


class EvasionModifiers:
    """Apply evasion flags to nmap/scapy."""

    def __init__(self, flags: list[str] | None = None) -> None:
        self.flags = flags or []

    def nmap_args(self) -> str:
        """Return nmap evasion arguments."""
        return " ".join(
            EVASION_FLAGS.get(f, "")
            for f in self.flags
            if f in EVASION_FLAGS and EVASION_FLAGS[f].startswith("-")
        )
