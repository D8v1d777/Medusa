from typing import Dict, List, Optional
import random

class EvasionEngine:
    def __init__(self, mode: Optional[str] = None):
        self.mode = mode

    def get_nmap_flags(self) -> str:
        """Get nmap flags based on evasion mode."""
        if not self.mode:
            return ""
        
        flags = []
        if self.mode == 'fragment':
            flags.append("-f")
        elif self.mode == 'decoy':
            # RND:10 decoy IPs
            flags.append("-D RND:10")
        elif self.mode == 'ttl':
            # Custom TTL (64)
            flags.append("--ttl 64")
        elif self.mode == 'timing':
            # T1 paranoid timing
            flags.append("-T1")
        
        return " ".join(flags)

    @staticmethod
    def get_scapy_ttl() -> int:
        """Get custom TTL for Scapy packets."""
        return random.randint(64, 128)
