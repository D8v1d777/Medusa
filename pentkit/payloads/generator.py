import base64
import yaml
import random
from pathlib import Path
from typing import List, Dict, Optional

class PayloadEncoder:
    @staticmethod
    def url_encode(data: str) -> str:
        import urllib.parse
        return urllib.parse.quote(data)

    @staticmethod
    def base64_encode(data: str) -> str:
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def hex_encode(data: str) -> str:
        return data.encode().hex()

    @staticmethod
    def xor_encode(data: str, key: int = 0x41) -> str:
        return "".join(chr(ord(c) ^ key) for c in data)

class PayloadGenerator:
    def __init__(self, base_dir: str = "pentkit/payloads"):
        self.base_dir = Path(base_dir)
        self.encoder = PayloadEncoder()

    def load_payloads(self, category_path: str) -> List[str]:
        # category_path can be "web/sqli" or "network/snmp"
        path = self.base_dir / f"{category_path}.yaml"
        if not path.exists():
            return []
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
            # Find the list in the YAML - can be 'payloads' or 'communities' etc.
            # We'll just take the first list we find.
            for key, value in data.items():
                if isinstance(value, list):
                    return value
        return []

    def generate(self, category_path: str, encoding: Optional[str] = None) -> List[str]:
        payloads = self.load_payloads(category_path)
        if not encoding:
            return payloads
        
        encoded_payloads = []
        for p in payloads:
            if encoding == 'url':
                encoded_payloads.append(self.encoder.url_encode(p))
            elif encoding == 'base64':
                encoded_payloads.append(self.encoder.base64_encode(p))
            elif encoding == 'hex':
                encoded_payloads.append(self.encoder.hex_encode(p))
            else:
                encoded_payloads.append(p)
        return encoded_payloads

# Singleton instance
generator = PayloadGenerator()
