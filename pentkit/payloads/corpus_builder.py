from __future__ import annotations
import httpx
import hashlib
import sqlite3
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class Payload:
    id: str
    payload: str
    injection_type: str
    source: str
    effectiveness_score: float = 0.5
    last_used: Optional[str] = None
    success_count: int = 0
    failure_count: int = 0
    waf_blocked_by: str = ""

@dataclass
class CorpusStats:
    total_payloads: int
    new_payloads: int
    updated_at: str

SOURCES = {
    "payloads_all_things": {
        "base_url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master",
        "paths": {
            "sqli":   "SQL Injection/Intruder/",
            "xss":    "XSS Injection/Intruder/",
            "xxe":    "XXE Injection/Payloads/",
            "ssrf":   "Server Side Request Forgery/Payloads/",
            "ssti":   "Server Side Template Injection/Payloads/",
            "lfi":    "File Inclusion/Intruder/",
            "open_redirect": "Open Redirect/Payloads/",
            "jwt":    "JSON Web Token/Payloads/",
        }
    },
    "seclists": {
        "base_url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master",
        "paths": {
            "xss_polyglot":  "Fuzzing/Polyglots/XSS-Polyglots.txt",
            "sqli_bypass":   "Fuzzing/SQLi/Generic-SQLi.txt",
            "sqli_auth":     "Fuzzing/SQLi/Auth-Bypass.txt",
            "jwt_secrets":   "Passwords/scraped-JWT-secrets.txt",
            "api_endpoints": "Discovery/Web-Content/api/api-endpoints.txt",
        }
    },
    "fuzzdb": {
        "base_url": "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master",
        "paths": {
            "sqli_detect":  "attack/sql-injection/detect/",
            "xss_detect":   "attack/xss/",
            "xxe":          "attack/xml/",
        }
    }
}

class CorpusBuilder:
    def __init__(self, db_path: Path = Path("pentkit/payloads/corpus.db")):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS corpus (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                injection_type TEXT NOT NULL,
                source TEXT NOT NULL,
                effectiveness_score REAL DEFAULT 0.5,
                last_used TEXT,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                waf_blocked_by TEXT DEFAULT ""
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_type ON corpus(injection_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_score ON corpus(effectiveness_score)")
        conn.commit()
        conn.close()

    async def build(self) -> CorpusStats:
        """Download and index payloads from authoritative sources."""
        total_before = self._get_total_count()
        new_count = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            for source_name, config in SOURCES.items():
                base_url = config["base_url"]
                for category, path in config["paths"].items():
                    logger.info(f"Ingesting {source_name}/{category} from {path}")
                    
                    # If path ends with .txt, it's a direct file
                    if path.endswith(".txt"):
                        urls = [f"{base_url}/{path}"]
                    else:
                        # It's a directory, we'd normally need to scrape or have a file list.
                        # For this implementation, we'll assume a set of common files if it's a directory.
                        # In a real tool, we might use GitHub API to list files.
                        # For now, let's just handle the direct files specified.
                        urls = [f"{base_url}/{path}"] if "/" in path else []

                    for url in urls:
                        try:
                            response = await client.get(url)
                            if response.status_code == 200:
                                payloads = self._parse_payloads(response.text)
                                for p in payloads:
                                    if self._add_payload(p, category, source_name):
                                        new_count += 1
                        except Exception as e:
                            logger.error(f"Failed to download {url}: {e}")

        total_after = self._get_total_count()
        self._export_to_yaml()
        
        return CorpusStats(
            total_payloads=total_after,
            new_payloads=new_count,
            updated_at=datetime.now().isoformat()
        )

    def _parse_payloads(self, text: str) -> List[str]:
        lines = text.splitlines()
        payloads = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                payloads.append(line)
        return payloads

    def _add_payload(self, payload: str, injection_type: str, source: str) -> bool:
        p_hash = hashlib.sha256(payload.encode()).hexdigest()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO corpus 
                (id, payload, injection_type, source, effectiveness_score)
                VALUES (?, ?, ?, ?, ?)
            """, (p_hash, payload, injection_type, source, 0.5))
            affected = cursor.rowcount
            conn.commit()
            return affected > 0
        finally:
            conn.close()

    def _get_total_count(self) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM corpus")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def _export_to_yaml(self):
        """Export to YAML per category for backward compatibility."""
        output_dir = Path("pentkit/payloads/web")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT injection_type FROM corpus")
        categories = [row[0] for row in cursor.fetchall()]
        
        for cat in categories:
            cursor.execute("SELECT payload FROM corpus WHERE injection_type = ?", (cat,))
            payloads = [row[0] for row in cursor.fetchall()]
            
            with open(output_dir / f"{cat}.yaml", "w") as f:
                yaml.dump({"payloads": payloads}, f)
        
        conn.close()

    def get_payloads(
        self,
        injection_type: str,
        waf_vendor: str | None = None,
        max_count: int = 200,
        min_effectiveness: float = 0.3,
    ) -> List[Payload]:
        """Query corpus DB for the best payloads."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT * FROM corpus 
            WHERE injection_type = ? 
            AND effectiveness_score >= ?
        """
        params: List[Any] = [injection_type, min_effectiveness]
        
        if waf_vendor:
            query += " AND waf_blocked_by NOT LIKE ?"
            params.append(f"%{waf_vendor}%")
            
        query += " ORDER BY effectiveness_score DESC, success_count DESC LIMIT ?"
        params.append(max_count)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return [Payload(**dict(row)) for row in rows]

    def update_effectiveness(self, payload_id: str, delta: float):
        """Update effectiveness score based on feedback."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE corpus 
            SET effectiveness_score = MIN(1.0, MAX(0.0, effectiveness_score + ?))
            WHERE id = ?
        """, (delta, payload_id))
        conn.commit()
        conn.close()

    def record_block(self, payload_id: str, waf_vendor: str):
        """Record that a payload was blocked by a specific WAF."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Append waf_vendor to blocked list if not already there
        cursor.execute("SELECT waf_blocked_by FROM corpus WHERE id = ?", (payload_id,))
        row = cursor.fetchone()
        if row:
            blocked = row[0].split(",") if row[0] else []
            if waf_vendor not in blocked:
                blocked.append(waf_vendor)
                new_blocked = ",".join(filter(None, blocked))
                cursor.execute("""
                    UPDATE corpus 
                    SET waf_blocked_by = ?, failure_count = failure_count + 1
                    WHERE id = ?
                """, (new_blocked, payload_id))
        conn.commit()
        conn.close()

    def record_success(self, payload_id: str):
        """Record that a payload successfully bypassed security."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE corpus 
            SET success_count = success_count + 1, last_used = ?
            WHERE id = ?
        """, (datetime.now().isoformat(), payload_id))
        conn.commit()
        conn.close()
