"""Corpus builder — download and index payloads from authoritative sources."""
from __future__ import annotations

import hashlib
import sqlite3
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import httpx
import yaml

__all__ = ["CorpusBuilder", "CorpusStats", "Payload"]

logger = logging.getLogger(__name__)


@dataclass
class Payload:
    """Single payload from corpus."""

    id: str
    payload: str
    injection_type: str
    source: str
    effectiveness_score: float = 0.5
    last_used: str | None = None
    success_count: int = 0
    failure_count: int = 0
    waf_blocked_by: str = ""


@dataclass
class CorpusStats:
    """Corpus build statistics."""

    total_payloads: int
    new_payloads: int
    updated_at: str


SOURCES = {
    "payloads_all_things": {
        "base_url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master",
        "paths": {
            "sqli": "SQL Injection/Intruder/",
            "xss": "XSS Injection/Intruder/",
            "xxe": "XXE Injection/Payloads/",
            "ssrf": "Server Side Request Forgery/Payloads/",
            "ssti": "Server Side Template Injection/Payloads/",
            "lfi": "File Inclusion/Intruder/",
        },
    },
    "seclists": {
        "base_url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master",
        "paths": {
            "sqli_bypass": "Fuzzing/SQLi/Generic-SQLi.txt",
            "xss_polyglot": "Fuzzing/Polyglots/XSS-Polyglots.txt",
        },
    },
}


class CorpusBuilder:
    """Builds and maintains the payload corpus database."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or Path(__file__).parent / "corpus.db"
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
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
        conn.commit()
        conn.close()

    async def build(self, output_dir: Path | None = None) -> CorpusStats:
        """Download and index payloads from sources."""
        new_count = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            for source_name, config in SOURCES.items():
                base_url = config["base_url"]
                for category, path in config["paths"].items():
                    if path.endswith(".txt"):
                        urls = [f"{base_url}/{path}"]
                    else:
                        urls = []
                    for url in urls:
                        try:
                            response = await client.get(url)
                            if response.status_code == 200:
                                payloads = self._parse_payloads(response.text)
                                for p in payloads:
                                    if self._add_payload(p, category, source_name):
                                        new_count += 1
                        except Exception as e:
                            logger.error("Failed to download %s: %s", url, e)

        total_after = self._get_total_count()
        self._export_to_yaml(output_dir)

        return CorpusStats(
            total_payloads=total_after,
            new_payloads=new_count,
            updated_at=datetime.now().isoformat(),
        )

    def _parse_payloads(self, text: str) -> list[str]:
        return [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def _add_payload(self, payload: str, injection_type: str, source: str) -> bool:
        p_hash = hashlib.sha256(payload.encode()).hexdigest()
        conn = sqlite3.connect(str(self.db_path))
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR IGNORE INTO corpus
                (id, payload, injection_type, source, effectiveness_score)
                VALUES (?, ?, ?, ?, ?)
            """,
                (p_hash, payload, injection_type, source, 0.5),
            )
            affected = cursor.rowcount
            conn.commit()
            return affected > 0
        finally:
            conn.close()

    def _get_total_count(self) -> int:
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM corpus")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def _export_to_yaml(self, output_dir: Path | None = None) -> None:
        out = output_dir or Path(__file__).parent / "web"
        out.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT injection_type FROM corpus")
        for row in cursor.fetchall():
            cat = row[0]
            cursor.execute("SELECT payload FROM corpus WHERE injection_type = ?", (cat,))
            payloads = [r[0] for r in cursor.fetchall()]
            (out / f"{cat}.yaml").write_text(
                yaml.dump({"payloads": payloads}, default_flow_style=False)
            )
        conn.close()
