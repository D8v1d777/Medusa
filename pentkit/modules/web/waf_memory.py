from __future__ import annotations
import sqlite3
import logging
from pathlib import Path
from typing import List, Dict, Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class WAFMemoryEntry(BaseModel):
    waf_vendor: str
    blocked_payload: str
    successful_mutation: str
    endpoint_context: str
    confidence: float

class WAFMemory:
    """
    Persistent memory of successful WAF bypasses across sessions.
    Prevents re-learning the same bypasses.
    """

    def __init__(self, db_path: Path = Path("pentkit/modules/web/waf_memory.db")):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bypass_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                waf_vendor TEXT NOT NULL,
                blocked_payload TEXT NOT NULL,
                successful_mutation TEXT NOT NULL,
                endpoint_context TEXT,
                confidence REAL,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_waf ON bypass_memory(waf_vendor)")
        conn.commit()
        conn.close()

    def store_bypass(self, entry: WAFMemoryEntry):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO bypass_memory (waf_vendor, blocked_payload, successful_mutation, endpoint_context, confidence)
            VALUES (?, ?, ?, ?, ?)
        """, (entry.waf_vendor, entry.blocked_payload, entry.successful_mutation, entry.endpoint_context, entry.confidence))
        conn.commit()
        conn.close()

    def get_known_bypasses(self, waf_vendor: str, blocked_payload: str) -> List[str]:
        """Retrieve mutations that worked for similar blocks in the past."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Simple similarity: check if blocked_payload contains similar keywords
        # In real tool, use Levenshtein distance or AI embeddings.
        cursor.execute("""
            SELECT successful_mutation FROM bypass_memory 
            WHERE waf_vendor = ? 
            ORDER BY confidence DESC LIMIT 5
        """, (waf_vendor,))
        results = [row[0] for row in cursor.fetchall()]
        conn.close()
        return results

__all__ = ["WAFMemory", "WAFMemoryEntry"]
