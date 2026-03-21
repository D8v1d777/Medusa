from __future__ import annotations
import sqlite3
import logging
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Literal, Any
from datetime import datetime
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class PayloadOutcome(BaseModel):
    payload_id: str
    injection_type: str
    tech_stack: List[str]
    waf_vendor: Optional[str]
    outcome: Literal["confirmed_finding", "false_positive", "blocked", "no_effect"]
    session_id: str

class EngagementAnalytics:
    """
    Records payload performance and provides data-driven recommendations.
    Implements Precision GAP 7.
    """

    def __init__(self, db_path: Path = Path("pentkit/payloads/analytics.db")):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_id TEXT NOT NULL,
                injection_type TEXT NOT NULL,
                tech_stack_hash TEXT NOT NULL,
                waf_vendor TEXT,
                outcome TEXT NOT NULL,
                session_id TEXT NOT NULL,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_payload ON analytics(payload_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tech_waf ON analytics(tech_stack_hash, waf_vendor)")
        conn.commit()
        conn.close()

    async def record_payload_outcome(self, outcome: PayloadOutcome):
        """Record what happened with a specific payload."""
        tech_hash = hashlib.sha256(",".join(sorted(outcome.tech_stack)).encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analytics (payload_id, injection_type, tech_stack_hash, waf_vendor, outcome, session_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (outcome.payload_id, outcome.injection_type, tech_hash, outcome.waf_vendor, outcome.outcome, outcome.session_id))
        conn.commit()
        conn.close()

        # Update effectiveness in corpus.db
        from pentkit.payloads.corpus_builder import CorpusBuilder
        corpus = CorpusBuilder()
        
        delta = 0.0
        if outcome.outcome == "confirmed_finding": delta = 0.15
        elif outcome.outcome == "false_positive": delta = -0.20
        elif outcome.outcome == "blocked": delta = -0.05
        elif outcome.outcome == "no_effect": delta = -0.02
        
        corpus.update_effectiveness(outcome.payload_id, delta)

    async def get_recommendations(
        self,
        tech_stack: List[str],
        waf_vendor: Optional[str],
        injection_type: str,
    ) -> Dict[str, Any]:
        """Query historical performance for recommendations."""
        tech_hash = hashlib.sha256(",".join(sorted(tech_stack)).encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get high performers for this tech/WAF combo
        cursor.execute("""
            SELECT payload_id, 
                   COUNT(*) FILTER (WHERE outcome = 'confirmed_finding') * 1.0 / COUNT(*) as success_rate
            FROM analytics
            WHERE tech_stack_hash = ? AND (waf_vendor = ? OR waf_vendor IS NULL)
            AND injection_type = ?
            GROUP BY payload_id
            HAVING success_rate > 0.5
            ORDER BY success_rate DESC
            LIMIT 10
        """, (tech_hash, waf_vendor, injection_type))
        
        recommendations = {
            "high_performers": [row[0] for row in cursor.fetchall()],
            "tech_stack": tech_stack,
            "waf_vendor": waf_vendor
        }
        
        conn.close()
        return recommendations

__all__ = ["EngagementAnalytics", "PayloadOutcome"]
