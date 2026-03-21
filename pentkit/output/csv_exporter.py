from __future__ import annotations
import csv
import os
import json
import hashlib
import logging
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from pentkit.core.session import Session
    from pentkit.core.models import FindingModel

logger = logging.getLogger(__name__)

COLUMNS = [
    # METADATA COLUMNS
    "export_ts", "session_id", "session_name", "operator", "scope",
    # FINDING IDENTITY
    "finding_id", "finding_ts", "module", "sub_check", "source",
    # TARGET COLUMNS
    "target_url", "target_host", "target_ip", "target_port", "target_path",
    "target_param", "injection_point", "http_method", "content_type",
    # FINDING DETAIL
    "title", "description", "severity", "confidence", "verified",
    "false_positive_risk", "cvss_vector", "cvss_score", "cvss_av", "cvss_ac",
    "cvss_pr", "cvss_ui", "cvss_scope", "cvss_c", "cvss_i", "cvss_a",
    "cwe_ids", "cve_ids", "owasp_category", "mitre_technique", "tags",
    # CONTEXT DETECTION
    "detected_db_engine", "orm_detected", "encoding_layers", "reflection_type",
    "waf_vendor", "waf_confidence", "waf_bypass_achieved", "waf_bypass_mutation",
    "waf_iterations_to_bypass",
    # PAYLOAD AND EVIDENCE
    "payload_raw", "payload_encoded", "payload_id", "payload_effectiveness_score",
    "request_method", "request_url", "request_headers", "request_body",
    "response_code", "response_headers", "response_body_snippet", "response_body_hash",
    "response_time_ms", "baseline_response_ms", "timing_delta_ms",
    "oob_callback_received", "oob_callback_ts", "oob_callback_protocol",
    "oob_callback_source_ip", "oob_data_exfiltrated", "screenshot_path", "pcap_path",
    # AI ANALYSIS
    "ai_technical_explanation", "ai_business_impact", "ai_remediation_steps",
    "ai_false_positive_reasoning", "ai_chain_ids", "ai_confidence_score",
    "ai_cvss_justification", "ai_references",
    # ANALYTICS
    "corpus_success_count", "corpus_failure_count", "engagement_payload_rank"
]

class CSVExporter:
    """
    Standalone CSV exporter for web findings.
    Implements strictly defined schema and formatting rules.
    """

    def __init__(self, session: Session, output_dir: Optional[str] = None):
        self.session = session
        self.cfg = session.cfg
        self.lock = asyncio.Lock()
        
        # Filename format: pentkit_{session_name_slug}_{YYYYMMDD_HHMMSS}_web_findings.csv
        session_name_slug = "".join(c if c.isalnum() else "_" for c in self.cfg.engagement.name.lower()).replace("__", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = f"pentkit_{session_name_slug}_{timestamp}_web_findings.csv"
        
        # Output directory from config
        base_report_dir = Path(os.path.expanduser(output_dir or self.cfg.output.report_dir))
        base_report_dir.mkdir(parents=True, exist_ok=True)
        self.csv_path = base_report_dir / self.filename
        
        # Evidence vault copy
        evidence_export_dir = Path(os.path.expanduser(self.cfg.output.evidence_dir)) / self.session.id / "exports"
        evidence_export_dir.mkdir(parents=True, exist_ok=True)
        self.vault_csv_path = evidence_export_dir / self.filename

        self._initialized = False

    async def _init_csv(self):
        """Write the header row if the file is new."""
        async with self.lock:
            if not self.csv_path.exists():
                with open(self.csv_path, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=COLUMNS, quoting=csv.QUOTE_ALL)
                    writer.writeheader()
            self._initialized = True

    def _format_value(self, val: Any) -> str:
        """Apply formatting rules (newlines, booleans, lists, nulls)."""
        if val is None:
            return ""
        if isinstance(val, bool):
            return "true" if val else "false"
        if isinstance(val, (list, set, tuple)):
            # Escape pipe if it exists in values
            escaped_vals = [str(v).replace("|", r"\|") for v in val]
            return "|".join(escaped_vals)
        
        # Handle newlines
        s_val = str(val)
        s_val = s_val.replace("\r\n", "⏎").replace("\n", "⏎").replace("\r", "⏎")
        return s_val

    def _extract_cvss(self, vector: Optional[str]) -> Dict[str, str]:
        """Extract CVSS v3.1 metrics from vector string."""
        metrics = {f"cvss_{m}": "" for m in ["av", "ac", "pr", "ui", "scope", "c", "i", "a"]}
        if not vector or not vector.startswith("CVSS:3.1"):
            return metrics
        
        parts = vector.split("/")
        mapping = {
            "AV": "cvss_av", "AC": "cvss_ac", "PR": "cvss_pr",
            "UI": "cvss_ui", "S": "cvss_scope", "C": "cvss_c",
            "I": "cvss_i", "A": "cvss_a"
        }
        for part in parts:
            if ":" in part:
                k, v = part.split(":", 1)
                if k in mapping:
                    metrics[mapping[k]] = v
        return metrics

    async def write_row(self, finding: FindingModel, extra_data: Optional[Dict[str, Any]] = None):
        """Write a single finding row to the CSV."""
        if not self._initialized:
            await self._init_csv()

        extra = extra_data or {}
        # If finding has a 'details' attribute (added via migration/update), use it
        if hasattr(finding, 'details') and finding.details:
            extra.update(finding.details)

        # Build row dictionary
        row = {c: "" for c in COLUMNS}
        
        # 1. METADATA
        row["export_ts"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        row["session_id"] = self.session.id
        row["session_name"] = self.cfg.engagement.name
        row["operator"] = self.cfg.engagement.operator
        row["scope"] = "|".join(self.cfg.scope.domains + self.cfg.scope.ips + self.cfg.scope.cidrs)

        # 2. FINDING IDENTITY
        row["finding_id"] = finding.id
        row["finding_ts"] = finding.ts.strftime("%Y-%m-%dT%H:%M:%SZ") if finding.ts else ""
        row["module"] = finding.module
        row["sub_check"] = extra.get("sub_check", "")
        row["source"] = finding.source

        # 3. TARGET COLUMNS
        row["target_url"] = finding.target
        from urllib.parse import urlparse
        parsed = urlparse(finding.target)
        row["target_host"] = parsed.hostname or ""
        row["target_ip"] = extra.get("target_ip", "")
        row["target_port"] = str(parsed.port) if parsed.port else ("443" if parsed.scheme == "https" else "80")
        row["target_path"] = parsed.path or "/"
        row["target_param"] = extra.get("target_param", "")
        row["injection_point"] = extra.get("injection_point", "")
        row["http_method"] = extra.get("http_method", "GET")
        row["content_type"] = extra.get("content_type", "")

        # 4. FINDING DETAIL
        row["title"] = finding.title
        row["description"] = finding.description
        row["severity"] = finding.severity
        row["confidence"] = finding.confidence
        row["verified"] = extra.get("verified", "")
        row["false_positive_risk"] = str(extra.get("false_positive_risk", ""))
        row["cvss_vector"] = finding.cvss_vector or ""
        row["cvss_score"] = str(finding.cvss_score) if finding.cvss_score else ""
        row.update(self._extract_cvss(finding.cvss_vector))
        row["cwe_ids"] = extra.get("cwe_ids", [])
        row["cve_ids"] = finding.cve_ids or []
        row["owasp_category"] = extra.get("owasp_category", "")
        row["mitre_technique"] = extra.get("mitre_technique", "")
        row["tags"] = finding.tags or []

        # 5. CONTEXT DETECTION
        row["detected_db_engine"] = extra.get("detected_db_engine", "")
        row["orm_detected"] = extra.get("orm_detected", False)
        row["encoding_layers"] = extra.get("encoding_layers", [])
        row["reflection_type"] = extra.get("reflection_type", "")
        row["waf_vendor"] = extra.get("waf_vendor", "")
        row["waf_confidence"] = str(extra.get("waf_confidence", ""))
        row["waf_bypass_achieved"] = extra.get("waf_bypass_achieved", "")
        row["waf_bypass_mutation"] = extra.get("waf_bypass_mutation", "")
        row["waf_iterations_to_bypass"] = str(extra.get("waf_iterations_to_bypass", ""))

        # 6. PAYLOAD AND EVIDENCE
        row["payload_raw"] = extra.get("payload_raw", finding.payload or "")
        row["payload_encoded"] = finding.payload or ""
        row["payload_id"] = extra.get("payload_id", "")
        row["payload_effectiveness_score"] = str(extra.get("payload_effectiveness_score", ""))
        row["request_method"] = row["http_method"]
        row["request_url"] = finding.target # Simplified
        row["request_headers"] = finding.request or "" # Assuming stored as JSON string
        row["request_body"] = extra.get("request_body", "")
        row["response_code"] = str(extra.get("response_code", ""))
        row["response_headers"] = extra.get("response_headers", "")
        # Response body snippet (capped at 2000)
        resp_body = finding.response or ""
        row["response_body_snippet"] = resp_body[:2000]
        row["response_body_hash"] = hashlib.sha256(resp_body.encode()).hexdigest() if resp_body else ""
        row["response_time_ms"] = str(extra.get("response_time_ms", ""))
        row["baseline_response_ms"] = str(extra.get("baseline_response_ms", ""))
        # timing_delta_ms
        try:
            row["timing_delta_ms"] = str(float(row["response_time_ms"]) - float(row["baseline_response_ms"]))
        except (ValueError, TypeError):
            row["timing_delta_ms"] = ""
            
        row["oob_callback_received"] = extra.get("oob_callback_received", "")
        row["oob_callback_ts"] = extra.get("oob_callback_ts", "")
        row["oob_callback_protocol"] = extra.get("oob_callback_protocol", "")
        row["oob_callback_source_ip"] = extra.get("oob_callback_source_ip", "")
        row["oob_data_exfiltrated"] = extra.get("oob_data_exfiltrated", "")
        row["screenshot_path"] = finding.screenshot_path or ""
        row["pcap_path"] = finding.pcap_path or ""

        # 7. AI ANALYSIS
        row["ai_technical_explanation"] = finding.ai_explanation or ""
        row["ai_business_impact"] = extra.get("ai_business_impact", "")
        row["ai_remediation_steps"] = finding.ai_remediation or ""
        row["ai_false_positive_reasoning"] = extra.get("ai_false_positive_reasoning", "")
        row["ai_chain_ids"] = extra.get("ai_chain_ids", [])
        row["ai_confidence_score"] = str(extra.get("ai_confidence_score", ""))
        row["ai_cvss_justification"] = extra.get("ai_cvss_justification", "")
        row["ai_references"] = extra.get("ai_references", [])

        # 8. ANALYTICS
        row["corpus_success_count"] = str(extra.get("corpus_success_count", ""))
        row["corpus_failure_count"] = str(extra.get("corpus_failure_count", ""))
        row["engagement_payload_rank"] = str(extra.get("engagement_payload_rank", ""))

        # Apply formatting to all fields
        formatted_row = {k: self._format_value(v) for k, v in row.items()}

        # Validation
        if len(formatted_row) != len(COLUMNS):
            logger.error(f"Row column mismatch for finding {finding.id}: expected {len(COLUMNS)}, got {len(formatted_row)}")
        if not formatted_row.get("finding_id"):
            logger.error(f"Empty finding_id for row in module {finding.module}")
        for k, v in formatted_row.items():
            if "\n" in v or "\r" in v:
                logger.error(f"Raw newline detected in column {k} for finding {finding.id}")

        # Atomic write
        async with self.lock:
            for path in [self.csv_path, self.vault_csv_path]:
                with open(path, "a", encoding="utf-8-sig", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=COLUMNS, quoting=csv.QUOTE_ALL)
                    writer.writerow(formatted_row)

    async def write_summary(self):
        """Append the final summary row."""
        # Query all web findings from DB
        from pentkit.core.models import FindingModel
        findings = self.session.db_session.query(FindingModel).filter(FindingModel.module.like("web.%")).all()
        
        if not findings:
            return

        row = {c: "" for c in COLUMNS}
        row["finding_id"] = "SUMMARY"
        
        # severity column: total_critical=N, total_high=N, total_medium=N, total_low=N, total_info=N
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        cvss_scores = []
        for f in findings:
            counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
            if f.cvss_score:
                cvss_scores.append(f.cvss_score)
        
        row["severity"] = ", ".join([f"total_{k}={v}" for k, v in counts.items()])
        
        # verified column: verified_count=N, unverified_count=N
        # (Assuming 'verified' is in details or we track it elsewhere)
        # For now, placeholder counts
        row["verified"] = "verified_count=0, unverified_count=0"
        
        # cvss_score: mean CVSS score
        if cvss_scores:
            row["cvss_score"] = str(sum(cvss_scores) / len(cvss_scores))
            
        # All other columns empty string
        formatted_row = {k: self._format_value(v) for k, v in row.items()}
        
        async with self.lock:
            for path in [self.csv_path, self.vault_csv_path]:
                with open(path, "a", encoding="utf-8-sig", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=COLUMNS, quoting=csv.QUOTE_ALL)
                    writer.writerow(formatted_row)

    @classmethod
    async def export_all(cls, session: Session):
        """Regenerate the full CSV from session DB."""
        exporter = cls(session)
        await exporter._init_csv()
        
        from pentkit.core.models import FindingModel
        findings = session.db_session.query(FindingModel).filter(FindingModel.module.like("web.%")).all()
        
        for f in findings:
            await exporter.write_row(f)
        
        await exporter.write_summary()
        return exporter.csv_path
