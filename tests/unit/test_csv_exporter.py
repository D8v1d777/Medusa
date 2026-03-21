from __future__ import annotations
import csv
import os
import pytest
import asyncio
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from pentkit.output.csv_exporter import CSVExporter, COLUMNS
from pentkit.core.models import FindingModel
from pentkit.core.config import Config, EngagementConfig, ScopeConfig, OutputConfig

@pytest.fixture
def mock_session(tmp_path):
    # Mock Config
    cfg = Config(
        engagement=EngagementConfig(name="Test Engagement", operator="Tester", authorized=True),
        scope=ScopeConfig(domains=["example.com"]),
        output=OutputConfig(
            report_dir=str(tmp_path / "reports"),
            evidence_dir=str(tmp_path / "evidence")
        ),
        database_url="sqlite:///:memory:"
    )
    
    session = MagicMock()
    session.id = "test-session-uuid"
    session.cfg = cfg
    session.db_session = MagicMock()
    return session

@pytest.mark.asyncio
async def test_csv_exporter_column_count(mock_session, tmp_path):
    exporter = CSVExporter(mock_session, output_dir=str(tmp_path))
    
    finding = FindingModel(
        id="finding-1",
        ts=datetime.utcnow(),
        module="web.test",
        target="http://example.com/path?q=1",
        title="Test XSS",
        description="Line 1\nLine 2",
        severity="high",
        source="tool",
        tags=["tag1", "tag2"]
    )
    
    await exporter.write_row(finding)
    
    assert exporter.csv_path.exists()
    
    with open(exporter.csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader)
        row = next(reader)
        
        assert len(header) == len(COLUMNS)
        assert len(row) == len(COLUMNS)
        assert header == COLUMNS

@pytest.mark.asyncio
async def test_csv_exporter_formatting(mock_session, tmp_path):
    exporter = CSVExporter(mock_session, output_dir=str(tmp_path))
    
    finding = FindingModel(
        id="finding-fmt",
        ts=datetime.utcnow(),
        module="web.injectors",
        target="http://example.com/",
        title="Title with \"quotes\"",
        description="Multiline\nDescription\r\nWith CRLF",
        severity="critical",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        tags=["tag1", "tag2|pipe"]
    )
    
    await exporter.write_row(finding, extra_data={"verified": True, "detected_db_engine": "mysql"})
    
    with open(exporter.csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        row = next(reader)
        
        # Newlines replaced with ⏎
        assert "Multiline⏎Description⏎With CRLF" in row["description"]
        # Booleans are lowercase "true"
        assert row["verified"] == "true"
        # Lists use pipe | and escape existing pipes
        assert row["tags"] == "tag1|tag2\|pipe"
        # CVSS extracted
        assert row["cvss_av"] == "N"
        assert row["cvss_c"] == "H"
        assert row["cvss_score"] == "9.8"
        # DB engine from extra
        assert row["detected_db_engine"] == "mysql"

@pytest.mark.asyncio
async def test_csv_exporter_no_truncation(mock_session, tmp_path):
    exporter = CSVExporter(mock_session, output_dir=str(tmp_path))
    
    long_text = "A" * 5000
    finding = FindingModel(
        id="finding-long",
        module="web.test",
        target="http://example.com/",
        title="Long Finding",
        description=long_text,
        severity="info"
    )
    
    await exporter.write_row(finding)
    
    with open(exporter.csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        row = next(reader)
        assert len(row["description"]) == 5000
        assert row["description"] == long_text
