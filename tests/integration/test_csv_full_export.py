from __future__ import annotations
import csv
import os
import pytest
import asyncio
from pathlib import Path
from pentkit.core.session import Session
from pentkit.core.config import Config, EngagementConfig, ScopeConfig, OutputConfig
from pentkit.core.models import FindingModel

@pytest.fixture
def real_session(tmp_path):
    db_path = tmp_path / "pentkit_test.db"
    cfg = Config(
        engagement=EngagementConfig(name="Integration Test", operator="Tester", authorized=True),
        scope=ScopeConfig(domains=["dvwa.local"]),
        output=OutputConfig(
            report_dir=str(tmp_path / "reports"),
            evidence_dir=str(tmp_path / "evidence")
        ),
        database_url=f"sqlite:///{db_path}"
    )
    session = Session(cfg)
    yield session
    session.close()

@pytest.mark.asyncio
async def test_csv_full_integration(real_session, tmp_path):
    # Simulate adding multiple findings from different modules
    findings_data = [
        {
            "module": "web.injectors",
            "target": "http://dvwa.local/vulnerabilities/sqli/",
            "title": "SQL Injection",
            "description": "Error-based SQLi detected",
            "severity": "high",
            "details": {"detected_db_engine": "mysql", "sub_check": "sqli_error_based"}
        },
        {
            "module": "web.auth_tester",
            "target": "http://dvwa.local/login.php",
            "title": "Weak Password",
            "description": "Admin/Admin is valid",
            "severity": "critical",
            "details": {"sub_check": "brute_force"}
        },
        {
            "module": "network.scanner", # Should NOT go into web CSV
            "target": "127.0.0.1",
            "title": "Open Port",
            "description": "Port 80 is open",
            "severity": "info"
        }
    ]
    
    for f_data in findings_data:
        real_session.add_finding(**f_data)
    
    # Wait for async tasks to complete
    await asyncio.sleep(1)
    
    # Finalize summary
    await real_session.csv_exporter.write_summary()
    
    csv_path = real_session.csv_exporter.csv_path
    assert csv_path.exists()
    
    # Verify content
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = list(csv.DictReader(f))
        
        # Should have 2 findings + 1 summary = 3 rows
        # (Finding 3 is network.scanner, so it's skipped by Session logic)
        assert len(reader) == 3
        
        # Verify first finding
        assert reader[0]["module"] == "web.injectors"
        assert reader[0]["detected_db_engine"] == "mysql"
        
        # Verify second finding
        assert reader[1]["module"] == "web.auth_tester"
        assert reader[1]["severity"] == "critical"
        
        # Verify summary row
        assert reader[2]["finding_id"] == "SUMMARY"
        assert "total_high=1" in reader[2]["severity"]
        assert "total_critical=1" in reader[2]["severity"]

@pytest.mark.asyncio
async def test_csv_export_all_command(real_session, tmp_path):
    # Add findings directly to DB to simulate an existing session
    real_session.add_finding(module="web.test", target="http://test.com", title="T1", description="D1", severity="low")
    await asyncio.sleep(0.5)
    
    # Use export_all to regenerate
    from pentkit.output.csv_exporter import CSVExporter
    new_csv_path = await CSVExporter.export_all(real_session)
    
    assert new_csv_path.exists()
    with open(new_csv_path, "r", encoding="utf-8-sig") as f:
        reader = list(csv.DictReader(f))
        assert any(r["finding_id"] == "SUMMARY" for r in reader)
        assert any(r["module"] == "web.test" for r in reader)
