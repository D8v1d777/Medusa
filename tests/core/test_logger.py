from __future__ import annotations
import json
import logging
from pathlib import Path
import pytest
from pentkit.core.logger import setup_logger
from pentkit.core.config import Config, EngagementConfig, ScopeConfig, OutputConfig

def test_logger_json_output(tmp_path):
    # Setup test config with temp directories
    log_dir = tmp_path / "logs"
    cfg = Config(
        engagement=EngagementConfig(name="Test", operator="Tester", authorized=True),
        scope=ScopeConfig(),
        output=OutputConfig(log_dir=str(log_dir)),
        database_url="sqlite:///:memory:"
    )
    
    session_id = "test_session_123"
    logger = setup_logger(cfg, session_id=session_id, log_level="INFO")
    
    # Log a message with extra fields
    test_logger = logging.getLogger("pentkit.test")
    test_logger.info("Test message", extra={"pentkit_module": "test_mod", "target": "1.2.3.4"})
    
    # Check if the file exists
    log_file = log_dir / f"{session_id}.log"
    assert log_file.exists()
    
    # Verify JSON structure
    with open(log_file, "r") as f:
        line = f.readline()
        data = json.loads(line)
        
        assert data["message"] == "Test message"
        assert data["session_id"] == session_id
        assert data["pentkit_module"] == "test_mod"
        assert data["target"] == "1.2.3.4"
        assert data["level"] == "INFO"
        assert "timestamp" in data
