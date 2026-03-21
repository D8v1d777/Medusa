from __future__ import annotations
import yaml
import pytest
from pentkit.core.config import Config

def test_config_load(tmp_path):
    config_data = {
        "engagement": {
            "name": "Test Engagement",
            "operator": "Tester",
            "authorized": True
        },
        "scope": {
            "ips": ["1.1.1.1"],
            "domains": ["example.com"],
            "cidrs": ["10.0.0.0/24"]
        },
        "rates": {
            "web": 10,
            "network": 5,
            "redteam": 1
        },
        "ai": {
            "provider": "openai",
            "model": "gpt-4o",
            "api_key_env": "TEST_KEY",
            "max_tokens": 1000,
            "temperature": 0.5
        },
        "output": {
            "evidence_dir": "/tmp/evidence",
            "log_dir": "/tmp/logs",
            "report_dir": "/tmp/reports"
        },
        "database_url": "sqlite:///:memory:"
    }
    
    cfg_file = tmp_path / "config.yaml"
    with open(cfg_file, "w") as f:
        yaml.dump(config_data, f)
        
    cfg = Config.load(cfg_file)
    assert cfg.engagement.name == "Test Engagement"
    assert cfg.engagement.authorized is True
    assert "1.1.1.1" in cfg.scope.ips
    assert cfg.rates.web == 10.0
    assert cfg.ai.model == "gpt-4o"
    assert cfg.output.evidence_dir == "/tmp/evidence"
