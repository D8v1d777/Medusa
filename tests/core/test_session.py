from __future__ import annotations
import pytest
from pentkit.core.session import Session
from pentkit.core.config import Config, EngagementConfig, ScopeConfig

@pytest.fixture
def mock_cfg():
    return Config(
        engagement=EngagementConfig(name="Test", operator="Tester", authorized=True),
        scope=ScopeConfig(ips=["1.1.1.1"]),
        database_url="sqlite:///:memory:"
    )

def test_session_create(mock_cfg):
    session = Session(mock_cfg)
    assert session.model.name == "Test"
    assert session.model.status == "active"
    assert session.id is not None
    session.close()

def test_session_add_finding(mock_cfg):
    session = Session(mock_cfg)
    finding = session.add_finding(
        module="test",
        target="1.1.1.1",
        title="Test Finding",
        description="A test finding",
        severity="high"
    )
    assert finding.title == "Test Finding"
    assert finding.session_id == session.id
    
    # Check persistence
    assert len(session.model.findings) == 1
    session.close()

def test_session_token_usage(mock_cfg):
    session = Session(mock_cfg)
    session.update_token_usage(500)
    assert session.model.ai_token_usage == 500.0
    session.close()
