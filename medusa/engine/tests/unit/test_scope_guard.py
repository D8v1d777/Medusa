"""Unit tests for scope_guard."""
import pytest

from medusa.engine.core.scope_guard import OutOfScopeError, ScopeGuard


def test_scope_guard_ip_allowed() -> None:
    guard = ScopeGuard(ips=["192.168.1.1"], domains=[], cidrs=[])
    assert guard.is_safe("192.168.1.1") is True
    assert guard.is_safe("http://192.168.1.1:80/") is True


def test_scope_guard_ip_blocked() -> None:
    guard = ScopeGuard(ips=["192.168.1.1"], domains=[], cidrs=[])
    assert guard.is_safe("192.168.1.2") is False


def test_scope_guard_cidr_allowed() -> None:
    guard = ScopeGuard(ips=[], domains=[], cidrs=["192.168.1.0/24"])
    assert guard.is_safe("192.168.1.100") is True


def test_scope_guard_domain_allowed() -> None:
    guard = ScopeGuard(ips=[], domains=["target.com"], cidrs=[])
    assert guard.is_safe("https://target.com/path") is True
    assert guard.is_safe("https://api.target.com/path") is True


def test_scope_guard_check_raises() -> None:
    guard = ScopeGuard(ips=[], domains=[], cidrs=[])
    with pytest.raises(OutOfScopeError) as exc:
        guard.check("https://evil.com", "web")
    assert "evil.com" in str(exc.value)
