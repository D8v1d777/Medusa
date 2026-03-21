from __future__ import annotations
import pytest
from pentkit.core.scope_guard import ScopeGuard, OutOfScopeError

def test_scope_guard_ips():
    guard = ScopeGuard(ips=["192.168.1.1"], domains=[], cidrs=[])
    assert guard.is_safe("192.168.1.1") is True
    assert guard.is_safe("192.168.1.2") is False
    assert guard.is_safe("http://192.168.1.1/admin") is True

def test_scope_guard_cidrs():
    guard = ScopeGuard(ips=[], domains=[], cidrs=["10.0.0.0/24"])
    assert guard.is_safe("10.0.0.50") is True
    assert guard.is_safe("10.0.1.50") is False

def test_scope_guard_domains():
    guard = ScopeGuard(ips=[], domains=["target.com"], cidrs=[])
    assert guard.is_safe("target.com") is True
    assert guard.is_safe("api.target.com") is True
    assert guard.is_safe("other.com") is False
    assert guard.is_safe("nottarget.com") is False

def test_scope_guard_check_raises():
    guard = ScopeGuard(ips=["1.1.1.1"], domains=[], cidrs=[])
    guard.check("1.1.1.1") # Should not raise
    with pytest.raises(OutOfScopeError):
        guard.check("2.2.2.2")
