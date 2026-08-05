"""Scope policy is safety-critical, so it gets thorough coverage."""

from __future__ import annotations

import pytest

from isahat.core.config import ScanConfig
from isahat.core.scope import Scope, ScopeViolation


def make_scope(target="https://example.com", allowed=None, include=None, exclude=None) -> Scope:
    config = ScanConfig()
    if allowed:
        config.target.allowed_hosts = allowed
    if include:
        config.scope.include = include
    if exclude:
        config.scope.exclude = exclude
    return Scope.from_config(target, config)


def test_target_host_is_allowed_by_default():
    scope = make_scope()
    assert scope.allows("https://example.com/")
    assert scope.allows("https://example.com/dashboard")


def test_other_hosts_are_rejected():
    scope = make_scope()
    assert not scope.allows("https://evil.com/")
    assert not scope.allows("https://api.example.com/")  # not in allowed_hosts


def test_additional_allowed_hosts():
    scope = make_scope(allowed=["api.example.com"])
    assert scope.allows("https://api.example.com/v1")
    assert scope.allows("https://example.com/")


def test_non_http_schemes_rejected():
    scope = make_scope()
    assert not scope.allows("ftp://example.com/")
    assert not scope.allows("file:///etc/passwd")


def test_exclude_beats_include():
    scope = make_scope(include=["/api/*"], exclude=["/api/secret"])
    assert scope.allows("https://example.com/api/users")
    assert not scope.allows("https://example.com/api/secret")


def test_include_restricts_paths():
    scope = make_scope(include=["/api/*"])
    assert scope.allows("https://example.com/api/users")
    assert not scope.allows("https://example.com/dashboard")


def test_require_raises_on_violation():
    scope = make_scope()
    with pytest.raises(ScopeViolation):
        scope.require("https://evil.com/")


def test_cannot_derive_host_from_bare_target():
    config = ScanConfig()
    with pytest.raises(ScopeViolation):
        Scope.from_config("not-a-url", config)


def test_scope_info_roundtrip():
    scope = make_scope(allowed=["api.example.com"], include=["/api/*"], exclude=["/logout"])
    info = scope.to_info()
    assert "example.com" in info.allowed_hosts
    assert "api.example.com" in info.allowed_hosts
    assert info.include == ["/api/*"]
    assert info.exclude == ["/logout"]
