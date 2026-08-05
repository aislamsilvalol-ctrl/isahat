"""Tests for configuration loading and validation."""

from __future__ import annotations

import pytest

from isahat.core.config import ScanConfig, find_default_config, load_config


def test_defaults_are_safe():
    config = ScanConfig()
    assert config.scan.profile == "safe"
    assert config.safety.destructive_tests is False
    assert config.safety.require_scope_confirmation is True
    assert config.safety.rate_limit == 3.0


def test_load_none_returns_defaults():
    assert load_config(None).scan.profile == "safe"


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope.yml")


def test_load_yaml(tmp_path):
    path = tmp_path / "isahat.yml"
    path.write_text(
        """
project:
  name: demo
target:
  url: https://example.com
  allowed_hosts:
    - example.com
    - api.example.com
scan:
  profile: safe
  concurrency: 7
scope:
  include:
    - /api/*
  exclude:
    - /logout
safety:
  rate_limit: 2
        """,
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.project.name == "demo"
    assert config.scan.concurrency == 7
    assert "api.example.com" in config.target.allowed_hosts
    assert config.scope.exclude == ["/logout"]
    assert config.safety.rate_limit == 2


def test_invalid_concurrency_rejected(tmp_path):
    path = tmp_path / "isahat.yml"
    path.write_text("scan:\n  concurrency: 0\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(path)


def test_non_mapping_root_rejected(tmp_path):
    path = tmp_path / "isahat.yml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(path)


def test_find_default_config(tmp_path):
    assert find_default_config(tmp_path) is None
    (tmp_path / "isahat.yml").write_text("project:\n  name: x\n", encoding="utf-8")
    found = find_default_config(tmp_path)
    assert found is not None and found.name == "isahat.yml"
