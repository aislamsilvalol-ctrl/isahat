"""Tests for auth.json loading and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from isahat.core.auth import AuthConfig, load_auth


def test_load_auth_reads_headers_and_cookies(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps({"headers": {"Authorization": "Bearer x"}, "cookies": {"session": "s"}}),
        encoding="utf-8",
    )
    auth = load_auth(path)
    assert auth.headers == {"Authorization": "Bearer x"}
    assert auth.cookies == {"session": "s"}
    assert not auth.is_empty()


def test_empty_auth_is_empty() -> None:
    assert AuthConfig().is_empty()


def test_load_auth_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_auth(tmp_path / "nope.json")


def test_load_auth_invalid_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_auth(path)


def test_load_auth_non_object_root_raises(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError):
        load_auth(path)
