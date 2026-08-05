"""Tests for secret masking — a privacy guarantee, so it is tested directly."""

from __future__ import annotations

from isahat.core.sanitize import format_headers, mask_headers, mask_value, truncate


def test_mask_bearer_token():
    masked = mask_value("Authorization: Bearer abc.def.ghi")
    assert "abc.def.ghi" not in masked
    assert "REDACTED" in masked


def test_mask_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepart"
    assert jwt not in mask_value(f"token={jwt}")


def test_mask_key_value_secret():
    masked = mask_value('{"password": "hunter2", "user": "bob"}')
    assert "hunter2" not in masked
    assert "bob" in masked  # non-secret data preserved


def test_mask_headers_redacts_sensitive():
    headers = {"Authorization": "Bearer xyz", "Cookie": "s=1", "Accept": "text/html"}
    masked = mask_headers(headers)
    assert masked["Authorization"] == "***REDACTED***"
    assert masked["Cookie"] == "***REDACTED***"
    assert masked["Accept"] == "text/html"


def test_format_headers_is_string():
    out = format_headers({"Accept": "text/html", "Authorization": "Bearer x"})
    assert "Accept: text/html" in out
    assert "Bearer x" not in out


def test_truncate():
    assert truncate("abc", 10) == "abc"
    long = "x" * 50
    result = truncate(long, 10)
    assert result.startswith("x" * 10)
    assert "truncated" in result
