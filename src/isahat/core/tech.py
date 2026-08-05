"""Passive technology fingerprinting from responses already fetched.

Detection is signature-based and non-intrusive: it only inspects headers,
cookies and HTML that the crawler already retrieved. No extra probing.
"""

from __future__ import annotations

import re

from isahat.core.http import HttpResponse
from isahat.core.models import Technology

# Header -> (technology name, category). Value may carry a version.
_HEADER_SIGNATURES: dict[str, tuple[str, str]] = {
    "x-powered-by": ("", "framework"),
    "server": ("", "server"),
    "x-aspnet-version": ("ASP.NET", "framework"),
    "x-aspnetmvc-version": ("ASP.NET MVC", "framework"),
    "x-drupal-cache": ("Drupal", "cms"),
    "x-generator": ("", "cms"),
}

# Cookie name -> (technology, category).
_COOKIE_SIGNATURES: dict[str, tuple[str, str]] = {
    "phpsessid": ("PHP", "language"),
    "laravel_session": ("Laravel", "framework"),
    "ci_session": ("CodeIgniter", "framework"),
    "connect.sid": ("Express", "framework"),
    "csrftoken": ("Django", "framework"),
    "sessionid": ("Django", "framework"),
    "jsessionid": ("Java", "language"),
    "asp.net_sessionid": ("ASP.NET", "framework"),
    "_shopify_y": ("Shopify", "platform"),
}

# Regexes applied to HTML bodies.
_HTML_SIGNATURES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I), "", "cms"),
    (re.compile(r"/_next/static/", re.I), "Next.js", "framework"),
    (re.compile(r"__NUXT__", re.I), "Nuxt.js", "framework"),
    (re.compile(r"data-reactroot|react(?:-dom)?\.production", re.I), "React", "frontend"),
    (re.compile(r"ng-version=", re.I), "Angular", "frontend"),
    (re.compile(r"wp-content/|wp-includes/", re.I), "WordPress", "cms"),
    (re.compile(r"cdn\.shopify\.com", re.I), "Shopify", "platform"),
]

_VERSION_RE = re.compile(r"([A-Za-z][\w.\-]*?)[/ ]?(\d+(?:\.\d+)+)")


def _split_name_version(raw: str) -> tuple[str, str | None]:
    match = _VERSION_RE.search(raw)
    if match:
        return match.group(1).strip(), match.group(2)
    return raw.strip(), None


def detect(response: HttpResponse) -> list[Technology]:
    """Return technologies inferred from a single response."""

    found: dict[str, Technology] = {}

    def add(name: str, category: str, version: str | None, evidence: str) -> None:
        if not name:
            return
        existing = found.get(name.lower())
        if existing is None or (version and not existing.version):
            found[name.lower()] = Technology(
                name=name, version=version, category=category, evidence=evidence
            )

    lowered = {k.lower(): v for k, v in response.headers.items()}

    for header, (default_name, category) in _HEADER_SIGNATURES.items():
        if header in lowered:
            raw = lowered[header]
            if default_name:
                add(default_name, category, None, f"header {header}: {raw}")
            else:
                name, version = _split_name_version(raw)
                add(name or raw, category, version, f"header {header}: {raw}")

    set_cookie = lowered.get("set-cookie", "")
    for cookie_name, (tech_name, category) in _COOKIE_SIGNATURES.items():
        if re.search(rf"\b{re.escape(cookie_name)}\b", set_cookie, re.I):
            add(tech_name, category, None, f"cookie {cookie_name}")

    content_type = lowered.get("content-type", "")
    if "html" in content_type:
        for pattern, tech_name, category in _HTML_SIGNATURES:
            match = pattern.search(response.text)
            if not match:
                continue
            if tech_name:
                add(tech_name, category, None, f"body match: {pattern.pattern[:40]}")
            elif match.groups():
                name, version = _split_name_version(match.group(1))
                add(name, category, version, "meta generator")

    return list(found.values())
