"""API surface discovery: OpenAPI/Swagger documents and GraphQL endpoints.

Probing is active but non-destructive: a short allowlist of conventional
locations is fetched with GET and parsed locally. OpenAPI documents are mined
for their operation inventory; GraphQL endpoints are probed with a minimal
read-only introspection query to confirm the endpoint exists (the introspection
*exposure* itself is reported by a detector, not here).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urljoin

import yaml

from isahat.core.http import SafeHttpClient
from isahat.core.models import ApiSpec

# Conventional discovery locations (GET, read-only).
_OPENAPI_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/docs/openapi.json",
]
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/query", "/v1/graphql"]

# Minimal introspection probe: read-only, no mutations, no data fields.
_INTROSPECTION_PROBE = "{__schema{queryType{name} mutationType{name} types{name}}}"
_MAX_OPERATIONS = 50
_MAX_SPEC_BYTES = 500_000

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def _looks_like_openapi(document: Any) -> bool:
    return (
        isinstance(document, dict)
        and ("openapi" in document or "swagger" in document)
        and isinstance(document.get("paths"), dict)
    )


def _parse_openapi(url: str, text: str) -> ApiSpec | None:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not _looks_like_openapi(document):
        return None

    info = document.get("info") or {}
    title = info.get("title") if isinstance(info, dict) else None
    version = info.get("version") if isinstance(info, dict) else None

    operations: list[str] = []
    paths = document.get("paths") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in item:
            if method.lower() in _HTTP_METHODS:
                operations.append(f"{method.upper()} {path}")
                if len(operations) >= _MAX_OPERATIONS:
                    break
        if len(operations) >= _MAX_OPERATIONS:
            break

    return ApiSpec(
        kind="rest",
        url=url,
        title=str(title) if title else None,
        version=str(version) if version else None,
        operations=operations,
        operation_count=len(paths),
    )


def _parse_graphql(url: str, text: str) -> ApiSpec | None:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(document, dict):
        return None
    schema = (document.get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        return None

    query_type = (schema.get("queryType") or {}).get("name")
    mutation_type = (schema.get("mutationType") or {}).get("name")
    type_names = [t.get("name") for t in schema.get("types") or [] if isinstance(t, dict)]
    type_names = [n for n in type_names if n and not str(n).startswith("__")]

    operations = []
    if query_type:
        operations.append(f"query: {query_type}")
    if mutation_type:
        operations.append(f"mutation: {mutation_type}")
    operations.extend(f"type: {name}" for name in type_names[:_MAX_OPERATIONS])

    return ApiSpec(
        kind="graphql",
        url=url,
        title=query_type or "GraphQL",
        operations=operations[:_MAX_OPERATIONS],
        operation_count=len(type_names),
    )


async def discover_apis(client: SafeHttpClient, target: str) -> list[ApiSpec]:
    """Probe the target for API surfaces. Never raises on target behaviour."""

    found: dict[tuple[str, str], ApiSpec] = {}

    for path in _OPENAPI_PATHS:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = await client.get(url)
        except Exception:  # noqa: BLE001 - a failed probe is not a finding
            continue
        if response.status != 200 or len(response.text) > _MAX_SPEC_BYTES:
            continue
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type and "yaml" not in content_type and not response.text.lstrip().startswith(("{", "openapi", "swagger")):
            continue
        spec = _parse_openapi(response.url, response.text)
        if spec and spec.key() not in found:
            found[spec.key()] = spec

    for path in _GRAPHQL_PATHS:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        # A GET probe keeps everything read-only; servers that require POST
        # simply won't match, which is fine for a non-destructive pass.
        probe_url = f"{url}?query={quote(_INTROSPECTION_PROBE)}"
        try:
            response = await client.get(probe_url)
        except Exception:  # noqa: BLE001
            continue
        if response.status != 200:
            continue
        spec = _parse_graphql(response.url, response.text)
        if spec and spec.key() not in found:
            found[spec.key()] = spec

    return list(found.values())
