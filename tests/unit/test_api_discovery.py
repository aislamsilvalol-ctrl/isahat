"""Tests for API surface discovery and the API-specific detectors."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from isahat.core.api import discover_apis
from isahat.core.detectors.base import DetectorContext
from isahat.core.detectors.graphql_introspection import GraphqlIntrospectionDetector
from isahat.core.detectors.sensitive_data import SensitiveDataExposureDetector
from isahat.core.models import ApiSpec, Confidence, Severity
from tests.unit.helpers import FakeClient, make_response, make_scope

TARGET = "https://example.com"

_OPENAPI_DOC = """{
  "openapi": "3.0.1",
  "info": {"title": "Users API", "version": "2.1.0"},
  "paths": {
    "/users": {"get": {}},
    "/users/{id}": {"get": {}, "delete": {}}
  }
}"""

_GRAPHQL_DOC = """{
  "data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": null,
    "types": [{"name": "Query"}, {"name": "User"}, {"name": "__Type"}]
  }}
}"""


# --- Discovery -----------------------------------------------------------


async def test_discovers_openapi_document():
    scope = make_scope(TARGET)
    client = FakeClient(
        scope,
        {"/openapi.json": make_response(
            TARGET + "/openapi.json",
            headers={"content-type": "application/json"},
            text=_OPENAPI_DOC,
        )},
    )
    apis = await discover_apis(client, TARGET)
    assert len(apis) == 1
    spec = apis[0]
    assert spec.kind == "rest"
    assert spec.title == "Users API"
    assert spec.version == "2.1.0"
    assert "GET /users" in spec.operations
    assert "DELETE /users/{id}" in spec.operations
    assert spec.operation_count == 2


async def test_discovers_graphql_via_introspection_probe():
    def graphql(url, headers):
        query = parse_qs(urlparse(url).query).get("query", [""])[0]
        if "__schema" in query:
            return make_response(
                url, headers={"content-type": "application/json"}, text=_GRAPHQL_DOC
            )
        return make_response(url, status=400, text='{"errors":[{"message":"no"}]}')

    scope = make_scope(TARGET)
    client = FakeClient(scope, {"/graphql": graphql})
    apis = await discover_apis(client, TARGET)
    assert len(apis) == 1
    spec = apis[0]
    assert spec.kind == "graphql"
    assert "query: Query" in spec.operations
    assert "type: User" in spec.operations
    # Introspection system types are filtered out.
    assert all("__Type" not in op for op in spec.operations)


async def test_no_api_surface_returns_empty():
    scope = make_scope(TARGET)
    client = FakeClient(scope, {"/": make_response(TARGET + "/")})
    assert await discover_apis(client, TARGET) == []


# --- GraphQL introspection detector --------------------------------------


def _ctx(apis=None, responses=None):
    scope = make_scope(TARGET)
    return DetectorContext(
        target=TARGET,
        scope=scope,
        client=FakeClient(scope, {}),
        responses=responses or [],
        apis=apis or [],
    )


async def test_introspection_finding_from_discovered_graphql():
    spec = ApiSpec(
        kind="graphql",
        url=TARGET + "/graphql",
        operations=["query: Query", "type: User"],
        operation_count=2,
    )
    findings = await GraphqlIntrospectionDetector().run(_ctx(apis=[spec]))
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].category == "API Security"


async def test_introspection_ignores_rest_specs():
    spec = ApiSpec(kind="rest", url=TARGET + "/openapi.json")
    assert await GraphqlIntrospectionDetector().run(_ctx(apis=[spec])) == []


# --- Sensitive data exposure detector ------------------------------------


async def test_sensitive_data_exposure_in_json():
    response = make_response(
        TARGET + "/api/users",
        headers={"content-type": "application/json"},
        text='{"users":[{"id":1,"email":"a@b.co","password_hash":"$2b$12$xyz"}]}',
    )
    findings = await SensitiveDataExposureDetector().run(_ctx(responses=[response]))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].confidence == Confidence.PROBABLE
    # The value must be masked in stored evidence.
    assert "$2b$12$xyz" not in (findings[0].evidence.response or "")


async def test_sensitive_data_ignores_clean_json():
    response = make_response(
        TARGET + "/api/status",
        headers={"content-type": "application/json"},
        text='{"status": "ok", "count": 3}',
    )
    assert await SensitiveDataExposureDetector().run(_ctx(responses=[response])) == []


async def test_sensitive_data_ignores_html_responses():
    response = make_response(
        TARGET + "/page",
        headers={"content-type": "text/html"},
        text="<html><body>password reset form</body></html>",
    )
    assert await SensitiveDataExposureDetector().run(_ctx(responses=[response])) == []
