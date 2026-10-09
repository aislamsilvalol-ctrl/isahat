"""Tests for the opt-in rate-limiting detector and scan resume checkpoints."""

from __future__ import annotations

import sqlite3

import pytest

from isahat.core.auth import AuthConfig
from isahat.core.config import ScanConfig
from isahat.core.detectors.base import Detector, DetectorContext
from isahat.core.detectors.rate_limiting import RateLimitingDetector
from isahat.core.engine import ScanEngine
from isahat.core.models import Confidence, ScanResult, Severity
from isahat.core.state import (
    ResponseSnapshot,
    ResumeRejected,
    ScanCheckpoint,
    ScanContract,
    require_resume_contract,
)
from isahat.storage import ScanStore
from tests.unit.helpers import FakeClient, make_response, make_scope

TARGET = "https://example.com"


def _ctx(client, *, responses, burst=10, interval=0.0):
    scope = make_scope(TARGET)
    return DetectorContext(
        target=TARGET,
        scope=scope,
        client=client,
        responses=responses,
        rate_limit_burst=burst,
        rate_limit_interval=interval,
    )


# --- Rate limiting --------------------------------------------------------


async def test_rate_limiting_missing_is_flagged_with_full_log():
    scope = make_scope(TARGET)
    client = FakeClient(
        scope, {"/login": make_response(TARGET + "/login", text="<form></form>")}
    )
    ctx = _ctx(client, responses=[make_response(TARGET + "/login")], burst=10)
    findings = await RateLimitingDetector().run(ctx)
    assert client.requests_made == 10  # full burst completed
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.PROBABLE
    assert finding.cwe == "CWE-307"
    # Every request/response of the burst is logged in evidence.
    assert "attempt 10" in (finding.evidence.response or "")


async def test_rate_limiting_stops_burst_on_first_429():
    hits = {"count": 0}

    def login(url, headers):
        hits["count"] += 1
        if hits["count"] >= 4:
            return make_response(url, status=429, text="slow down")
        return make_response(url, text="<form></form>")

    scope = make_scope(TARGET)
    client = FakeClient(scope, {"/login": login})
    ctx = _ctx(client, responses=[make_response(TARGET + "/login")], burst=10)
    assert await RateLimitingDetector().run(ctx) == []
    assert hits["count"] == 4  # interrupted immediately on 429


async def test_rate_limiting_ignores_non_auth_endpoints():
    scope = make_scope(TARGET)
    client = FakeClient(scope, {"/about": make_response(TARGET + "/about")})
    ctx = _ctx(client, responses=[make_response(TARGET + "/about")], burst=10)
    assert await RateLimitingDetector().run(ctx) == []
    assert client.requests_made == 0  # never probed a non-auth endpoint


async def test_rate_limiting_burst_is_hard_capped():
    scope = make_scope(TARGET)
    client = FakeClient(
        scope, {"/login": make_response(TARGET + "/login", text="<form></form>")}
    )
    ctx = _ctx(client, responses=[make_response(TARGET + "/login")], burst=500)
    findings = await RateLimitingDetector().run(ctx)
    assert client.requests_made <= 30  # hard cap, regardless of configuration
    assert len(findings) == 1


# --- Checkpoints ----------------------------------------------------------


def test_checkpoint_store_roundtrip(tmp_path):
    with ScanStore(tmp_path / "isahat.db") as store:
        checkpoint = ScanCheckpoint(
            scan_id="abc123",
            target=TARGET,
            stage="detectors",
            requests_made=12,
            responses=[
                ResponseSnapshot.from_response(make_response(TARGET + "/login", status=200))
            ],
        )
        store.save_checkpoint(checkpoint)
        loaded = store.load_checkpoint("abc123")
        assert loaded is not None
        assert loaded.stage == "detectors"
        assert loaded.requests_made == 12
        restored = loaded.responses[0].to_response()
        assert restored.url == TARGET + "/login"
        assert restored.status == 200
        store.delete_checkpoint("abc123")
        assert store.load_checkpoint("abc123") is None


def test_checkpoint_upsert_overwrites(tmp_path):
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(ScanCheckpoint(scan_id="x1", target=TARGET, stage="apis"))
        store.save_checkpoint(ScanCheckpoint(scan_id="x1", target=TARGET, stage="detectors"))
        loaded = store.load_checkpoint("x1")
        assert loaded is not None and loaded.stage == "detectors"


def _finished_result(scan_id: str) -> ScanResult:
    result = ScanResult(
        id=scan_id,
        target=TARGET,
        scope={"target": TARGET, "allowed_hosts": ["example.com"]},
    )
    result.finished_at = result.started_at
    result.recompute_stats()
    return result


def test_finalize_scan_saves_result_and_drops_checkpoint(tmp_path):
    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(ScanCheckpoint(scan_id="abc123", target=TARGET, stage="detectors"))
        store.finalize_scan(_finished_result("abc123"))
        assert store.get("abc123") is not None
        assert store.load_checkpoint("abc123") is None


def test_finalize_scan_rolls_back_when_commit_fails(tmp_path):
    """A failure before commit must not delete the checkpoint or publish the scan."""

    class _CommitProxy:
        def __init__(self, real: sqlite3.Connection) -> None:
            self._real = real
            self.statements: list[str] = []

        def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
            self.statements.append(sql)
            return self._real.execute(sql, parameters)

        def commit(self) -> None:
            blob = " ".join(self.statements).lower()
            if "insert into scans" in blob and "delete from checkpoints" in blob:
                raise sqlite3.OperationalError("injected commit failure")
            self._real.commit()

        def rollback(self) -> None:
            self._real.rollback()

        def __getattr__(self, name: str) -> object:
            return getattr(self._real, name)

    with ScanStore(tmp_path / "isahat.db") as store:
        store.save_checkpoint(ScanCheckpoint(scan_id="abc123", target=TARGET, stage="detectors"))
        store._conn = _CommitProxy(store._conn)  # type: ignore[assignment]
        with pytest.raises(sqlite3.OperationalError, match="injected commit failure"):
            store.finalize_scan(_finished_result("abc123"))
        assert store.get("abc123") is None
        checkpoint = store.load_checkpoint("abc123")
        assert checkpoint is not None
        assert checkpoint.stage == "detectors"


def test_raising_detector_is_not_completed_and_resume_reruns_it(tmp_path):
    calls = {"ok": 0, "boom": 0, "tail": 0}
    stop = {"on": True}

    class OkDetector(Detector):
        name = "ok-one"
        category = "test"

        async def run(self, ctx: DetectorContext) -> list:
            calls["ok"] += 1
            return []

    class BoomDetector(Detector):
        name = "boom"
        category = "test"

        async def run(self, ctx: DetectorContext) -> list:
            calls["boom"] += 1
            raise RuntimeError("detector failed")

    class TailDetector(Detector):
        name = "tail"
        category = "test"

        async def run(self, ctx: DetectorContext) -> list:
            calls["tail"] += 1
            if stop["on"]:
                raise KeyboardInterrupt
            return []

    scan_id = "resume-boom"
    db = tmp_path / "isahat.db"
    with ScanStore(db) as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id=scan_id,
                target=TARGET,
                stage="detectors",
                responses=[ResponseSnapshot.from_response(make_response(TARGET + "/"))],
            )
        )
        first = ScanEngine(
            TARGET,
            ScanConfig(),
            detectors=[OkDetector(), BoomDetector(), TailDetector()],
            checkpoint_store=store,
            scan_id=scan_id,
        )
        with pytest.raises(KeyboardInterrupt):
            first.scan()
        assert store.get(scan_id) is None
        checkpoint = store.load_checkpoint(scan_id)
        assert checkpoint is not None
        assert checkpoint.completed_detectors == ["ok-one"]
        assert calls == {"ok": 1, "boom": 1, "tail": 1}

        stop["on"] = False
        second = ScanEngine(
            TARGET,
            ScanConfig(),
            detectors=[OkDetector(), BoomDetector(), TailDetector()],
            checkpoint_store=store,
            scan_id=scan_id,
        )
        result = second.scan()
        assert calls == {"ok": 1, "boom": 2, "tail": 2}
        assert result.id == scan_id
        assert store.get(scan_id) is not None
        assert store.load_checkpoint(scan_id) is None


async def test_persisted_checkpoint_has_no_auth_material(tmp_path):
    """SQLite checkpoint payload must not contain auth headers or raw secrets."""

    import hashlib

    from isahat.core.detectors.cookies import CookieSecurityDetector
    from isahat.core.detectors.sensitive_data import SensitiveDataExposureDetector
    from isahat.core.http import HttpResponse

    secret = "super-secret-token"
    body = '{"password": "' + secret + '", "user": "ada"}'
    response = HttpResponse(
        url=TARGET + "/api",
        status=200,
        headers={
            "Content-Type": "application/json",
            "Set-Cookie": f"session={secret}; Secure; SameSite=Lax; Path=/",
        },
        text=body,
        elapsed_ms=1.0,
        request_method="GET",
        request_headers={
            "Authorization": f"Bearer {secret}",
            "Cookie": f"session={secret}",
            "Proxy-Authorization": f"Basic {secret}",
            "X-Api-Key": secret,
            "Accept": "application/json",
        },
    )
    db = tmp_path / "isahat.db"
    with ScanStore(db) as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="sec1",
                target=TARGET,
                stage="detectors",
                responses=[ResponseSnapshot.from_response(response)],
            )
        )
    raw = sqlite3.connect(db).execute(
        "SELECT payload FROM checkpoints WHERE scan_id = ?", ("sec1",)
    ).fetchone()[0]
    assert isinstance(raw, str)
    assert secret not in raw

    loaded = ScanCheckpoint.model_validate_json(raw)
    snap = loaded.responses[0]
    assert snap.request_headers["authorization"] == "***REDACTED***"
    assert snap.request_headers["cookie"] == "***REDACTED***"
    assert snap.request_headers["proxy-authorization"] == "***REDACTED***"
    assert snap.request_headers["x-api-key"] == "***REDACTED***"
    assert snap.request_headers["accept"] == "application/json"
    assert secret not in snap.headers["set-cookie"]
    assert "SameSite=Lax" in snap.headers["set-cookie"]
    assert "session=" in snap.headers["set-cookie"]
    assert "password" in snap.text
    assert secret not in snap.text
    assert snap.body_size == len(body.encode())
    assert snap.body_sha256 == hashlib.sha256(body.encode()).hexdigest()

    restored = snap.to_response()
    scope = make_scope(TARGET)
    ctx = DetectorContext(
        target=TARGET,
        scope=scope,
        client=FakeClient(scope, {}),
        responses=[restored],
    )
    cookies = await CookieSecurityDetector().run(ctx)
    assert any("session" in finding.title for finding in cookies)
    exposed = await SensitiveDataExposureDetector().run(ctx)
    assert exposed


def test_new_checkpoint_records_contract_without_secrets():
    secret = "super-secret-token"
    config = ScanConfig()
    config.scan.profile = "deep"
    config.safety.rate_limit_checks = True
    engine = ScanEngine(
        TARGET,
        config,
        scan_type="api",
        auth=AuthConfig(headers={"Authorization": f"Bearer {secret}"}),
    )
    result = ScanResult(
        id=engine.scan_id,
        target=TARGET,
        scope={"target": TARGET, "allowed_hosts": ["example.com"]},
    )
    checkpoint = engine._new_checkpoint(result, [], stage="apis")
    assert checkpoint.contract is not None
    assert checkpoint.contract.profile == "deep"
    assert checkpoint.contract.scan_type == "api"
    assert checkpoint.contract.rate_limit_check is True
    assert checkpoint.contract.authenticated is True
    dumped = checkpoint.model_dump_json()
    assert secret not in dumped
    assert "Bearer" not in dumped


def test_legacy_checkpoint_and_authenticated_resume_are_rejected():
    legacy = ScanCheckpoint.model_validate(
        {"scan_id": "old", "target": TARGET, "stage": "apis"}
    )
    assert legacy.contract is None
    with pytest.raises(ResumeRejected, match="no scan contract"):
        require_resume_contract(legacy)

    authenticated = ScanCheckpoint(
        scan_id="auth",
        target=TARGET,
        contract=ScanContract(
            profile="safe", scan_type="web", rate_limit_check=False, authenticated=True
        ),
    )
    with pytest.raises(ResumeRejected, match="credential store"):
        require_resume_contract(authenticated)


def test_cli_resume_refuses_missing_and_authenticated_contracts(tmp_path):
    from typer.testing import CliRunner  # noqa: PLC0415

    from isahat.cli.main import app as cli_app  # noqa: PLC0415

    db = tmp_path / "isahat.db"
    secret = "super-secret-token"
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        '{"headers": {"Authorization": "Bearer ' + secret + '"}}', encoding="utf-8"
    )
    with ScanStore(db) as store:
        store.save_checkpoint(ScanCheckpoint(scan_id="old", target=TARGET, stage="crawl"))
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="auth",
                target=TARGET,
                stage="detectors",
                contract=ScanContract(
                    profile="safe",
                    scan_type="web",
                    rate_limit_check=False,
                    authenticated=True,
                ),
            )
        )

    runner = CliRunner()
    missing = runner.invoke(
        cli_app, ["scan", TARGET, "--resume", "old", "--db", str(db), "--yes"]
    )
    assert missing.exit_code == 2
    assert "no scan contract" in missing.output

    refused = runner.invoke(
        cli_app,
        [
            "scan",
            TARGET,
            "--resume",
            "auth",
            "--auth",
            str(auth_file),
            "--db",
            str(db),
            "--yes",
        ],
    )
    assert refused.exit_code == 2
    assert "authenticated" in refused.output.lower()
    assert secret not in refused.output


def test_cli_resume_restores_contract(tmp_path, monkeypatch):
    from typer.testing import CliRunner  # noqa: PLC0415

    from isahat.cli.main import app as cli_app  # noqa: PLC0415

    db = tmp_path / "isahat.db"
    with ScanStore(db) as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="c1",
                target=TARGET,
                stage="detectors",
                contract=ScanContract(profile="deep", scan_type="api", rate_limit_check=True),
            )
        )

    captured: dict[str, object] = {}

    def _scan(self):  # noqa: ANN001
        captured["profile"] = self.config.scan.profile
        captured["scan_type"] = self.scan_type
        captured["rate_limit_checks"] = self.config.safety.rate_limit_checks
        captured["auth"] = self._auth
        raise RuntimeError("stop-before-network")

    monkeypatch.setattr(ScanEngine, "scan", _scan)
    result = CliRunner().invoke(
        cli_app,
        ["scan", TARGET, "--resume", "c1", "--db", str(db), "--yes", "--quiet", "--profile", "safe"],
    )
    assert result.exit_code == 1
    assert captured == {
        "profile": "deep",
        "scan_type": "api",
        "rate_limit_checks": True,
        "auth": None,
    }


def test_cli_resume_refuses_when_another_store_holds_the_lease(tmp_path, monkeypatch):
    from typer.testing import CliRunner  # noqa: PLC0415

    from isahat.cli.main import app as cli_app  # noqa: PLC0415

    db = tmp_path / "isahat.db"
    with ScanStore(db) as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="held",
                target=TARGET,
                stage="detectors",
                contract=ScanContract(profile="safe", scan_type="web", rate_limit_check=False),
            )
        )
        assert store.try_acquire_resume_lease("held", 3600) is True

    def _refuse_engine(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("engine must not start")

    monkeypatch.setattr(ScanEngine, "__init__", _refuse_engine)
    result = CliRunner().invoke(
        cli_app, ["scan", TARGET, "--resume", "held", "--db", str(db), "--yes"]
    )
    assert result.exit_code == 2
    assert "scan já está sendo retomado" in result.output
    with ScanStore(db) as store:
        assert store.try_acquire_resume_lease("held", 3600) is False


def test_cli_resume_acquire_none_uses_missing_checkpoint_message(tmp_path, monkeypatch):
    from typer.testing import CliRunner  # noqa: PLC0415

    from isahat.cli.main import app as cli_app  # noqa: PLC0415

    db = tmp_path / "isahat.db"
    with ScanStore(db) as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="gone",
                target=TARGET,
                stage="crawl",
                contract=ScanContract(profile="safe", scan_type="web", rate_limit_check=False),
            )
        )

    def _missing(self, _scan_id, _ttl):  # noqa: ANN001
        return None

    def _refuse_engine(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("engine must not start")

    monkeypatch.setattr(ScanStore, "try_acquire_resume_lease", _missing)
    monkeypatch.setattr(ScanEngine, "__init__", _refuse_engine)
    result = CliRunner().invoke(
        cli_app, ["scan", TARGET, "--resume", "gone", "--db", str(db), "--yes"]
    )
    assert result.exit_code == 2
    assert "No checkpoint found" in result.output


def test_cli_resume_releases_lease_on_interrupt(tmp_path, monkeypatch):
    from typer.testing import CliRunner  # noqa: PLC0415

    from isahat.cli.main import app as cli_app  # noqa: PLC0415

    db = tmp_path / "isahat.db"
    with ScanStore(db) as store:
        store.save_checkpoint(
            ScanCheckpoint(
                scan_id="stop",
                target=TARGET,
                stage="detectors",
                contract=ScanContract(profile="safe", scan_type="web", rate_limit_check=False),
            )
        )

    def _scan(self):  # noqa: ANN001
        raise KeyboardInterrupt

    monkeypatch.setattr(ScanEngine, "scan", _scan)
    result = CliRunner().invoke(
        cli_app, ["scan", TARGET, "--resume", "stop", "--db", str(db), "--yes", "--quiet"]
    )
    assert result.exit_code == 130
    with ScanStore(db) as store:
        row = store._conn.execute(
            "SELECT lease_until FROM checkpoints WHERE scan_id = ?", ("stop",)
        ).fetchone()
        assert row["lease_until"] is None
        assert store.try_acquire_resume_lease("stop", 30) is True


def test_checkpoint_body_is_capped(tmp_path):
    raw_body = "a" * 250_000
    snapshot = ResponseSnapshot.from_response(make_response(TARGET + "/", text=raw_body))
    assert len(snapshot.text) == 200_000
    assert snapshot.body_size == 250_000
    assert raw_body not in snapshot.model_dump_json()
