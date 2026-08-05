"""The ``isahat`` command-line entrypoint (Typer application)."""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console

from isahat import __version__
from isahat.cli import console as ui
from isahat.cli.exit_codes import ExitCode
from isahat.core.auth import AuthConfig, load_auth
from isahat.core.config import ScanConfig, find_default_config, load_config
from isahat.core.detectors import default_detectors
from isahat.core.engine import ScanEngine
from isahat.core.models import ScanResult, Severity
from isahat.core.scope import Scope, ScopeViolation
from isahat.reporting import compare_scans, diff_to_markdown, extension_for, render
from isahat.storage import ScanStore

app = typer.Typer(
    name="isahat",
    help="IsaHat — Open Source AI Security Auditor for Vibe-Coded Applications.",
    add_completion=True,
    no_args_is_help=True,
)
plugins_app = typer.Typer(help="Manage and inspect detection plugins.")
app.add_typer(plugins_app, name="plugins")

_SEVERITY_CHOICES = "critical|high|medium|low|info"


def _parse_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError as exc:  # pragma: no cover - argparse-style guard
        raise typer.BadParameter(f"severity must be one of {_SEVERITY_CHOICES}") from exc


def _exit(code: ExitCode) -> None:
    raise typer.Exit(code=int(code))


def _build_config(
    config_path: Path | None,
    *,
    profile: str | None,
    concurrency: int | None,
    timeout: float | None,
    rate_limit: float | None,
) -> ScanConfig:
    resolved = config_path or find_default_config()
    config = load_config(resolved)
    if profile is not None:
        config.scan.profile = profile
    if concurrency is not None:
        config.scan.concurrency = concurrency
    if timeout is not None:
        config.scan.timeout = timeout
    if rate_limit is not None:
        config.safety.rate_limit = rate_limit
    return config


def _confirm_scope(console: Console, target: str, scope: Scope, assume_yes: bool) -> bool:
    ui.print_scope_banner(console, target, scope.describe())
    if assume_yes:
        console.print("[dim]Scope confirmed via --yes.[/dim]")
        return True
    if not sys.stdin.isatty():
        console.print(
            "[red]Refusing to scan: no TTY for scope confirmation. "
            "Pass --yes to confirm authorisation in non-interactive environments.[/red]"
        )
        return False
    return typer.confirm("I am authorised to test this target. Proceed?", default=False)


def _write_reports(
    console: Console,
    result: ScanResult,
    fmt: str,
    output: Path | None,
) -> None:
    formats = ["json", "markdown"] if fmt == "both" else [fmt]
    for one in formats:
        content = render(result, one)
        if output is None:
            if len(formats) == 1:
                console.print(content)
            continue
        target_path = (
            output if len(formats) == 1 else output.with_suffix("." + extension_for(one))
        )
        target_path.write_text(content, encoding="utf-8")
        console.print(f"[green]Report written:[/green] {target_path}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL, e.g. https://example.com"),
    profile: str = typer.Option("safe", "--profile", help="Audit profile (safe by default)."),
    scan_type: str = typer.Option("web", "--type", help="Scan type: web or api."),
    config_path: Path | None = typer.Option(
        None, "--config", "-c", help="Path to isahat.yml (auto-detected if omitted)."
    ),
    auth_path: Path | None = typer.Option(
        None, "--auth", help="Path to auth.json (headers/cookies) for an authenticated scan."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the report to a file instead of stdout."
    ),
    fmt: str = typer.Option(
        "markdown", "--format", "-f", help="json | markdown | html | sarif | csv | both."
    ),
    severity: str | None = typer.Option(
        None, "--severity", help=f"Only display findings >= this severity ({_SEVERITY_CHOICES})."
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help=f"Exit code 3 if findings >= this severity ({_SEVERITY_CHOICES})."
    ),
    concurrency: int | None = typer.Option(None, "--concurrency", help="Parallel requests."),
    timeout: float | None = typer.Option(None, "--timeout", help="Per-request timeout (s)."),
    rate_limit: float | None = typer.Option(
        None, "--rate-limit", help="Max requests/sec per host."
    ),
    rate_limit_check: bool = typer.Option(
        False,
        "--rate-limit-check",
        help="Opt-in: controlled burst probes for missing rate limiting on auth endpoints.",
    ),
    resume: str | None = typer.Option(
        None, "--resume", help="Resume an interrupted scan by its ID (requires local storage)."
    ),
    assume_yes: bool = typer.Option(
        False, "--yes", "-y", help="Confirm authorisation without prompting."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show per-stage progress."),
    no_store: bool = typer.Option(False, "--no-store", help="Do not persist the scan locally."),
    db_path: Path | None = typer.Option(None, "--db", help="Override the SQLite database path."),
) -> None:
    """Audit a target within an authorised scope."""

    console = ui.make_console(quiet=quiet)
    min_severity = _parse_severity(severity)
    fail_severity = _parse_severity(fail_on)

    try:
        config = _build_config(
            config_path,
            profile=profile,
            concurrency=concurrency,
            timeout=timeout,
            rate_limit=rate_limit,
        )
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        _exit(ExitCode.USAGE)

    if rate_limit_check:
        config.safety.rate_limit_checks = True

    auth: AuthConfig | None = None
    if auth_path is not None:
        try:
            auth = load_auth(auth_path)
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"[red]Auth error:[/red] {exc}")
            _exit(ExitCode.USAGE)

    try:
        scope = Scope.from_config(target, config)
    except ScopeViolation as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        _exit(ExitCode.USAGE)

    require_confirm = config.safety.require_scope_confirmation
    if require_confirm and not _confirm_scope(console, target, scope, assume_yes):
        console.print("[red]Aborted: authorisation not confirmed.[/red]")
        _exit(ExitCode.USAGE)

    def on_progress(stage: str, message: str) -> None:
        if verbose and not quiet:
            console.print(f"[dim]{stage}[/dim] {message}")

    if resume is not None and no_store:
        console.print("[red]--resume requires local storage (remove --no-store).[/red]")
        _exit(ExitCode.USAGE)

    store: ScanStore | None = None
    if not no_store:
        store = ScanStore(db_path)
        if resume is not None and store.load_checkpoint(resume) is None:
            console.print(
                f"[red]No checkpoint found for scan '{resume}'.[/red] "
                "Checkpoints exist only for interrupted scans run with storage enabled."
            )
            store.close()
            _exit(ExitCode.USAGE)

    engine = ScanEngine(
        target,
        config,
        scan_type=scan_type,
        on_progress=on_progress if verbose else None,
        auth=auth,
        checkpoint_store=store,
        scan_id=resume,
    )
    if auth is not None and not quiet:
        console.print("[dim]Authenticated scan: attaching provided headers/cookies.[/dim]")
    if rate_limit_check and not quiet:
        console.print(
            "[yellow]Rate-limit checks enabled:[/yellow] controlled burst probes "
            f"(max {config.safety.rate_limit_burst} requests/endpoint) on auth-like endpoints."
        )
    if not quiet:
        console.print(f"[dim]Scan ID: {engine.scan_id} (resume with --resume {engine.scan_id})[/dim]")

    try:
        if quiet or verbose:
            result = engine.scan()
        else:
            with console.status(f"Scanning {target}…", spinner="dots"):
                result = engine.scan()
    except ScopeViolation as exc:
        console.print(f"[red]Scope error:[/red] {exc}")
        if store is not None:
            store.close()
        _exit(ExitCode.USAGE)
    except KeyboardInterrupt:  # pragma: no cover - interactive
        console.print(
            f"[yellow]Cancelled by user.[/yellow] Progress saved — resume with:\n"
            f"  isahat scan {target} --resume {engine.scan_id}"
        )
        if store is not None:
            store.close()
        _exit(ExitCode.CANCELLED)
    except Exception as exc:  # noqa: BLE001 - surface a clean error and code
        console.print(f"[red]Scan failed:[/red] {exc}")
        if store is not None:
            store.close()
        _exit(ExitCode.ERROR)

    if min_severity is not None:
        result.findings = result.findings_at_or_above(min_severity)
        result.recompute_stats()

    if store is not None:
        store.save(result)
        store.close()

    if not quiet:
        ui.render_findings_table(console, result)
        ui.render_summary(console, result)

    _write_reports(console, result, fmt, output)

    if fail_severity is not None and result.findings_at_or_above(fail_severity):
        console.print(
            f"[red]Gate failed:[/red] findings at or above '{fail_severity.value}' were found."
        )
        _exit(ExitCode.THRESHOLD)
    _exit(ExitCode.OK)


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID to render a report for."),
    fmt: str = typer.Option(
        "markdown", "--format", "-f", help="json | markdown | html | sarif | csv."
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write to a file."),
    db_path: Path | None = typer.Option(None, "--db", help="Override the SQLite database path."),
) -> None:
    """Re-render a stored scan report."""

    console = ui.make_console()
    with ScanStore(db_path) as store:
        result = store.get(scan_id)
    if result is None:
        console.print(f"[red]No scan found with id '{scan_id}'.[/red]")
        _exit(ExitCode.USAGE)
    try:
        content = render(result, fmt)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        _exit(ExitCode.USAGE)
    if output is None:
        console.print(content)
    else:
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Report written:[/green] {output}")
    _exit(ExitCode.OK)


@app.command()
def compare(
    base_id: str = typer.Argument(..., help="Older scan ID."),
    head_id: str = typer.Argument(..., help="Newer scan ID."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write to a file."),
    db_path: Path | None = typer.Option(None, "--db", help="Override the SQLite database path."),
) -> None:
    """Compare two stored scans and show new/resolved findings."""

    console = ui.make_console()
    with ScanStore(db_path) as store:
        base = store.get(base_id)
        head = store.get(head_id)
    missing = [sid for sid, res in ((base_id, base), (head_id, head)) if res is None]
    if missing:
        console.print(f"[red]Scan(s) not found:[/red] {', '.join(missing)}")
        _exit(ExitCode.USAGE)
    assert base is not None and head is not None
    diff = compare_scans(base, head)
    content = diff_to_markdown(diff)
    if output is None:
        console.print(content)
    else:
        output.write_text(content, encoding="utf-8")
        console.print(f"[green]Comparison written:[/green] {output}")
    _exit(ExitCode.OK)


@app.command(name="list")
def list_scans(
    limit: int = typer.Option(20, "--limit", "-n", help="Max scans to show."),
    db_path: Path | None = typer.Option(None, "--db", help="Override the SQLite database path."),
) -> None:
    """List recent scans stored locally."""

    from rich.table import Table

    console = ui.make_console()
    with ScanStore(db_path) as store:
        rows = store.list(limit=limit)
    if not rows:
        console.print("[dim]No scans recorded yet. Run `isahat scan <url>`.[/dim]")
        _exit(ExitCode.OK)
    table = Table(title="Recent scans", header_style="bold")
    table.add_column("ID")
    table.add_column("Target", overflow="fold")
    table.add_column("Started", style="dim")
    table.add_column("C", justify="right")
    table.add_column("H", justify="right")
    table.add_column("M", justify="right")
    table.add_column("L", justify="right")
    table.add_column("I", justify="right")
    for row in rows:
        table.add_row(
            row.id,
            row.target,
            row.started_at,
            str(row.critical),
            str(row.high),
            str(row.medium),
            str(row.low),
            str(row.info),
        )
    console.print(table)
    _exit(ExitCode.OK)


@plugins_app.command("list")
def plugins_list() -> None:
    """List available detectors (the built-in plugins shipped with IsaHat)."""

    from rich.table import Table

    console = ui.make_console()
    table = Table(title="Detectors", header_style="bold")
    table.add_column("Name")
    table.add_column("Category")
    for detector in default_detectors():
        table.add_row(detector.name, detector.category)
    console.print(table)
    _exit(ExitCode.OK)


@plugins_app.command("install")
def plugins_install(name: str = typer.Argument(..., help="Plugin name.")) -> None:
    """Install a plugin (external plugin registry lands in Phase 5)."""

    console = ui.make_console()
    console.print(
        f"[yellow]Plugin installation is not available yet.[/yellow] "
        f"Requested: '{name}'. Track progress in ROADMAP.md (Phase 5)."
    )
    _exit(ExitCode.USAGE)


@app.command()
def doctor(
    db_path: Path | None = typer.Option(None, "--db", help="Override the SQLite database path."),
) -> None:
    """Check the local environment and configuration health."""

    console = ui.make_console()
    console.print(f"[bold]IsaHat[/bold] {__version__}")
    console.print(f"Python: {sys.version.split()[0]}")

    checks: list[tuple[str, bool, str]] = []

    try:
        import httpx  # noqa: F401

        checks.append(("httpx available", True, ""))
    except Exception as exc:  # noqa: BLE001
        checks.append(("httpx available", False, str(exc)))

    detectors = default_detectors()
    checks.append(("built-in detectors", len(detectors) > 0, f"{len(detectors)} loaded"))

    try:
        with ScanStore(db_path) as store:
            store.list(limit=1)
            db_location = store.path
        checks.append(("storage writable", True, f"db at {db_location}"))
    except Exception as exc:  # noqa: BLE001
        checks.append(("storage writable", False, str(exc)))

    config_path = find_default_config()
    # Not having an isahat.yml is fine — defaults are safe — so this is
    # informational and never fails the check.
    checks.append(
        ("configuration", True, str(config_path or "(using safe defaults)"))
    )

    all_ok = True
    for name, ok, detail in checks:
        mark = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        all_ok = all_ok and ok
        console.print(f"  {mark}  {name}{f'  [dim]{detail}[/dim]' if detail else ''}")

    _exit(ExitCode.OK if all_ok else ExitCode.ERROR)


@app.command()
def version() -> None:
    """Print the IsaHat version."""

    console = ui.make_console()
    console.print(__version__)
    _exit(ExitCode.OK)


if __name__ == "__main__":  # pragma: no cover
    app()
