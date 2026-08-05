# CLI Reference

The `isahat` command is a thin shell over the core engine. Run `isahat --help`
or `isahat <command> --help` for live help.

## Global behaviour

- **Authorisation:** unless disabled in config, `scan` requires scope
  confirmation. In non-interactive environments you must pass `--yes`.
- **Colours:** respect `NO_COLOR`. Use `--quiet` for machine output, `--verbose`
  for per-stage progress.

## `isahat scan`

Audit a target within an authorised scope.

```bash
isahat scan <TARGET> [options]
```

| Option | Default | Description |
| --- | --- | --- |
| `--profile` | `safe` | Audit profile. |
| `--type` | `web` | Scan type: `web` or `api`. |
| `--config, -c` | auto | Path to `isahat.yml` (auto-detected in CWD). |
| `--auth` | — | Path to `auth.json` (headers/cookies) for an authenticated scan. |
| `--output, -o` | stdout | Write report(s) to a file. |
| `--format, -f` | `markdown` | `json`, `markdown`, `html`, `sarif`, `csv`, or `both`. |
| `--severity` | — | Only display findings ≥ this severity. |
| `--fail-on` | — | Exit code 3 if findings ≥ this severity exist. |
| `--concurrency` | config | Parallel requests. |
| `--timeout` | config | Per-request timeout (seconds). |
| `--rate-limit` | config | Max requests/sec per host. |
| `--rate-limit-check` | false | Opt-in controlled burst checks for missing rate limiting. |
| `--resume` | — | Resume an interrupted scan by ID (requires local storage). |
| `--yes, -y` | false | Confirm authorisation without prompting. |
| `--quiet, -q` | false | Suppress progress/table output. |
| `--verbose, -v` | false | Show per-stage progress. |
| `--no-store` | false | Do not persist the scan locally. |
| `--db` | `~/.isahat/isahat.db` | Override the SQLite database path. |

Examples:

```bash
isahat scan https://example.com
isahat scan https://api.example.com --type api
isahat scan https://example.com --format html -o report.html   # self-contained report
isahat scan https://example.com --format json
isahat scan https://example.com --severity high
isahat scan https://example.com --auth auth.json              # authenticated scan
isahat scan https://example.com --format both -o report        # writes report.json + report.md
isahat scan https://example.com --yes --fail-on high           # CI gate
```

When `--format both` is used with `-o report`, IsaHat writes `report.json` and
`report.md`.

### Authenticated scans (`--auth`)

Pass an `auth.json` to scan behind a login. Headers and cookies are attached to
every request; secrets are never written to stored results and are masked in
evidence.

```json
{
  "headers": { "Authorization": "Bearer eyJhbGciOi..." },
  "cookies": { "session": "abc123" }
}
```

### Resuming an interrupted scan (`--resume`)

Scans run with storage enabled (the default) checkpoint after every stage. If a
scan is interrupted (Ctrl+C, crash), resume it from the last completed stage
instead of starting over:

```bash
isahat scan https://example.com                    # prints the Scan ID up front
isahat scan https://example.com --resume 1f985ec9d883
```

The resumed run reuses the crawled surface, API inventory and findings already
gathered, and only runs the detectors that had not finished. Completed scans
delete their checkpoint, so `--resume` only works for interrupted scans.

### Controlled rate-limit checks (`--rate-limit-check`)

Off by default. When enabled, IsaHat sends a small, paced burst of GET requests
(capped, interval-configurable via `safety.rate_limit_burst` /
`rate_limit_interval`) to authentication-looking endpoints only, stops at the
first sign of throttling, and logs every request in evidence. It never submits
credentials and never uses wordlists.

## `isahat report <scan-id>`

Re-render a stored scan in any supported format (`json`, `markdown`, `html`,
`sarif`, `csv`).

```bash
isahat report 1f985ec9d883 --format markdown
isahat report 1f985ec9d883 --format html -o report.html
isahat report 1f985ec9d883 --format json -o report.json
isahat report 1f985ec9d883 --format sarif -o isahat.sarif   # upload to code scanning
isahat report 1f985ec9d883 --format csv -o findings.csv
```

## `isahat compare <old-id> <new-id>`

Diff two scans, showing new / resolved / still-present findings (correlated by
stable finding fingerprint).

```bash
isahat compare <old-id> <new-id>
isahat compare <old-id> <new-id> -o diff.md
```

## `isahat list`

List recent scans stored locally.

```bash
isahat list --limit 20
```

## `isahat plugins`

```bash
isahat plugins list            # list built-in detectors
isahat plugins install <name>  # external registry: Phase 5
```

## `isahat doctor`

Check the local environment, detectors and storage health.

## `isahat version`

Print the installed version.

## Exit codes

These are a stable contract for CI/pipelines:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; no gating threshold exceeded. |
| `1` | Unexpected runtime error. |
| `2` | Invalid usage, configuration, or scope. |
| `3` | Findings met/exceeded `--fail-on` severity. |
| `130` | Interrupted by the user (SIGINT). |

## Configuration file

See the annotated example in [`examples/isahat.yml`](../examples/isahat.yml) and
the schema in [SCANNING-METHODOLOGY.md](SCANNING-METHODOLOGY.md).

## Shell completion

Typer provides completion out of the box:

```bash
isahat --install-completion    # install for your shell
isahat --show-completion       # print the script
```
