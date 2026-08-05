"""Example: run an IsaHat scan from Python and print a summary.

Run against the bundled lab app:

    python labs/vulnerable_apps/simple_app/app.py --port 8123 &
    python examples/programmatic_scan.py http://127.0.0.1:8123
"""

from __future__ import annotations

import sys
from urllib.parse import urlparse

from isahat.core import ScanConfig, ScanEngine
from isahat.reporting import to_markdown


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python examples/programmatic_scan.py <target-url>")
        return 2

    target = sys.argv[1]
    host = urlparse(target).hostname
    if not host:
        print("target must be a full URL, e.g. http://127.0.0.1:8123")
        return 2

    config = ScanConfig()
    config.target.allowed_hosts = [host]
    # You are asserting you are authorised to test this target.
    config.safety.require_scope_confirmation = False

    engine = ScanEngine(target, config)
    result = engine.scan()

    print(f"Scan {result.id}: {result.stats.findings_total} findings "
          f"across {result.stats.endpoints_discovered} endpoints\n")
    for finding in result.findings:
        print(f"[{finding.severity.value:8}] ({finding.confidence.value:9}) {finding.title}")

    # Full Markdown report is available too:
    _ = to_markdown(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
