# Installation

IsaHat requires **Python 3.11+**. During alpha, installing from source is
recommended.

## From source (recommended during alpha)

```bash
git clone https://github.com/aislamsilvalol-ctrl/isahat.git
cd isahat
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
isahat doctor                    # verify the environment
```

### Making `isahat` available outside the venv

The editable install puts the `isahat` command inside `.venv/bin`, so a fresh
terminal without the venv activated will report `command not found`. Pick one:

```bash
# Option A — activate the venv whenever you use the CLI
source .venv/bin/activate

# Option B — symlink the entrypoint onto your PATH (macOS/Linux)
mkdir -p ~/.local/bin
ln -sf "$PWD/.venv/bin/isahat" ~/.local/bin/isahat
# ~/.local/bin must be on PATH (it usually is on modern distros/macOS).

# Option C — pipx (isolated global install; recommended for end users)
pipx install .
```

With option B, recreating the venv (e.g. after `rm -rf .venv`) breaks the link
— rerun the `ln` command after reinstalling.

## From PyPI (planned)

Once published:

```bash
pip install isahat
# or, isolated:
pipx install isahat
```

## Docker

```bash
# Build the image
docker build -t isahat:local .

# Run a scan (non-interactive requires --yes)
docker run --rm isahat:local scan https://example.com --yes

# Persist scans to a local volume
docker run --rm -v "$PWD/.isahat:/data" -e ISAHAT_HOME=/data \
  isahat:local scan https://example.com --yes
```

Or with Compose:

```bash
docker compose run --rm isahat scan https://example.com --yes
```

## GitHub Actions / CI

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install isahat            # or: pip install -e ".[dev]"
- run: isahat scan "$TARGET" --yes --format json -o report.json --fail-on high
```

`--fail-on high` makes the job exit non-zero (code 3) when high+ findings are
found. See [CLI.md](CLI.md#exit-codes).

## Where data lives

Scans are stored in a local SQLite database at `~/.isahat/isahat.db` by default.
Override with the `ISAHAT_HOME` environment variable or the `--db` flag.

## Verifying the install

```bash
isahat version
isahat doctor
isahat plugins list
```

## Uninstall

```bash
pip uninstall isahat
rm -f ~/.local/bin/isahat   # if you created the symlink
rm -rf ~/.isahat            # remove stored scans (optional)
```
