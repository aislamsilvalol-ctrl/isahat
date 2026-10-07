"""Local bearer token for the loopback bridge.

The desktop and any other front-end must send this token. It is created on
first use with mode ``0600`` next to the SQLite database (``$ISAHAT_HOME`` or
``~/.isahat``) and reused after that.

If the file is readable or writable by group or others, startup is refused.
The mode is not tightened in place: a looser file may already have been read,
so the operator deletes it (a new token is generated) or runs ``chmod 0600``
on that path after accepting the existing secret. The token value is never
included in the error.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

TOKEN_FILENAME = "bridge.token"
_OWNER_ONLY = 0o600


class BridgeTokenError(Exception):
    """The bridge token file cannot be used safely."""


def data_directory(db_path: str | Path | None = None) -> Path:
    """Directory that holds the database and the bridge token.

    Passing ``db_path`` keeps tests and ``--db`` on the same folder as the
    SQLite file. The directory is not created here.
    """

    if db_path is not None:
        return Path(db_path).expanduser().parent
    home = os.environ.get("ISAHAT_HOME")
    if home:
        return Path(home).expanduser()
    return Path.home() / ".isahat"


def bridge_token_path(db_path: str | Path | None = None) -> Path:
    """Path of the token file. Does not create it and does not read it."""

    return data_directory(db_path) / TOKEN_FILENAME


def load_or_create_bridge_token(path: Path | None = None) -> str:
    """Return the existing token, or create a mode-0600 file on first use."""

    token_path = path if path is not None else bridge_token_path()
    token_path.parent.mkdir(parents=True, exist_ok=True)
    if token_path.exists():
        _require_private(token_path)
        return _read_token(token_path)
    token = secrets.token_urlsafe(32)
    try:
        _write_private(token_path, token)
    except FileExistsError:
        # Another process created the file between the exists() check and open.
        _require_private(token_path)
        return _read_token(token_path)
    return token


def _read_token(path: Path) -> str:
    token = path.read_text(encoding="utf-8").strip()
    if not token:
        raise BridgeTokenError(f"bridge token file is empty: {path}")
    return token


def _write_private(path: Path, token: str) -> None:
    """Create the file as mode 0600. ``umask`` cannot add group/other bits."""

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(path, flags, _OWNER_ONLY)
    try:
        os.write(fd, (token + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, _OWNER_ONLY)
    _require_private(path)


def _require_private(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise BridgeTokenError(
            f"bridge token file {path} is mode {mode:04o}, expected 0600. "
            "Refusing to start: group or other users may have read the secret, "
            "and the mode is not changed automatically. "
            f"Delete {path} so the next start creates a new token, "
            f"or run `chmod 0600 {path}` if the existing secret is still acceptable."
        )


def is_loopback_host(host: str) -> bool:
    """True for bind addresses that stay on this machine."""

    return host.strip().lower() in {"127.0.0.1", "localhost", "::1"}


def non_loopback_warning(host: str) -> str | None:
    """Warning text when ``--host`` is not loopback. Never includes a token."""

    if is_loopback_host(host):
        return None
    return (
        "binding the bridge beyond loopback exposes scan control on the network. "
        "Every route except GET /health requires the local bridge token. "
        "The token value is not printed; it stays in the token file."
    )
