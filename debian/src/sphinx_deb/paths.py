"""Where things live on a Debian machine — one place, so the daemon,
the command line, and the tests agree. Every path can be redirected
with an environment variable (the test suite and manual scratch runs
use that; production uses the defaults)."""
from __future__ import annotations

import os
from pathlib import Path


def conf_path() -> Path:
    return Path(os.environ.get("SPHINX_CONF", "/etc/sphinx/sphinx.conf"))


def list_path() -> Path:
    return Path(
        os.environ.get("SPHINX_LIST", "/usr/share/sphinx/bundled-blocklist.txt")
    )


def state_dir() -> Path:
    return Path(os.environ.get("SPHINX_STATE_DIR", "/var/lib/sphinx"))


def runtime_dir() -> Path:
    return Path(os.environ.get("SPHINX_RUNTIME_DIR", "/run/sphinx"))


def dns_port() -> int:
    raw = os.environ.get("SPHINX_PORT", "")
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return 53
