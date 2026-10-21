"""The Sphinx daemon: the filter, running as a service.

Loads the bundled blocklist (through the sanity gate — a list that
does not parse to a real blocklist stops the daemon loudly rather
than "protecting" with a torn file), serves it on loopback, and
answers the control socket so the command line can prove liveness
and read real counters.

The daemon never touches the machine's resolver configuration.
Pointing DNS at the filter is ``sphinx engage``'s job, under the
guard's discipline; stopping the daemon never strands the machine
either — engage proved the daemon answers before pointing, and
uninstall restores before removing (the package's prerm).
"""
from __future__ import annotations

import ipaddress
import signal
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

from . import __version__, paths
from .control import ControlServer, control_socket_path
from .core.blocklist import Allowlist, FilterLists
from .core.forwarder import UPSTREAM_RESOLVERS, forward_query
from .core.server import DnsFilterServer, FilterEngine
from .core.validation import parse_and_validate
from .resolver.systemview import is_loopback


class ConfigError(RuntimeError):
    pass


class DaemonConfig:
    """The daemon's settings from /etc/sphinx/sphinx.conf.

    Plain ``key = value`` lines. What a user may set in Phase 1: the
    upstream resolvers (FILTER-SPEC's defaults are 1.1.1.1 with
    9.9.9.9 as the fallback) and whether the in-memory query log
    records. Everything else is the spec's, not a setting.
    """

    def __init__(self, upstreams: List[str], log_queries: bool = True):
        self.upstreams = upstreams
        self.log_queries = log_queries

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "DaemonConfig":
        upstreams = list(UPSTREAM_RESOLVERS)
        log_queries = True
        path = path if path is not None else paths.conf_path()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []  # no config file: the spec's defaults rule
        seen = {}
        for line in lines:
            text = line.split("#", 1)[0].strip()
            if not text or "=" not in text:
                continue
            key, _, value = text.partition("=")
            seen[key.strip().lower()] = value.strip()
        primary = seen.get("upstream", "")
        fallback = seen.get("fallback", "")
        if primary:
            upstreams[0] = primary
        if fallback:
            upstreams[1] = fallback
        elif primary:
            upstreams = upstreams[:1]
        for address in upstreams:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                raise ConfigError(
                    f"The upstream resolver '{address}' in {path} is "
                    "not an IP address. Fix it, or remove the line to "
                    "use the standard upstream (1.1.1.1)."
                )
            if ip.is_loopback or is_loopback(address):
                raise ConfigError(
                    f"The upstream resolver '{address}' in {path} is "
                    "on this machine. Sphinx never forwards to a "
                    "resolver on the same machine — that would loop "
                    "questions back into a local resolver (or into "
                    "Sphinx itself). Use a real upstream resolver, "
                    "or remove the line to use the standard one "
                    "(1.1.1.1)."
                )
        if seen.get("query_log", "").lower() in ("off", "no", "false", "0"):
            log_queries = False
        return cls(upstreams=upstreams, log_queries=log_queries)


def _say(message: str) -> None:
    print(f"sphinx: {message}", file=sys.stderr, flush=True)


def run() -> int:
    """Serve until SIGTERM/SIGINT. Returns the process exit code."""
    try:
        config = DaemonConfig.load()
    except ConfigError as exc:
        _say(str(exc))
        return 2

    list_file = paths.list_path()
    try:
        lines = list_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        _say(
            f"The blocklist at {list_file} cannot be read, so the "
            "filter cannot start. Reinstall the sphinx package to "
            "restore it."
        )
        return 2
    blocklist = parse_and_validate(lines)
    if blocklist is None:
        _say(
            f"The blocklist at {list_file} did not pass its sanity "
            "check (it parsed to fewer domains than a real blocklist "
            "holds), so the filter cannot start — a broken list must "
            "never quietly become the protection. Reinstall the "
            "sphinx package to restore the bundled list."
        )
        return 2

    lists = FilterLists(blocklist, Allowlist([]))

    def forward(data: bytes):
        return forward_query(data, resolvers=config.upstreams)

    engine = FilterEngine(
        lists_provider=lambda: lists,
        forwarder=forward,
        log_enabled=config.log_queries,
    )
    server = DnsFilterServer(engine, port=paths.dns_port())
    try:
        bound = server.start()
    except OSError as exc:
        _say(
            f"The filter could not start listening on loopback port "
            f"{paths.dns_port()} ({exc}). Another program may already "
            "be using that port on this machine."
        )
        return 1

    started = time.monotonic()

    def stats() -> dict:
        return {
            "version": __version__,
            "blocked": engine.blocked_count,
            "allowed": engine.allowed_count,
            "list_size": blocklist.size,
            "bound": [f"{host}:{port}" for host, port in server.bound_addresses],
            "uptime_s": int(time.monotonic() - started),
            "queries_logged": len(engine.query_log),
            "upstreams": list(config.upstreams),
        }

    control = ControlServer(
        control_socket_path(paths.runtime_dir()),
        proof=lambda address: server.answers_on(address),
        stats=stats,
    )
    try:
        control.start()
    except OSError as exc:
        _say(f"The control socket could not be opened ({exc}); continuing without it.")
        control = None

    where = ", ".join(f"{host}:{port}" for host, port in bound)
    _say(
        f"Sphinx {__version__} is listening on {where} with "
        f"{blocklist.size:,} domains loaded. Upstream: "
        f"{', '.join(config.upstreams)}."
    )

    stopped = threading.Event()

    def _handle(signum, frame):  # noqa: ARG001 - signal signature
        stopped.set()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    stopped.wait()

    if control is not None:
        control.stop()
    server.stop()
    _say("Sphinx stopped.")
    return 0
