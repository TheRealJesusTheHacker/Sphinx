"""The Sphinx daemon: the filter, running as a service.

Loads the working set from the store — the downloaded lists when
they are valid, the bundled list as the floor beneath them, the
user's own rules on top — through the sanity gate: a base list
that does not parse to a real blocklist stops the daemon loudly
rather than "protecting" with a torn file. While it runs, it
watches the store's files and reloads the whole set when they
change, so `sphinx update`, rule edits, and profile switches land
in the running filter without a restart. It serves the result on
loopback and answers the control socket so the command line can
prove liveness and read real counters.

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
from typing import List, Optional, Tuple

from . import __version__, paths
from .control import ControlServer, control_socket_path
from .core.blocklist import FilterLists
from .core.forwarder import UPSTREAM_RESOLVERS, forward_query
from .core.server import DnsFilterServer, FilterEngine
from .core.store import LiveState, Store
from .core.validation import DEFAULT_MIN_DOMAINS
from .resolver.guard import DnsGuard, DnsState
from .resolver.systemview import RealSystemView, is_loopback, nameservers_in


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


class LiveLists:
    """The running filter's view of the store: the whole working
    set, reloaded when the store's files change.

    The store is edited by the command line (list updates, rule
    edits, profile switches) while the daemon runs. Reloading keys
    on a watched-file signature (mtime + size): the engine asks
    for the current lists on every query, and a changed signature
    swaps in a freshly loaded set *as one unit* — the running
    filter never sees a half-applied edit, and never needs a
    restart to see a whole one. A reload that fails (a file
    vanishing mid-edit, an unreadable list) keeps the last good
    set and says so in the journal; the daemon *start*, by
    contrast, has no last good set and refuses to run listless.
    """

    def __init__(self, store: Store):
        self._store = store
        self._lock = threading.Lock()
        self._signature: Optional[Tuple] = None
        self._state: Optional[LiveState] = None

    def _signature_now(self) -> Tuple:
        parts = []
        for path in self._store.watched_files():
            try:
                st = path.stat()
                # mtime + size alone can collide: a same-size edit
                # whose mtime is set back (utime, a restore tool, a
                # coarse timestamp) would be silently missed. The
                # store's writes are temp-and-rename, so every real
                # edit also changes the inode, and ctime — which no
                # tool can set back — moves on any write or rename.
                # Including both makes a missed edit require the
                # file to be literally the same file (Debian
                # Phase 2 audit).
                parts.append(
                    (str(path), st.st_mtime_ns, st.st_size, st.st_ino, st.st_ctime_ns)
                )
            except OSError:
                parts.append((str(path), None, None, None, None))
        return tuple(parts)

    def current(self) -> LiveState:
        """The current working set, reloading first if the store
        changed. A first-call failure propagates (the daemon
        refuses to start); a later failure keeps the last good
        set and does not retry until the files change again."""
        signature = self._signature_now()
        with self._lock:
            if self._state is not None and signature == self._signature:
                return self._state
            try:
                state = self._store.load_live()
            except Exception as exc:
                if self._state is None:
                    raise
                _say(
                    "The lists on disk could not be reloaded "
                    f"({exc}); the filter keeps running with the "
                    "lists it already has."
                )
                self._signature = signature
                return self._state
            self._state = state
            self._signature = signature
            return state

    def get(self) -> FilterLists:
        return self.current().lists


class SystemResolvers:
    """The forwarding chain's floor for the daemon: the machine's
    own DNS servers (FILTER-SPEC's forwarding chain).

    Where they come from, in order:

    - While Sphinx is engaged, the engage-time record is the
      truth — the direct stack's record holds the original
      /etc/resolv.conf (its nameservers are the floor), and the
      resolved stack's record holds the link's prior servers.
      The live files cannot supply the floor then: the direct
      file *is* the filter's loopbacks, and the link's live
      servers are the override itself.
    - While Sphinx is not engaged, the live resolver file's
      nameservers are the machine's own as they stand.

    Loopbacks never reach the chain (the chain builder refuses
    them too): on this machine a loopback "own server" is the
    filter itself or the resolved stub it replaced. Reads are
    cached on the record/resolver files' mtime+size — the
    provider is consulted per query, and a fresh engage is
    picked up without a daemon restart. Best effort throughout:
    an unreadable state yields an empty floor, never a dead
    daemon — the chain then stands on the configured upstreams
    alone.
    """

    def __init__(self, state_dir: Path, view=None):
        self._state_dir = Path(state_dir)
        self._view = view if view is not None else RealSystemView()
        self._cache_key: Optional[Tuple] = None
        self._cache: List[str] = []

    def _key(self) -> Tuple:
        parts = []
        for path in (
            self._state_dir / "dns-backup.json",
            Path("/etc/resolv.conf"),
        ):
            try:
                st = path.stat()
                parts.append((st.st_mtime_ns, st.st_size))
            except OSError:
                parts.append(None)
        return tuple(parts)

    def __call__(self) -> List[str]:
        key = self._key()
        if key == self._cache_key:
            return list(self._cache)
        servers = self._read()
        self._cache_key = key
        self._cache = servers
        return list(servers)

    def _read(self) -> List[str]:
        try:
            guard = DnsGuard(self._view, self._state_dir)
            record = guard.load_backup()
        except Exception:
            record = None
        if record is not None:
            if record.stack == "direct":
                original = record.original_resolv_conf()
                found = (
                    nameservers_in(original) if original is not None else []
                )
            else:
                found = list(record.prior_servers)
        else:
            try:
                found = nameservers_in(self._view.resolv_conf_bytes())
            except Exception:
                found = []
        # Loopbacks are dropped here as well as in the chain
        # builder: neither reader trusts the other's input.
        return [s for s in found if not is_loopback(s)]


def _resumption_note() -> Optional[str]:
    """At daemon start: if Sphinx was on (the guard's recorded
    intent) but the machine's DNS no longer points at the filter —
    the resolved stack's runtime engagement does not survive a
    reboot, and a moved default route strands it the same way —
    say so, plainly, in the journal. The daemon never re-points
    anything itself: pointing DNS is the command's job, as root,
    through the guard's prove-then-point path; this is the
    surfacing, not the acting. Best effort throughout: a machine
    whose state cannot be read gets no note, never a dead daemon.
    (`sphinx status` carries the same reconciliation for the
    user, with the same words.)"""
    try:
        guard = DnsGuard(RealSystemView(), paths.state_dir())
        intent = guard.load_intent()
        if not intent or not intent.get("engaged"):
            return None
        if guard.load_backup() is None:
            return None
        if guard.detect_state() != DnsState.LEFTOVER:
            return None
        return (
            "Sphinx was on, but this machine's DNS no longer points "
            "at the filter — a reboot or a connection change ended "
            "the engagement, and nothing was re-pointed behind your "
            "back. Run 'sudo sphinx engage' to turn Sphinx back on "
            "against the saved settings, or 'sudo sphinx restore' "
            "to put the saved settings back."
        )
    except Exception:
        return None


def run() -> int:
    """Serve until SIGTERM/SIGINT. Returns the process exit code."""
    try:
        config = DaemonConfig.load()
    except ConfigError as exc:
        _say(str(exc))
        return 2

    store = Store(paths.state_dir(), paths.list_path())
    live = LiveLists(store)
    try:
        initial = live.current()
    except OSError:
        _say(
            f"The blocklist at {paths.list_path()} cannot be read, "
            "so the filter cannot start. Reinstall the sphinx "
            "package to restore it."
        )
        return 2
    if initial.base_domains < DEFAULT_MIN_DOMAINS:
        _say(
            f"The blocklist Sphinx would run with parsed to "
            f"{initial.base_domains} domains — fewer than a real "
            "blocklist holds — so the filter cannot start: a broken "
            "list must never quietly become the protection. "
            "Reinstall the sphinx package to restore the bundled "
            "list."
        )
        return 2

    system_resolvers = SystemResolvers(paths.state_dir())

    def forward(data: bytes):
        return forward_query(
            data,
            resolvers=config.upstreams,
            system_resolvers=system_resolvers(),
        )

    engine = FilterEngine(
        lists_provider=live.get,
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
        current = live.current()
        return {
            "version": __version__,
            "blocked": engine.blocked_count,
            "allowed": engine.allowed_count,
            "list_size": current.lists.blocklist.size,
            "using_downloaded": current.using_downloaded,
            "last_updated_ms": current.last_updated_ms,
            "bound": [f"{host}:{port}" for host, port in server.bound_addresses],
            "uptime_s": int(time.monotonic() - started),
            "queries_logged": len(engine.query_log),
            "upstreams": list(config.upstreams),
            "floor": system_resolvers(),
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
    floor = system_resolvers()
    _say(
        f"Sphinx {__version__} is listening on {where} with "
        f"{initial.lists.blocklist.size:,} domains loaded. Upstream: "
        f"{', '.join(config.upstreams)}."
        + (f" Floor: {', '.join(floor)}." if floor else "")
    )
    note = _resumption_note()
    if note is not None:
        _say(note)

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
