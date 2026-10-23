"""App orchestration, free of any UI toolkit: owns the store, the
filter engine, the DNS server, and the DNS guard, and sequences
start/stop so the machine is never left pointing at a resolver that
isn't answering.

Start order (each step verified before the next):
  1. Start the loopback DNS server.
  2. Prove it answers on every loopback it bound.
  3. Engage DNS (the guard saves + verifies the original settings
     before changing anything, and verifies every change).
If anything after step 1 fails, the server is stopped again — DNS
was either never moved or is restored by the guard's rollback.

Stop order is the mirror: restore DNS first, and only stop the
server once the restore verifies. If the restore fails, the filter
keeps running and the failure is reported — a live filter with a
restore still owed beats a dead resolver.

The controller also records the user's protection intent in the
store at every successful start, stop, and leftover resolution —
the fact the tray host's start-at-sign-in logic honors (Windows
Phase 2), mirroring the Android edition's recorded intent. A failed
start or stop records nothing: the intent stays whatever the last
*successful* transition made it.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from ..core.forwarder import forward_query
from ..core.querylog import QueryLog
from ..core.server import DnsFilterServer, FilterEngine
from ..core.store import Store
from ..dnsmgmt.base import DnsManager, NotElevatedError
from ..dnsmgmt.guard import DnsGuard, DnsState


class StartError(RuntimeError):
    pass


class SphinxController:
    def __init__(
        self,
        store: Store,
        manager: DnsManager,
        data_dir: Path,
        server_factory=None,
    ):
        self.store = store
        self.guard = DnsGuard(manager, Path(data_dir))
        # Injectable so the orchestration is testable without binding
        # port 53; production uses the real loopback server.
        self._server_factory = server_factory or (
            lambda engine: DnsFilterServer(engine)
        )
        self._lists_lock = threading.Lock()
        self._lists = store.load_effective_lists()
        self.engine = FilterEngine(
            self._current_lists,
            forwarder=self._forward,
            query_log=QueryLog(),
        )
        self.engine.log_enabled = store.query_log_enabled()
        self.server: Optional[DnsFilterServer] = None
        self.running = False

    # --- Lists -------------------------------------------------------

    def _current_lists(self):
        with self._lists_lock:
            return self._lists

    def _forward(self, data: bytes):
        """Forward one allowed query along the spec's chain: the
        public resolvers, then the machine's own DNS as the floor —
        the servers captured at engage time and held by the guard
        (empty when Sphinx is not engaged, when the floor degrades
        to the publics alone). Read per query through the guard's
        cache, so a floor captured by a later engage is picked up
        without rebuilding the engine."""
        return forward_query(data, system_resolvers=self.guard.load_floor())

    def reload_lists(self):
        """Re-read every list input from the store and swap the
        engine's set atomically. One call applies ALL state — the
        Android Phase 4 audit lesson (a restart that only applied
        part of the state left the old rules running indefinitely).
        """
        new_lists = self.store.load_effective_lists()
        with self._lists_lock:
            self._lists = new_lists
        return new_lists

    def set_log_enabled(self, enabled: bool) -> None:
        self.store.set_query_log_enabled(enabled)
        self.engine.log_enabled = enabled
        # Turning recording off does NOT erase the existing log:
        # "off" and "clear" are separate controls (FILTER-SPEC's
        # counting/log rules; the Android edition's audited behavior
        # is the same). The Clear button is the only eraser.

    # --- Lifecycle -----------------------------------------------------

    def start(self) -> str:
        if self.running:
            return "Sphinx is already on."
        if self.guard.detect_state() is DnsState.UNKNOWN:
            raise StartError(
                "DNS already points at a loopback resolver, but Sphinx "
                "has no saved copy of the previous settings, so it will "
                "not take over settings it cannot restore. Set DNS "
                "back to automatic (DHCP) in Windows settings, then "
                "start Sphinx."
            )
        server = self._server_factory(self.engine)
        try:
            bound = server.start()
        except OSError as e:
            raise StartError(
                f"Sphinx could not start its DNS filter on port 53 "
                f"({e}). Another program may already use that port."
            ) from e
        try:
            for address, _port in bound:
                if not server.answers_on(address):
                    raise StartError(
                        "The filter started but did not answer on "
                        f"{address}, so DNS was left unchanged."
                    )
            # Engage only the loopbacks just proven to answer: a
            # family the server could not bind (IPv6 is best-effort)
            # is recorded in the backup but its DNS is left alone —
            # the machine is never aimed at a resolver that isn't
            # answering.
            result = self.guard.engage(
                only_loopbacks={address for address, _port in bound}
            )
        except NotElevatedError:
            server.stop()
            raise
        except Exception:
            server.stop()
            raise
        if not result.ok:
            server.stop()
            raise StartError(result.message)
        self.server = server
        self.running = True
        self.store.set_protection_intent(True)
        return result.message

    def stop(self) -> str:
        try:
            result = self.guard.disengage()
        except NotElevatedError:
            raise
        if not result.ok:
            # The restore didn't verify: keep the filter running so
            # the machine keeps a working resolver, and say so.
            raise StartError(
                result.message
                + " The filter was left running so your DNS keeps working."
            )
        if self.server is not None:
            self.server.stop()
            self.server = None
        self.running = False
        self.store.set_protection_intent(False)
        return result.message

    def restore_dns(self) -> str:
        """Restore saved DNS settings without any server involvement
        (the leftover path: Sphinx isn't filtering, but it holds the
        machine's previous settings)."""
        result = self.guard.disengage()
        if not result.ok:
            raise StartError(result.message)
        self.store.set_protection_intent(False)
        return result.message

    def dismiss_leftover(self) -> bool:
        """Dismiss a leftover backup at the user's say-so (they have
        checked the current settings themselves). Changes no
        settings; records that protection is off by the user's own
        action, so a later sign-in does not resurrect an engagement
        the user has already dealt with."""
        dismissed = self.guard.dismiss_leftover()
        if dismissed:
            self.store.set_protection_intent(False)
        return dismissed

    def dns_state(self) -> DnsState:
        return self.guard.detect_state()
