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

import socket
import threading
import time
from dataclasses import dataclass
from enum import Enum
from functools import partial
from pathlib import Path
from typing import Callable, List, Optional

from ..core.forwarder import Forwarder, forward_query
from ..core.querylog import QueryLog
from ..core.server import DnsFilterServer, FilterEngine
from ..core.store import Store
from ..core.tunnel import (
    OPENVPN_PHASE2_MESSAGE,
    TunnelRefusal,
    endpoint_host,
    endpoint_port,
    is_ip_literal,
)
from ..core.tunnelstore import TunnelState, TunnelStore, TunnelStoreError
from ..dnsmgmt.base import AdapterDns, DnsManager, NotElevatedError
from ..dnsmgmt.guard import DnsGuard, DnsState
from ..tunnelmgmt.base import TunnelError, TunnelManager, TunnelNotElevated


class StartError(RuntimeError):
    pass


class SphinxMode(Enum):
    """The TUNNEL-SPEC mode model: four modes, stated plainly."""

    OFF = "off"
    BLOCKER_ONLY = "blocker-only"
    VPN_ONLY = "vpn-only"
    VPN_BLOCKER = "vpn+blocker"


@dataclass
class VpnStatus:
    """The tunnel's truth, read from the backend — never from
    intent or configuration. ``connected`` is True only on a
    fresh handshake; ``blocked`` is the kill-switch state."""

    active: bool = False
    connected: bool = False
    blocked: bool = False
    leftover: bool = False
    profile_name: Optional[str] = None
    with_blocker: bool = False
    message: str = "VPN is off."
    rx_bytes: int = 0
    tx_bytes: int = 0


def _default_resolver(host: str) -> str:
    """Resolve a hostname with the machine's own resolver — the
    pre-tunnel resolver, called BEFORE the tunnel engages."""
    return socket.gethostbyname(host)


class SphinxController:
    def __init__(
        self,
        store: Store,
        manager: DnsManager,
        data_dir: Path,
        server_factory=None,
        tunnel_manager: Optional[TunnelManager] = None,
        tunnel_store: Optional[TunnelStore] = None,
        resolver: Optional[Callable[[str], str]] = None,
        vpn_forwarder_factory: Optional[Callable[[List[str]], Forwarder]] = None,
        handshake_wait_s: float = 5.0,
    ):
        self.store = store
        self._dns_manager = manager
        self.guard = DnsGuard(manager, Path(data_dir))
        # --- VPN mode (TUNNEL-SPEC) --------------------------------
        # The tunnel manager is injectable exactly like the DNS
        # server factory: production builds the WireGuardNT-backed
        # manager, tests drive the mode model over the fake. The
        # tunnel state record is a PARALLEL record in the same data
        # folder — the DNS backup contract is untouched by it.
        self._tunnel_manager = tunnel_manager
        self.tunnel_store = tunnel_store or TunnelStore(Path(data_dir))
        self._resolver = resolver or _default_resolver
        self._vpn_forwarder_factory = vpn_forwarder_factory or (
            lambda dns_servers: partial(
                forward_query, resolvers=tuple(dns_servers)
            )
        )
        self._handshake_wait_s = handshake_wait_s
        self._default_forwarder = forward_query
        self._vpn_active = False
        self._vpn_profile_name: Optional[str] = None
        # Injectable so the orchestration is testable without binding
        # port 53; production uses the real loopback server.
        self._server_factory = server_factory or (
            lambda engine: DnsFilterServer(engine)
        )
        self._lists_lock = threading.Lock()
        self._lists = store.load_effective_lists()
        self.engine = FilterEngine(
            self._current_lists, query_log=QueryLog()
        )
        self.engine.log_enabled = store.query_log_enabled()
        self.server: Optional[DnsFilterServer] = None
        self.running = False

    # --- Lists -------------------------------------------------------

    def _current_lists(self):
        with self._lists_lock:
            return self._lists

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

    # --- VPN mode (TUNNEL-SPEC) -------------------------------------
    #
    # The mode model. The blocker paths above are untouched: the
    # filter's only action remains the DNS decision (listed names
    # sinkhole locally and immediately; unlisted names resolve
    # normally and their traffic passes untouched). VPN mode adds
    # a tunnel AROUND that, never a new kind of blocking — the
    # only blocked state in any tunnel mode is the kill switch on
    # tunnel failure, and it always announces itself with the
    # intentional-disconnect choice.

    def current_mode(self) -> SphinxMode:
        if self._vpn_active:
            return SphinxMode.VPN_BLOCKER if self._vpn_with_blocker() else SphinxMode.VPN_ONLY
        return SphinxMode.BLOCKER_ONLY if self.running else SphinxMode.OFF

    def _vpn_with_blocker(self) -> bool:
        try:
            state = self.tunnel_store.load_state()
        except TunnelStoreError:
            return False
        return bool(state and state.with_blocker)

    def vpn_active(self) -> bool:
        return self._vpn_active

    def tunnel_leftover(self) -> bool:
        """A tunnel state record exists but this process holds no
        live tunnel: a leftover. It is surfaced and waits for the
        user — never silently taken over, never silently dropped
        (TUNNEL-SPEC's resumption discipline)."""
        if self._vpn_active:
            return False
        try:
            return self.tunnel_store.load_state() is not None
        except TunnelStoreError:
            return True  # an unreadable record is surfaced, not hidden

    def connect_vpn(self, profile_name: str, *, with_blocker: bool) -> str:
        """Connect a server profile, per the mode model:

        1. The profile is read and its protocol checked (OpenVPN
           is refused at connect with the reason named — Phase 1).
        2. A second tunnel disconnects the first through the
           ordinary stop path first — one tunnel at a time.
        3. The endpoint is resolved BEFORE anything engages, with
           the pre-tunnel resolver, and that answer is pinned for
           the session.
        4. VPN + Blocker: the blocker runs (started if needed) and
           its forwarder's upstreams become the profile's DNS
           servers, reached through the tunnel. VPN only: the
           blocker does not run; if the profile names DNS servers,
           the machine's DNS is pointed at them as TUNNEL-record
           state (saved first, verified, restored exactly — the
           DNS guard's backup is never touched by this path).
        5. Connected is claimed only on a fresh handshake.
        """
        if self._tunnel_manager is None:
            raise StartError(
                "VPN mode is not available in this build of Sphinx."
            )
        profile = self.tunnel_store.get_profile(profile_name)
        if profile is None:
            raise StartError(f"No saved server named {profile_name!r}.")
        if profile.protocol == "openvpn":
            raise StartError(OPENVPN_PHASE2_MESSAGE)
        if profile.endpoint is None:
            raise StartError(
                "This profile names no endpoint, so there is no "
                "server to connect to. Nothing was changed."
            )
        available, reason = self._tunnel_manager.availability()
        if not available:
            raise StartError(reason)
        if not self._tunnel_manager.is_elevated():
            raise TunnelNotElevated(
                "Connecting a VPN needs administrator rights: "
                "Windows will ask with its standard prompt when "
                "Sphinx is restarted as administrator (the window "
                "and tray offer that action). If you decline the "
                "prompt, Sphinx stays off and does not ask again in "
                "a loop. Nothing was changed."
            )
        if self._vpn_active:
            if self._vpn_profile_name == profile_name:
                return f"VPN is already connected to {profile_name}."
            self.disconnect_vpn()  # one tunnel at a time, ordinary path

        host = endpoint_host(profile.endpoint)
        port = endpoint_port(profile.endpoint)
        # Resolve BEFORE engaging, and pin: the tunnel cannot
        # resolve its own doorway from inside itself. A failure
        # here is a connect failure, surfaced — nothing engaged.
        try:
            pinned_ip = host if is_ip_literal(host) else self._resolver(host)
        except Exception as e:
            raise StartError(
                f"Sphinx could not resolve {host} before connecting "
                f"({e}). Nothing was changed."
            ) from e

        mode_before = "blocker" if self.running else "off"
        state = TunnelState(
            profile_name=profile_name,
            mode_before_vpn=mode_before,
            with_blocker=with_blocker,
            intent=False,
            pinned_endpoint=f"{pinned_ip}:{port}",
        )
        blocker_started_here = False
        blocker_stopped_here = False
        try:
            if with_blocker:
                if not self.running:
                    self.start()
                    blocker_started_here = True
                if profile.dns:
                    # The forwarder is replaced WHOLE with the
                    # honest fallback chain over the profile's
                    # DNS servers (forward_query tries each in
                    # turn): an unlisted name must fail only when
                    # every one of them genuinely fails, and that
                    # failure is the upstream's, surfaced by
                    # vpn_status — never a silent swallow. Blocked
                    # names never reach the forwarder at all.
                    self.engine.set_forwarder(
                        self._vpn_forwarder_factory(list(profile.dns))
                    )
            else:
                if self.running:
                    # VPN ONLY means the brain is not in the path —
                    # a blocker left running underneath would make
                    # the mode's own statement ("DNS is
                    # unfiltered") a lie. The blocker stops through
                    # its ordinary path (DNS restored by the
                    # guard); disconnect restarts it to return to
                    # Blocker only, per mode_before.
                    self.stop()
                    blocker_stopped_here = True
                if profile.dns:
                    self._engage_tunnel_dns(profile, state)
            # The record lands BEFORE the tunnel moves (save-first,
            # like the DNS discipline): a crash mid-connect leaves
            # a record the next start surfaces, not a mystery.
            self.tunnel_store.save_state(state)
            self._tunnel_manager.up(
                profile, endpoint_ip=pinned_ip, endpoint_port=port
            )
        except TunnelNotElevated:
            self._undo_failed_connect(state, blocker_started_here, blocker_stopped_here)
            raise
        except Exception as e:
            self._undo_failed_connect(state, blocker_started_here, blocker_stopped_here)
            if isinstance(e, StartError):
                raise
            raise StartError(
                f"The VPN could not be started ({e}). Nothing is "
                "left half-connected."
            ) from e
        state.intent = True
        try:
            self.tunnel_store.save_state(state)
        except TunnelStoreError:
            pass  # the live state is in memory; the record is retried at disconnect
        self._vpn_active = True
        self._vpn_profile_name = profile_name
        status = self._await_handshake()
        if status.connected:
            return status.message
        # Engaged but no fresh handshake: the kill-switch state,
        # stated plainly — NOT a failure that quietly unwraps to a
        # direct connection.
        return status.message

    def _undo_failed_connect(
        self,
        state: TunnelState,
        blocker_started_here: bool,
        blocker_stopped_here: bool = False,
    ) -> None:
        """Roll a failed connect back to the pre-VPN mode. The
        tunnel never engaged in these paths (up() failed), so what
        may exist is: the state record, tunnel-DNS changes, and a
        blocker started — or stopped — for the occasion."""
        if state.dns_originals:
            try:
                self._restore_tunnel_dns(state)
            except Exception:
                pass  # the record stays, and says a restore is owed
            else:
                state.dns_originals = []
        if not state.dns_originals:
            self.tunnel_store.clear_state()
        self.engine.set_forwarder(self._default_forwarder)
        if blocker_started_here and self.running:
            try:
                self.stop()
            except Exception:
                pass
        if blocker_stopped_here and not self.running:
            try:
                self.start()
            except Exception:
                pass

    def _await_handshake(self) -> "VpnStatus":
        deadline = time.monotonic() + self._handshake_wait_s
        while True:
            status = self.vpn_status()
            if status.connected or time.monotonic() >= deadline:
                return status
            time.sleep(0.05)

    def disconnect_vpn(self) -> str:
        """The ordinary stop path back to the pre-VPN mode, in the
        spec's order: tunnel down first, then the DNS restore."""
        if not self._vpn_active and not self.tunnel_leftover():
            return "VPN is already off."
        try:
            state = self.tunnel_store.load_state()
        except TunnelStoreError as e:
            raise StartError(str(e)) from e
        # 1. Tunnel down first.
        if self._tunnel_manager is not None:
            try:
                self._tunnel_manager.down()
            except Exception as e:
                raise StartError(
                    f"The tunnel could not be taken down ({e}). It "
                    "was left as it is rather than half-stopped."
                ) from e
        self._vpn_active = False
        self._vpn_profile_name = None
        # 2. DNS restore: the tunnel record's own originals (VPN
        # only), exactly, verified adapter by adapter.
        if state is not None and state.dns_originals:
            self._restore_tunnel_dns(state)  # raises, keeping the record
        # 3. The blocker leg returns to the pre-VPN mode.
        self.engine.set_forwarder(self._default_forwarder)
        if state is not None and state.with_blocker and state.mode_before_vpn == "off":
            if self.running:
                self.stop()
        if (
            state is not None
            and not state.with_blocker
            and state.mode_before_vpn == "blocker"
            and not self.running
        ):
            # VPN-only stopped the blocker on the way in (see
            # connect_vpn); returning to Blocker only means
            # starting it again, through the ordinary path. A
            # failure here is loud — it raises before the record
            # is retired, so the session surfaces as a leftover
            # with the reason, never as a silent half-return.
            self.start()
        self.tunnel_store.clear_state()
        return "VPN is off."

    def reconnect_vpn(self) -> str:
        """Reconnect the active (or kill-switched) profile: down
        through the stop path's tunnel leg, then connect again —
        the endpoint is re-resolved while the tunnel is DOWN,
        i.e. with the pre-tunnel resolver, and re-pinned."""
        try:
            state = self.tunnel_store.load_state()
        except TunnelStoreError as e:
            raise StartError(str(e)) from e
        if state is None:
            raise StartError("No VPN session to reconnect.")
        name, with_blocker = state.profile_name, state.with_blocker
        self.disconnect_vpn()
        # Disconnect restored the pre-VPN blocker mode; the fresh
        # connect measures its own pre-mode from that same state.
        return self.connect_vpn(name, with_blocker=with_blocker)

    def vpn_status(self) -> VpnStatus:
        if self._tunnel_manager is None:
            return VpnStatus(message="VPN mode is not available in this build.")
        try:
            state = self.tunnel_store.load_state()
        except TunnelStoreError as e:
            return VpnStatus(leftover=True, message=str(e))
        backend = self._tunnel_manager.status()
        if not self._vpn_active:
            if state is not None:
                return VpnStatus(
                    leftover=True,
                    profile_name=state.profile_name,
                    message=(
                        "A VPN session record from an earlier run "
                        f"({state.profile_name}) was found, but no "
                        "tunnel is running in this Sphinx. Nothing "
                        "was taken over or dropped silently: "
                        "reconnect it, or disconnect to clear the "
                        "record and restore what it holds."
                    ),
                )
            return VpnStatus(message="VPN is off.")
        name = self._vpn_profile_name or (state.profile_name if state else None)
        with_blocker = bool(state and state.with_blocker)
        if backend.adapter_up and backend.handshake_fresh():
            facts = f"VPN on — {name}."
            if with_blocker:
                facts += " Ad blocking on."
            else:
                facts += (
                    " Ads are not blocked in this mode: DNS is "
                    "unfiltered while VPN-only is on."
                )
            return VpnStatus(
                active=True,
                connected=True,
                profile_name=name,
                with_blocker=with_blocker,
                message=facts,
                rx_bytes=backend.rx_bytes,
                tx_bytes=backend.tx_bytes,
            )
        # The kill-switch state, in plain language, with the two
        # visible choices. Covered traffic blocks; it never falls
        # back to the direct route.
        return VpnStatus(
            active=True,
            blocked=True,
            profile_name=name,
            with_blocker=with_blocker,
            message=(
                "VPN disconnected — traffic is blocked, not going "
                "around the tunnel. The server did not answer with "
                "a fresh handshake, so Sphinx is not claiming a "
                "connection. Reconnect, or disconnect intentionally "
                "to return to the mode you had before the VPN."
            ),
            rx_bytes=backend.rx_bytes,
            tx_bytes=backend.tx_bytes,
        )

    # --- VPN-only DNS (tunnel-record state, never the DNS backup) -----

    def _engage_tunnel_dns(self, profile, state: TunnelState) -> None:
        """Point the machine's DNS at the profile's servers, for
        VPN-only mode. The originals are saved into the TUNNEL
        state record and read back before anything changes; the
        DNS guard's dns-backup.json is not involved in any way."""
        manager = self._dns_manager
        adapters = manager.active_adapters()
        if not adapters:
            raise StartError(
                "No active network adapter was found, so there is "
                "nowhere to point DNS for the VPN. Nothing changed."
            )
        originals = [a.to_dict() for a in adapters]
        state.dns_originals = originals
        state.dns_applied = list(profile.dns)
        # Save first, verified (save_state reads back): no
        # verified record of the originals, no change.
        self.tunnel_store.save_state(state)
        v4 = [d for d in profile.dns if ":" not in d]
        v6 = [d for d in profile.dns if ":" in d]
        changed: List[AdapterDns] = []
        try:
            for adapter in adapters:
                wanted = v4 if adapter.family == "IPv4" else v6
                if not wanted:
                    continue
                manager.set_dns(adapter.interface_alias, adapter.family, wanted)
                if manager.get_dns(adapter.interface_alias, adapter.family) != wanted:
                    raise StartError(
                        f"DNS on {adapter.interface_alias} "
                        f"({adapter.family}) did not verify after "
                        "the change; everything was restored."
                    )
                changed.append(adapter)
        except Exception:
            self._restore_tunnel_dns_quietly(state)
            state.dns_originals = []
            self.tunnel_store.clear_state()
            raise

    def _restore_tunnel_dns_quietly(self, state: TunnelState) -> None:
        try:
            self._restore_tunnel_dns(state)
        except Exception:
            pass

    def _restore_tunnel_dns(self, state: TunnelState) -> None:
        """Restore the tunnel record's saved DNS settings exactly,
        verifying each; any failure raises and the record stays —
        a restore still owed is never hidden."""
        manager = self._dns_manager
        failed = []
        for raw in state.dns_originals:
            adapter = AdapterDns.from_dict(raw)
            try:
                manager.set_dns(
                    adapter.interface_alias, adapter.family, list(adapter.servers)
                )
                if manager.get_dns(adapter.interface_alias, adapter.family) != list(
                    adapter.servers
                ):
                    failed.append(adapter)
            except Exception:
                failed.append(adapter)
        if failed:
            names = ", ".join(
                f"{a.interface_alias} ({a.family})" for a in failed
            )
            raise StartError(
                f"DNS could not be verified as restored on: {names}. "
                "The tunnel record was kept — disconnect again to "
                "retry the restore."
            )
