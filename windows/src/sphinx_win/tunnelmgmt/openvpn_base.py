"""The OpenVPN engine interface (TUNNEL-SPEC Phase 2).

THE ROUTE — evaluated first, recorded here and in
windows/README.md:

**(a) SUPERVISE the installed ``openvpn.exe`` as a child process
— CHOSEN.** OpenVPN on Windows is a program the user installs
(the community installer or OpenVPN Connect's underlying client,
from openvpn.net — GPLv2, at arm's length: Sphinx bundles
nothing, links nothing, and ships no copy). Sphinx writes a
SANITIZED config (core.openvpn_sanitize), launches the installed
client as its own child with its own controlled flags only, and
owns the lifecycle and the state: one process — the tray host —
owns the tunnel, exactly as with the WireGuardNT embed. Routes
and the TAP/Wintun adapter need elevation, which fits the
edition's existing UAC story unchanged: Sphinx is restarted as
administrator by the user's own approval of the standard prompt,
and the child inherits that elevation.

**(b) Drive the official OpenVPNService / interactive service —
NOT chosen.** That service is a second owner of tunnel state:
it would hold the connection, its own lifecycle, and its own
idea of "connected", and Sphinx would be interrogating another
program to report its own status truthfully — the same argument
that rejected route (b) for WireGuard in Phase 1. It also
splits teardown: uninstall and quit would have to negotiate
with a service Sphinx does not own. Route (a) has none of
that, and it is workable, so (b) was not taken.

"Connected" discipline, unchanged: never from process spawn.
The engine claims an established tunnel only from the client's
own proof — the management interface reporting state CONNECTED /
SUCCESS, or the client's log line "Initialization Sequence
Completed" — and the mode model reads that proof through
``status()`` exactly as it reads WireGuard's handshake.

Licensing, stated plainly: OpenVPN is GPLv2 and it is
**invoked, never bundled** — a separate program the user
installs and Sphinx runs at arm's length. Nothing GPL is
copied, linked, or shipped by Sphinx, and no copy of OpenVPN
is ever downloaded or installed by Sphinx silently: a missing
client is an honest state with the remedy named
(OPENVPN_NOT_INSTALLED_MESSAGE).
"""
from __future__ import annotations

from typing import List, Protocol, Tuple

from .base import TunnelStatus  # re-exported shape: the mode model
# reads OpenVPN proof through the same TunnelStatus the WireGuard
# backend reports (adapter_up + a fresh "handshake" timestamp; for
# OpenVPN the timestamp is the last management/log proof time).

#: The honest missing-client state, with the remedy named. Never
#: a silent failure, never a bundled copy.
OPENVPN_NOT_INSTALLED_MESSAGE = (
    "OpenVPN isn't installed on this machine, so this OpenVPN "
    "server can't connect yet. Install OpenVPN yourself — the "
    "community installer or OpenVPN Connect, from openvpn.net — "
    "and try again. Sphinx uses the OpenVPN program you install "
    "(a separate GPLv2 program, run at arm's length); it does "
    "not bundle or download its own copy. Nothing was connected."
)


class OpenVpnManager(Protocol):
    """Drives one OpenVPN connection as a supervised child.

    Implementations must only ever be invoked through the
    controller's mode model, which owns the ordering (sanitize
    first, blocker/forwarder wiring, the tunnel record, the
    ordinary stop path back)."""

    def is_elevated(self) -> bool:
        """True when this process may create adapters and routes
        (the child inherits this process's elevation)."""
        ...

    def availability(self) -> Tuple[bool, str]:
        """(usable, reason) — the reason is plain language for
        the UI: OPENVPN_NOT_INSTALLED_MESSAGE when the client is
        not installed."""
        ...

    def up(self, profile, *, sanitized_config: str) -> None:
        """Start the client for ``profile`` with the SANITIZED
        config text (never the stored text). Returns once the
        process is started; establishment is proven through
        status(), never assumed from the spawn."""
        ...

    def down(self) -> None:
        """Stop the child Sphinx started and let the client
        remove its routes, in the client's own teardown."""
        ...

    def status(self) -> TunnelStatus:
        """The client's live truth: adapter_up while the child
        runs, a fresh proof timestamp only while the management
        interface / log proves CONNECTED, and
        exited_unexpectedly when the child died on its own."""
        ...

    def pushed_dns(self) -> List[str]:
        """The DNS servers the server pushed for this session
        (dhcp-option DNS), in push order — the mode model's
        upstream set / accepted DNS, read from the client's own
        report, never guessed."""
        ...

    @property
    def process_id(self):
        """The supervised child's pid, or None."""
        ...
