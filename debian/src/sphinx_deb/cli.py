"""The ``sphinx`` command.

- ``sphinx serve`` — run the filter daemon (the systemd unit runs
  this; it never touches DNS settings itself).
- ``sudo sphinx engage`` — turn Sphinx on: the filter proves it
  answers, your current DNS settings are saved and verified, and
  only then is DNS pointed at the filter.
- ``sudo sphinx restore`` — turn Sphinx off: the saved settings are
  put back exactly and verified before the record is retired.
- ``sudo sphinx dismiss`` — retire a leftover saved record without
  changing any settings (after you have checked DNS yourself).
- ``sphinx status`` — the truth, from real reads: is the service
  running, is the filter answering, which lists it loaded, and does
  DNS point at it right now.

Plain language throughout: Sphinx's audience is everyone, not just
people who already know what a resolver is.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__, daemon, paths
from .control import ControlClient, control_socket_path
from .core.blocklist import Blocklist
from .resolver.guard import (
    DnsGuard,
    DnsState,
    RightsRequiredError,
    Stack,
    detect_stack,
)
from .resolver.proof import WireProofer
from .resolver.systemview import RealSystemView

EXIT_OK = 0
EXIT_REFUSED = 2


def _guard() -> DnsGuard:
    return DnsGuard(RealSystemView(), paths.state_dir())


def _cmd_serve(_args: argparse.Namespace) -> int:
    return daemon.run()


def _cmd_engage(_args: argparse.Namespace) -> int:
    try:
        result = _guard().engage(WireProofer())
    except RightsRequiredError as exc:
        print(str(exc))
        return EXIT_REFUSED
    print(result.message)
    return EXIT_OK if result.ok else EXIT_REFUSED


def _cmd_restore(_args: argparse.Namespace) -> int:
    try:
        result = _guard().disengage()
    except RightsRequiredError as exc:
        print(str(exc))
        return EXIT_REFUSED
    print(result.message)
    return EXIT_OK if result.ok else EXIT_REFUSED


def _cmd_dismiss(_args: argparse.Namespace) -> int:
    try:
        result = _guard().dismiss_leftover()
    except RightsRequiredError as exc:
        print(str(exc))
        return EXIT_REFUSED
    print(result.message)
    return EXIT_OK if result.ok else EXIT_REFUSED


_STACK_WORDS = {
    Stack.DIRECT: "a plain /etc/resolv.conf",
    Stack.RESOLVED: "systemd-resolved (standard stub setup)",
    Stack.NETWORKMANAGER: "NetworkManager",
    Stack.OTHER: "a setup Sphinx does not recognize",
}

_STATE_WORDS = {
    DnsState.ENGAGED: "points at Sphinx — the filter is on",
    DnsState.DISENGAGED: "your own settings — the filter is off",
    DnsState.LEFTOVER: (
        "your own settings, but a saved record from when Sphinx was "
        "on is still waiting — sudo sphinx restore puts the saved "
        "settings back, sudo sphinx dismiss retires the record"
    ),
    DnsState.UNKNOWN: (
        "a resolver on this machine that Sphinx has no saved record "
        "for — Sphinx will not take it over, because it cannot "
        "promise to restore settings it never saved"
    ),
}


def _installed_list_size() -> Optional[int]:
    try:
        lines = paths.list_path().read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return None
    return Blocklist.from_lines(lines).size


def _cmd_status(_args: argparse.Namespace) -> int:
    view = RealSystemView()
    guard = DnsGuard(view, paths.state_dir())
    stack = detect_stack(view)
    state = guard.detect_state()
    service = view.service_active("sphinx")
    client = ControlClient(control_socket_path(paths.runtime_dir()))
    stats = client.stats()

    print("Sphinx on this machine")
    if service is True:
        print("  Service: running (systemd)")
    elif service is False:
        print("  Service: not running")
    else:
        print("  Service: systemd is not available to ask on this machine")
    if stats is not None:
        bound = ", ".join(stats.get("bound", [])) or "no loopback"
        print(
            f"  Filter: answering on {bound} — "
            f"{stats.get('list_size', 0):,} domains loaded"
        )
        print(
            f"  Questions since the service started: "
            f"{stats.get('blocked', 0):,} blocked, "
            f"{stats.get('allowed', 0):,} let through"
        )
    elif service is True and client.last_error == "permission":
        # The daemon is up (systemd says so) but its control socket
        # is mode 0660 for the daemon's user/group and root — an
        # unprivileged status cannot read the counters, and must not
        # report a running filter as "not answering". (Debian
        # Phase 1 audit, finding 3.)
        print(
            "  Filter: running — but its counters live on a control "
            "socket only root and the sphinx group can read. Run "
            "'sudo sphinx status' for the counters."
        )
    elif service is True:
        print(
            "  Filter: the service is running but is not answering "
            "its control socket, so its counters cannot be read."
        )
    else:
        size = _installed_list_size()
        if size is not None:
            print(
                f"  Filter: not answering (the service is not "
                f"running). The installed blocklist holds {size:,} "
                "domains."
            )
        else:
            print(
                "  Filter: not answering (the service is not "
                "running), and the blocklist file is missing."
            )
    print(f"  DNS right now: {_STATE_WORDS[state]}")
    print(f"  Resolver setup: {_STACK_WORDS[stack]}")
    intent = guard.load_intent()
    if intent is not None:
        print(
            "  Recorded decision: "
            + ("on" if intent.get("engaged") else "off")
            + " (written at the last change Sphinx verified)"
        )
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sphinx",
        description=(
            "Sphinx — every request gets questioned. A free, "
            "system-wide ad and tracker blocker from Sentinel "
            "Safeguard."
        ),
    )
    parser.add_argument("--version", action="version", version=f"sphinx {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="run the filter daemon (used by the systemd service)")
    sub.add_parser("engage", help="turn Sphinx on (needs sudo)")
    sub.add_parser("restore", help="turn Sphinx off and put your DNS settings back (needs sudo)")
    sub.add_parser("dismiss", help="retire a leftover saved DNS record without changing settings (needs sudo)")
    sub.add_parser("status", help="show what Sphinx is really doing right now")
    args = parser.parse_args(argv)
    handlers = {
        "serve": _cmd_serve,
        "engage": _cmd_engage,
        "restore": _cmd_restore,
        "dismiss": _cmd_dismiss,
        "status": _cmd_status,
    }
    handler = handlers.get(args.command or "")
    if handler is None:
        parser.print_help()
        return EXIT_REFUSED
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
