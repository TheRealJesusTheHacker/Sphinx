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
- ``sudo sphinx update`` — download fresh blocklists from the
  sources Sphinx shows, under the spec's update rules (HTTPS only,
  sanity gate, atomic swap). Manual only: nothing fetches in the
  background, ever.
- ``sudo sphinx allow add example.com`` / ``sphinx block add …`` —
  your own rules: names never to block, names always to block.
  Edits land in the running filter on their own.
- ``sphinx profile …`` — named sets of those rules, switchable as
  a whole; profiles never change which blocklists are in force.

Plain language throughout: Sphinx's audience is everyone, not just
people who already know what a resolver is.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime
from typing import List, Optional

from . import __version__, daemon, paths
from .control import ControlClient, control_socket_path
from .core.blocklist import Blocklist, normalize_entry
from .core.store import Store
from .core.updater import ListUpdater
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


def _store() -> Store:
    return Store(paths.state_dir(), paths.list_path())


def _is_root() -> bool:
    return os.geteuid() == 0


def _root_refusal(what: str, command: str) -> int:
    print(
        f"{what} changes Sphinx's stored state, which belongs to "
        f"the system. Run it with sudo: sudo sphinx {command} — "
        "nothing was changed."
    )
    return EXIT_REFUSED


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


def _cmd_update(_args: argparse.Namespace) -> int:
    if not _is_root():
        return _root_refusal("Updating the blocklists", "update")
    store = _store()
    sources = store.sources()
    print("Downloading the blocklists Sphinx uses:")
    for source in sources:
        print(f"  {source.name}\n    {source.url}")
    result = ListUpdater(store).update_all(int(time.time() * 1000))
    for outcome in result.outcomes:
        if outcome.refreshed:
            print(f"  {outcome.source.name}: {outcome.domains:,} domains.")
        else:
            print(f"  {outcome.source.name}: FAILED — {outcome.note}.")
    if not result.success:
        print(
            "The update did not complete, so nothing was changed: "
            "every source keeps the copy it had, the lists the "
            "filter is running with are exactly what they were, and "
            "the last-updated time did not move."
        )
        return EXIT_REFUSED
    print(
        f"Lists updated: {result.total_domains:,} domains in force. "
        "The running filter picks the new lists up on its own — no "
        "restart needed."
    )
    return EXIT_OK


#: The two user-rule kinds share one shape; they differ in words.
_RULE_KINDS = {
    "allow": ("allowlist", "never blocked"),
    "block": ("custom block list", "always blocked"),
}


def _rule_entries(store: Store, kind: str) -> List[str]:
    return store.allowlist_entries() if kind == "allow" else store.custom_block_entries()


def _save_rule_entries(store: Store, kind: str, entries: List[str]) -> None:
    if kind == "allow":
        store.save_allowlist(entries)
    else:
        store.save_custom_block_entries(entries)


def _cmd_rule(args: argparse.Namespace) -> int:
    kind = args.rule_kind
    noun, _effect = _RULE_KINDS[kind]
    if args.action is None:
        print(
            f"Say what to do: sphinx {kind} list, sphinx {kind} "
            f"add <domain>, or sphinx {kind} remove <domain>."
        )
        return EXIT_REFUSED
    store = _store()
    if args.action == "list":
        entries = _rule_entries(store, kind)
        if not entries:
            print(f"Your {noun} is empty.")
        else:
            print(f"Your {noun} ({len(entries)}):")
            for entry in entries:
                print(f"  {entry}")
        return EXIT_OK
    if not _is_root():
        return _root_refusal(
            f"Editing your {noun}", f"{kind} {args.action} {args.domain or ''}".strip()
        )
    entry = normalize_entry(args.domain or "")
    if entry is None:
        print(
            f"'{args.domain}' cannot be an entry: entries are domain "
            "names with at least two parts (like example.com) — not "
            "a single word, not an IP address, and not one of the "
            "reserved names for this machine itself. Nothing was "
            "changed."
        )
        return EXIT_REFUSED
    entries = _rule_entries(store, kind)
    if args.action == "add":
        if entry in entries:
            print(f"{entry} is already on your {noun} — nothing changed.")
            return EXIT_OK
        _save_rule_entries(store, kind, entries + [entry])
        print(
            f"{entry} added to your {noun}. The running filter uses "
            "it from the next question it answers."
        )
        return EXIT_OK
    # remove
    if entry not in entries:
        print(f"{entry} is not on your {noun} — nothing changed.")
        return EXIT_OK
    _save_rule_entries(store, kind, [e for e in entries if e != entry])
    print(
        f"{entry} removed from your {noun}. The running filter uses "
        "the change from the next question it answers."
    )
    return EXIT_OK


def _cmd_profile(args: argparse.Namespace) -> int:
    if args.action is None:
        print(
            "Say what to do: sphinx profile list, sphinx profile "
            "save <name>, sphinx profile use <name>, or sphinx "
            "profile delete <name>."
        )
        return EXIT_REFUSED
    store = _store()
    if args.action == "list":
        profile_set = store.load_profile_set()
        live = store.snapshot_live_state()
        if profile_set.is_empty:
            print("No profiles saved yet.")
        else:
            print("Profiles:")
            for profile in profile_set.profiles:
                marker = "*" if profile.name == profile_set.active_name else " "
                state = profile.state
                print(
                    f"  {marker} {profile.name} — "
                    f"{len(state.allowlist_entries)} allowed, "
                    f"{len(state.custom_block_entries)} blocked by you"
                )
        if profile_set.active_name:
            print(f"Your live rules are under the profile '{profile_set.active_name}'.")
        else:
            print("Your live rules are not under a profile.")
        print(
            f"Live rules right now: {len(live.allowlist_entries)} "
            f"allowed, {len(live.custom_block_entries)} blocked by you."
        )
        return EXIT_OK
    if not _is_root():
        return _root_refusal(
            "Changing profiles", f"profile {args.action} {args.name or ''}".strip()
        )
    name = (args.name or "").strip()
    if args.action == "save":
        updated = store.create_profile(name)
        if updated is None:
            existing = store.load_profile_set().profile(name)
            if existing is not None:
                print(
                    f"A profile called '{name}' already exists — "
                    "nothing was saved over it. Delete it first "
                    f"(sudo sphinx profile delete {name}) if you want "
                    "to replace it."
                )
            else:
                print(
                    f"'{args.name}' cannot be a profile name: names "
                    "are 1–40 characters, with no control characters. "
                    "Nothing was changed."
                )
            return EXIT_REFUSED
        print(
            f"Profile '{name}' saved from your rules as they are "
            "now, and it is the active profile: edits to your rules "
            "are written into it as you make them."
        )
        return EXIT_OK
    if args.action == "use":
        if not store.switch_profile(name):
            print(f"There is no profile called '{name}' — nothing changed.")
            return EXIT_REFUSED
        print(
            f"Profile '{name}' is now in force. Profiles change only "
            "your own rules — which blocklists Sphinx questions with "
            "is unchanged — and the running filter uses the new rules "
            "from the next question it answers."
        )
        return EXIT_OK
    # delete
    if not store.delete_profile(name):
        print(f"There is no profile called '{name}' — nothing changed.")
        return EXIT_REFUSED
    print(
        f"Profile '{name}' deleted. Your live rules are exactly as "
        "they were — deleting a profile never changes the rules in "
        "force."
    )
    return EXIT_OK


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
    """The size of the blocklist the daemon would run with: the
    downloaded lists when they are valid, the bundled list
    otherwise (the store's own choosing, so status and the daemon
    never disagree about which list is 'the' list)."""
    try:
        return _store().status().active_domains
    except Exception:
        pass
    try:
        lines = paths.list_path().read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return None
    return Blocklist.from_lines(lines).size


def _lists_line(stats: Optional[dict]) -> str:
    """Which lists are in force, in plain words: the downloaded set
    (and when it was fetched) or the bundled floor."""
    using_downloaded = stats.get("using_downloaded") if stats else None
    last_updated_ms = stats.get("last_updated_ms") if stats else None
    if using_downloaded is None:
        try:
            status = _store().status()
            using_downloaded = status.using_downloaded
            last_updated_ms = status.last_updated_ms
        except Exception:
            return "  Lists: could not be read from Sphinx's state directory."
    if using_downloaded:
        when = "an unknown time"
        if last_updated_ms:
            when = datetime.fromtimestamp(last_updated_ms / 1000).strftime(
                "%Y-%m-%d %H:%M"
            )
        return (
            f"  Lists: the downloaded lists, last updated {when} "
            "(sudo sphinx update refreshes them)."
        )
    return (
        "  Lists: the bundled list that ships with Sphinx — no "
        "downloaded update yet (sudo sphinx update fetches fresh "
        "lists)."
    )


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
    print(_lists_line(stats))
    print(f"  DNS right now: {_STATE_WORDS[state]}")
    print(f"  Resolver setup: {_STACK_WORDS[stack]}")
    intent = guard.load_intent()
    if intent is not None:
        print(
            "  Recorded decision: "
            + ("on" if intent.get("engaged") else "off")
            + " (written at the last change Sphinx verified)"
        )
    if state == DnsState.LEFTOVER and intent is not None and intent.get("engaged"):
        # The resumption reconciliation (Phase 2): protection was
        # on and a record exists, but the live path no longer
        # points at the filter — the resolved engagement is runtime
        # state, ended by a reboot or a route change. Nothing is
        # re-pointed from here: the user chooses, and `engage`
        # performs the re-engage through the guard's ordinary
        # prove-then-point path. (The daemon's journal carries the
        # same note at service start.)
        print(
            "  Sphinx was on when this machine's network changed "
            "(a reboot, or a different connection taking over), and "
            "nothing was re-pointed behind your back. To turn it "
            "back on against the saved settings: sudo sphinx "
            "engage. To finish turning it off instead: sudo sphinx "
            "restore."
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
    sub.add_parser(
        "update",
        help="download fresh blocklists from Sphinx's sources (needs sudo; manual only — nothing fetches in the background)",
    )
    for kind, blurb in (
        ("allow", "names Sphinx must never block"),
        ("block", "names Sphinx must always block"),
    ):
        rule_parser = sub.add_parser(kind, help=f"your own rules: {blurb}")
        rule_parser.set_defaults(rule_kind=kind)
        rule_sub = rule_parser.add_subparsers(dest="action")
        rule_sub.add_parser("list", help=f"show your {kind} rules")
        for action in ("add", "remove"):
            action_parser = rule_sub.add_parser(
                action, help=f"{action} a name {'to' if action == 'add' else 'from'} your {kind} rules (needs sudo)"
            )
            action_parser.add_argument("domain", help="the domain name, like example.com")
    profile_parser = sub.add_parser(
        "profile", help="named sets of your allow/block rules, switchable as a whole"
    )
    profile_sub = profile_parser.add_subparsers(dest="action")
    profile_sub.add_parser("list", help="show your profiles and which is active")
    for action, blurb in (
        ("save", "save your current rules as a new profile and make it active (needs sudo)"),
        ("use", "switch to a profile's rules (needs sudo)"),
        ("delete", "delete a profile; your live rules do not change (needs sudo)"),
    ):
        action_parser = profile_sub.add_parser(action, help=blurb)
        action_parser.add_argument("name", help="the profile name")
    args = parser.parse_args(argv)
    handlers = {
        "serve": _cmd_serve,
        "engage": _cmd_engage,
        "restore": _cmd_restore,
        "dismiss": _cmd_dismiss,
        "status": _cmd_status,
        "update": _cmd_update,
        "allow": _cmd_rule,
        "block": _cmd_rule,
        "profile": _cmd_profile,
    }
    handler = handlers.get(args.command or "")
    if handler is None:
        parser.print_help()
        return EXIT_REFUSED
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
