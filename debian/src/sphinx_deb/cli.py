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
from .core.tunnel import (
    REFUSAL_TEXT,
    TunnelRefusal,
    build_wireguard_text,
    parse_config,
    server_peer_stanza,
)
from .core.tunnelstore import TunnelStore
from .core import vpngate as _vpngate_mod
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
from .tunnel.guard import RealTunnelRunner, TunnelGuard, TunnelState

EXIT_OK = 0
EXIT_REFUSED = 2

#: Injectable VPN Gate fetcher (tests monkeypatch this; production
#: uses vpngate.default_fetcher). Tests NEVER hit the live feed.
_vpngate_fetcher = None


def _fetch_vpngate_rows():
    return _vpngate_mod.get_directory(paths.state_dir(), fetcher=_vpngate_fetcher)


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



def _tunnel_store() -> TunnelStore:
    return TunnelStore(paths.state_dir())


def _dns_restore_for_tunnel():
    """The tunnel teardown's second half: the existing DNS restore
    path, untouched, run only when a DNS record actually exists
    (a VPN-only connect may never have engaged the filter's DNS).
    Returns the DnsGuard's RestoreResult."""

    class _NoRecord:
        ok = True
        message = "No saved DNS settings to restore."

    guard = _guard()
    if guard.load_backup() is None and not guard.backup_file.exists():
        return _NoRecord()
    return guard.disengage()


def _tunnel_guard(with_dns_restore: bool = False) -> TunnelGuard:
    return TunnelGuard(
        RealTunnelRunner(),
        _tunnel_store(),
        paths.runtime_dir(),
        dns_restore=_dns_restore_for_tunnel if with_dns_restore else None,
    )


_MODE_WORDS = {
    "vpn": "VPN only (DNS is not filtered in this mode — ads are not blocked)",
    "vpn+blocker": "VPN + Blocker (DNS is filtered, then forwarded through the tunnel)",
}


def _vpn_status_lines() -> List[str]:
    """The VPN facts for `sphinx status`, from the guard's real
    reads — including the proof discipline: a record alone never
    reads as 'connected'; only a fresh handshake does."""
    guard = _tunnel_guard()
    status = guard.status()
    if status.state == TunnelState.DISENGAGED:
        return ["  VPN: off — no tunnel is up and no server is selected."]
    lines = []
    if getattr(status, "protocol", "") == "openvpn":
        if status.state == TunnelState.ENGAGED and status.connected:
            lines.append(
                f"  VPN: on — '{status.profile_name}' is connected and "
                "proven (OpenVPN process running, tunnel interface up)."
            )
            lines.append(
                "  VPN DNS: pushed DNS was rejected — the resolver in "
                "force before the tunnel stands, unfiltered by the "
                "tunnel itself (in VPN+Blocker, Sphinx's filter still "
                "fronts DNS as it did before)."
            )
            if status.removed_directives:
                lines.append(
                    "  OpenVPN config sanitized before connecting — removed: "
                    + ", ".join(status.removed_directives) + "."
                )
        else:
            lines.append(
                "  VPN: disconnected — the OpenVPN tunnel is not proven "
                "up. DNS was never re-pointed (pushed DNS is rejected), "
                "so DNS stays with the resolver in force before the "
                "tunnel. Note the honest limit: unlike WireGuard, "
                "Sphinx cannot blackhole general traffic after an "
                "unexpected openvpn exit, because openvpn removes its "
                "own routes as it dies. Reconnect (sudo sphinx vpn "
                f"connect {status.profile_name or '<name>'}) or "
                "disconnect on purpose (sudo sphinx vpn disconnect)."
            )
        if status.mode in _MODE_WORDS:
            lines.append(f"  VPN mode: {_MODE_WORDS[status.mode]}")
        return lines
    if status.state == TunnelState.ENGAGED and status.handshake_fresh:
        lines.append(
            f"  VPN: on — '{status.profile_name}' is connected and "
            f"proven (last handshake {status.handshake_age_s}s ago)."
        )
    elif status.state == TunnelState.UNKNOWN:
        lines.append(
            "  VPN: a tunnel interface is up but Sphinx has no record "
            "of it, so Sphinx will not claim it or take it over."
        )
        return lines
    else:
        lines.append(
            "  VPN: disconnected — the tunnel is not proven up, so "
            "traffic this profile covers is blocked, not going "
            "around the tunnel. Reconnect (sudo sphinx vpn connect "
            f"{status.profile_name or '<name>'}) or disconnect on "
            "purpose (sudo sphinx vpn disconnect)."
        )
    if status.mode in _MODE_WORDS:
        lines.append(f"  VPN mode: {_MODE_WORDS[status.mode]}")
    stored = _tunnel_store().get(status.profile_name) if status.profile_name else None
    if stored is not None:
        lines.append(
            f"  VPN scope: this profile routes {stored.profile.scope_words()}."
        )
    return lines


def _cmd_vpn_profile(args: argparse.Namespace) -> int:
    action = args.vpn_profile_action
    store = _tunnel_store()
    if action is None:
        print(
            "Say what to do: sphinx vpn profile list, sphinx vpn "
            "profile import <file>, sphinx vpn profile export "
            "<name>, sphinx vpn profile remove <name>, or sphinx "
            "vpn profile create <name> …"
        )
        return EXIT_REFUSED
    if action == "list":
        profiles = store.list_profiles()
        if not profiles:
            print(
                "No server profiles yet — your server list starts "
                "empty. Sphinx ships no servers of its own: add one "
                "your provider gave you (sphinx vpn profile import) "
                "or one you run yourself (sphinx vpn profile create)."
            )
        else:
            print("Server profiles:")
            for stored in profiles:
                p = stored.profile
                if p.protocol == "openvpn":
                    print(
                        f"  {p.name} — OpenVPN, server {p.endpoint} "
                        "(connectable — Sphinx invokes the system openvpn; "
                        "see 'sphinx vpn public' for public volunteer servers)"
                    )
                else:
                    print(
                        f"  {p.name} — WireGuard, server {p.endpoint}, "
                        f"routes {p.scope_words()}"
                    )
        for problem in store.problems():
            print(
                f"  {problem.path.name}: cannot be used ({problem.reason}) "
                "— the file was left exactly as it is."
            )
        return EXIT_OK
    if action == "export":
        stored = store.get(args.name or "")
        if stored is None:
            print(f"There is no server profile called '{args.name}' — nothing was exported.")
            return EXIT_REFUSED
        sys.stdout.write(stored.profile.export_text())
        return EXIT_OK
    if not _is_root():
        return _root_refusal(
            "Changing server profiles", f"vpn profile {action} {args.name or ''}".strip()
        )
    if action == "import":
        if args.file and args.file != "-":
            try:
                text = open(args.file, encoding="utf-8").read()
            except OSError as exc:
                print(f"That file could not be read ({exc}) — nothing was imported.")
                return EXIT_REFUSED
            fallback_name = os.path.splitext(os.path.basename(args.file))[0]
        else:
            text = sys.stdin.read()
            fallback_name = ""
        try:
            profile = parse_config(text)
        except TunnelRefusal as exc:
            print(
                f"That profile was refused: {exc} "
                f"(refusal: {exc.reason}). Nothing was imported, and "
                "every profile you already have is untouched."
            )
            return EXIT_REFUSED
        name = (args.name or profile.name or fallback_name or "").strip()
        if not name:
            print(
                "That profile carries no name and there is no file "
                "name to take one from — import it with a name: "
                "sudo sphinx vpn profile import --name <name> -"
            )
            return EXIT_REFUSED
        profile.set_name(name)
        if store.get(name) is not None:
            print(
                f"A server profile called '{name}' already exists — "
                "nothing was written over it. Remove it first (sudo "
                f"sphinx vpn profile remove {name}) to replace it."
            )
            return EXIT_REFUSED
        try:
            store.save(profile)
        except (ValueError, OSError) as exc:
            print(f"That profile could not be saved: {exc}")
            return EXIT_REFUSED
        if profile.protocol == "openvpn":
            print(
                f"Server profile '{name}' saved — OpenVPN, server "
                f"{profile.endpoint}. It connects through the system "
                "openvpn (sanitized first — script and persistence "
                "directives are stripped and named)."
            )
        else:
            print(
                f"Server profile '{name}' saved — WireGuard, server "
                f"{profile.endpoint}, routes {profile.scope_words()}. "
                "Choosing a server is trusting its operator with your "
                "traffic; Sphinx vouches for no server."
            )
        return EXIT_OK
    if action == "remove":
        if not store.remove(args.name or ""):
            print(f"There is no server profile called '{args.name}' — nothing changed.")
            return EXIT_REFUSED
        print(f"Server profile '{args.name}' removed.")
        return EXIT_OK
    # create
    name = (args.name or "").strip()
    if not name:
        print("A new profile needs a name — nothing was created.")
        return EXIT_REFUSED
    if store.get(name) is not None:
        print(f"A server profile called '{name}' already exists — nothing was created.")
        return EXIT_REFUSED
    guard = _tunnel_guard()
    try:
        private_key, public_key = guard.generate_keypair()
    except RuntimeError as exc:
        print(str(exc))
        return EXIT_REFUSED
    try:
        text = build_wireguard_text(
            name=name,
            private_key=private_key,
            addresses=[args.address],
            dns=[d.strip() for d in (args.dns or "").split(",") if d.strip()],
            server_public_key=args.server_key or "",
            endpoint=args.endpoint or "",
            allowed_ips=[
                a.strip() for a in (args.allowed or "0.0.0.0/0").split(",") if a.strip()
            ],
        )
        profile = parse_config(text)
    except TunnelRefusal as exc:
        print(
            f"That profile was refused: {exc} (refusal: {exc.reason}). "
            "Nothing was created."
        )
        return EXIT_REFUSED
    try:
        store.save(profile)
    except (ValueError, OSError) as exc:
        print(f"That profile could not be saved: {exc}")
        return EXIT_REFUSED
    print(f"Server profile '{name}' created. Its keypair was generated on this machine.")
    print(f"  This device's public key: {public_key}")
    print("  Give the server's operator this peer stanza for their server config:")
    for line in server_peer_stanza(
        client_public_key=public_key, addresses=[args.address]
    ).splitlines():
        print(f"    {line}")
    print(
        "  The private key never leaves this machine except in an "
        "export you make yourself (sphinx vpn profile export)."
    )
    return EXIT_OK


def _public_row_profile(row):
    from .core.tunnel import parse_config as _pc
    profile = _pc(row.config_text())
    profile.name = row.label
    try:
        profile.source = "vpngate"  # type: ignore[attr-defined]
    except Exception:
        pass
    return profile


def _cmd_vpn_public(args: argparse.Namespace) -> int:
    action = getattr(args, "vpn_public_action", None)
    if action is None:
        print(
            "Say what to do: sphinx vpn public list, sphinx vpn "
            "public connect <row>, or sphinx vpn public import <row> <name>."
        )
        return EXIT_REFUSED
    if action == "list":
        print(_vpngate_mod.DISCLOSURE)
        result = _fetch_vpngate_rows()
        if not result.rows:
            print(_vpngate_mod.EMPTY_STATE)
            return EXIT_REFUSED
        if not result.live and result.cache is not None:
            print(f"Cached list — {result.cache.age_label()}. Cached rows are not live.")
        else:
            print("Live list fetched just now from VPN Gate.")
        print("Public volunteer servers:")
        for i, row in enumerate(result.rows, start=1):
            print(f"  {i}. {row.label} — score {row.score or '?'}, ping {row.ping or '?'} ms, {row.ip}")
        return EXIT_OK
    # connect / import both need a row; disclosure rides first, always.
    print(_vpngate_mod.DISCLOSURE)
    if not _is_root():
        return _root_refusal("Using a public server", f"vpn public {action}")
    result = _fetch_vpngate_rows()
    if not result.rows:
        print(_vpngate_mod.EMPTY_STATE)
        return EXIT_REFUSED
    if not result.live and result.cache is not None:
        print(f"Using the cached list — {result.cache.age_label()}.")
    try:
        row_no = int(args.row)
    except (TypeError, ValueError):
        print(f"'{args.row}' is not a row number from 'sphinx vpn public list' — nothing was changed.")
        return EXIT_REFUSED
    if not (1 <= row_no <= len(result.rows)):
        print(f"There is no row {row_no} in the public list ({len(result.rows)} rows) — nothing was changed.")
        return EXIT_REFUSED
    row = result.rows[row_no - 1]
    try:
        profile = _public_row_profile(row)
    except Exception as exc:
        print(f"That server's config could not be used: {exc} — nothing was changed.")
        return EXIT_REFUSED
    if action == "import":
        name = (args.name or "").strip()
        if not name:
            print("Import needs a name: sphinx vpn public import <row> <name> — nothing was changed.")
            return EXIT_REFUSED
        store = _tunnel_store()
        if store.get(name) is not None:
            print(f"A server profile called '{name}' already exists — nothing was written over it.")
            return EXIT_REFUSED
        profile.name = name
        try:
            stored = store.save(profile)
        except (ValueError, OSError) as exc:
            print(f"That profile could not be saved: {exc}")
            return EXIT_REFUSED
        # Source recorded in the profile record (sidecar next to the profile file).
        try:
            import json as _json
            sidecar = stored.path.with_suffix(".source.json")
            sidecar.write_text(_json.dumps({"source": "vpngate", "hostname": row.hostname, "country_long": row.country_long, "label": row.label}), encoding="utf-8")
        except OSError:
            pass
        print(f"Server profile '{name}' saved — {row.label}, source: vpngate. Sanitization happens at connect time, and the removals are named then.")
        return EXIT_OK
    # connect — the command itself is the consent; disclosure was printed above.
    mode = args.mode if getattr(args, "mode", None) else ("vpn+blocker" if _guard().detect_state() == DnsState.ENGAGED else "vpn")
    result2 = _tunnel_guard().engage(profile, mode=mode)
    print(result2.message)
    if result2.ok:
        print(f"  Mode: {_MODE_WORDS[mode]}")
        print("  Disconnecting returns this machine to the mode it had before the VPN (Blocker only, or Off).")
    return EXIT_OK if result2.ok else EXIT_REFUSED


def _cmd_vpn(args: argparse.Namespace) -> int:
    action = args.vpn_action
    if action is None:
        print(
            "Say what to do: sphinx vpn profile …, sphinx vpn "
            "connect <name>, sphinx vpn disconnect, sphinx vpn "
            "status, or sphinx vpn public …."
        )
        return EXIT_REFUSED
    if action == "profile":
        return _cmd_vpn_profile(args)
    if action == "public":
        return _cmd_vpn_public(args)
    if action == "status":
        for line in _vpn_status_lines():
            print(line)
        return EXIT_OK
    if action == "connect":
        if not _is_root():
            return _root_refusal("Connecting the VPN", f"vpn connect {args.name or ''}")
        store = _tunnel_store()
        stored = store.get(args.name or "")
        if stored is None:
            print(f"There is no server profile called '{args.name}' — nothing was changed.")
            return EXIT_REFUSED
        mode = args.mode
        if mode is None:
            # Default: keep the blocker in the path when the filter
            # is engaged; otherwise VPN only, said out loud below.
            mode = (
                "vpn+blocker"
                if _guard().detect_state() == DnsState.ENGAGED
                else "vpn"
            )
        result = _tunnel_guard().engage(stored.profile, mode=mode)
        print(result.message)
        if result.ok:
            print(f"  Mode: {_MODE_WORDS[mode]}")
            print(
                "  Disconnecting returns this machine to the mode it "
                "had before the VPN (Blocker only, or Off)."
            )
        return EXIT_OK if result.ok else EXIT_REFUSED
    # disconnect
    if not _is_root():
        return _root_refusal("Disconnecting the VPN", "vpn disconnect")
    result = _tunnel_guard(with_dns_restore=True).disengage()
    print(result.message)
    return EXIT_OK if result.ok else EXIT_REFUSED


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
    for line in _vpn_status_lines():
        print(line)
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
    vpn_parser = sub.add_parser(
        "vpn",
        help="VPN mode: server profiles and the tunnel (WireGuard and OpenVPN connect; OpenVPN invokes the system openvpn)",
    )
    vpn_sub = vpn_parser.add_subparsers(dest="vpn_action")
    vpn_profile_parser = vpn_sub.add_parser(
        "profile", help="server profiles: the servers you can connect to (the list starts empty — Sphinx ships no servers)"
    )
    vpn_profile_sub = vpn_profile_parser.add_subparsers(dest="vpn_profile_action")
    vpn_profile_sub.add_parser("list", help="show your server profiles")
    import_parser = vpn_profile_sub.add_parser(
        "import", help="import a WireGuard or OpenVPN config from a file or stdin (needs sudo)"
    )
    import_parser.add_argument("file", nargs="?", default="-", help="the config file, or - for stdin")
    import_parser.add_argument("--name", help="name the profile this (else the config's own name or the file name)")
    export_parser = vpn_profile_sub.add_parser("export", help="print a profile's config text (it holds a private key — treat it like one)")
    export_parser.add_argument("name", help="the profile name")
    remove_parser = vpn_profile_sub.add_parser("remove", help="remove a server profile (needs sudo)")
    remove_parser.add_argument("name", help="the profile name")
    create_parser = vpn_profile_sub.add_parser(
        "create", help="create a profile for a server you run: generates this device's keypair here, with wg (needs sudo)"
    )
    create_parser.add_argument("name", help="the profile name, like Home Server")
    create_parser.add_argument("--server-key", required=True, help="the server's public key")
    create_parser.add_argument("--endpoint", required=True, help="the server's endpoint, like vpn.example.com:51820")
    create_parser.add_argument("--address", required=True, help="this device's tunnel address, like 10.8.0.2/32")
    create_parser.add_argument("--dns", default="", help="the profile's DNS servers, comma-separated (optional)")
    create_parser.add_argument("--allowed", default="0.0.0.0/0", help="which traffic enters the tunnel (default 0.0.0.0/0 — all of it)")
    connect_parser = vpn_sub.add_parser("connect", help="connect a server profile (needs sudo)")
    connect_parser.add_argument("name", help="the profile name")
    connect_parser.add_argument(
        "--mode",
        choices=("vpn", "vpn+blocker"),
        default=None,
        help="vpn = tunnel only, DNS unfiltered; vpn+blocker = tunnel with the ad filter in the DNS path (default: vpn+blocker when the filter is on, else vpn)",
    )
    vpn_sub.add_parser("disconnect", help="disconnect the tunnel and put DNS back as it was (needs sudo)")
    vpn_sub.add_parser("status", help="show the VPN state, proven — never claimed from intent")
    public_parser = vpn_sub.add_parser("public", help="public volunteer servers from VPN Gate — strangers' machines; the disclosure prints at point of use")
    public_sub = public_parser.add_subparsers(dest="vpn_public_action")
    public_sub.add_parser("list", help="fetch and list public volunteer servers (disclosure first)")
    pub_connect = public_sub.add_parser("connect", help="connect to a listed public server by row number (disclosure first; needs sudo)")
    pub_connect.add_argument("row", help="the row number from 'sphinx vpn public list'")
    pub_connect.add_argument("--mode", choices=("vpn", "vpn+blocker"), default=None)
    pub_import = public_sub.add_parser("import", help="store a listed public server as a named profile (source: vpngate; needs sudo)")
    pub_import.add_argument("row", help="the row number from 'sphinx vpn public list'")
    pub_import.add_argument("name", help="the profile name to store it under")
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
        "vpn": _cmd_vpn,
    }
    handler = handlers.get(args.command or "")
    if handler is None:
        parser.print_help()
        return EXIT_REFUSED
    try:
        return handler(args)
    except OSError as exc:
        # A save or resolver write that failed on disk must surface
        # as a plain refusal, never a traceback — and never as the
        # success the handler would have printed had the write
        # landed (Sweep #4: store writes now raise on failure, the
        # W-4 rule, so this is where that honesty reaches the user).
        print(f"Sphinx could not finish that: {exc}")
        return EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
