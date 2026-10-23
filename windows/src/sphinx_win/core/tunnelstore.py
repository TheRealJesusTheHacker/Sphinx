"""Storage for VPN mode: the server-profile store and the tunnel
state record, both in the per-user data folder.

Two files, two disciplines — both borrowed from the audited DNS
side and kept strictly parallel to it:

- ``vpn-profiles.json`` — the user's server profiles. The server
  list starts EMPTY (TUNNEL-SPEC: no bundled servers, ever) — an
  absent file is an empty store, not an error. Writes are atomic
  (core.store.write_atomically, the fleet's store discipline): a
  bad profile is refused at import with the reason named and the
  store on disk is untouched — no profile is ever half-written.
- ``tunnel-state.json`` — the tunnel state record. It is a
  PARALLEL record to ``dns-backup.json``, never a rewrite of it:
  the DNS backup contract (FILTER-SPEC / dnsmgmt) does not change
  for VPN mode. The record holds only what the resume and restore
  disciplines need: the mode, the profile name, the intent, the
  pinned endpoint, and — for a VPN-only session that pointed the
  machine's DNS at the profile's servers — the original DNS
  settings it must restore exactly. No traffic data, ever.

A corrupt record (torn JSON, a profile that no longer parses, a
state with missing fields) is REFUSED LOUDLY: TunnelStoreError,
the file left exactly as found, nothing silently degraded to
"empty" or "off" — the same posture the DNS guard takes toward a
record it cannot read honestly. Private keys live only inside a
profile's config text in this folder (the per-user data folder is
the spec's Windows store); they are never logged, and no repr in
this module includes config text.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

from .store import write_atomically
from .tunnel import (
    TunnelRefusal,
    WgPeer,
    WireGuardProfile,
    _parse_cidr_list,
    _require_key,
    parse_endpoint,
    parse_profile,
    resolve_name,
)

PROFILES_FILE_NAME = "vpn-profiles.json"
STATE_FILE_NAME = "tunnel-state.json"


class TunnelStoreError(RuntimeError):
    """A stored tunnel record is corrupt or unreadable. Raised
    loudly, with the file left untouched — never papered over by
    pretending the store is empty."""


@dataclass
class TunnelState:
    """The tunnel state record (see the module docstring)."""

    profile_name: str
    #: The mode to return to on disconnect: "off" or "blocker".
    mode_before_vpn: str = "off"
    with_blocker: bool = False
    intent: bool = False
    #: The endpoint as pinned at connect time: "ip:port" — the
    #: tunnel never re-resolves its own doorway mid-session.
    pinned_endpoint: Optional[str] = None
    #: For VPN-only sessions that moved system DNS to the profile's
    #: servers: the originals, as AdapterDns dicts, restored
    #: exactly through the tunnel record (never the DNS backup).
    dns_originals: List[dict] = field(default_factory=list)
    dns_applied: List[str] = field(default_factory=list)
    #: Phase 2: which protocol this session runs ("wireguard" for
    #: every Phase 1 record; the field is absent there and reads
    #: back as the default).
    protocol: str = "wireguard"
    #: For OpenVPN sessions: the config directives the sanitizer
    #: removed before connecting, by name — the removal record is
    #: part of the session's truth, surfaced in its status, never
    #: a silent edit (core.openvpn_sanitize).
    sanitized_removed: List[str] = field(default_factory=list)
    #: For OpenVPN sessions: the supervised openvpn.exe child's
    #: pid, so the headless uninstall teardown can end a
    #: Sphinx-started client even when the tray host is gone.
    openvpn_pid: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "profile_name": self.profile_name,
            "mode_before_vpn": self.mode_before_vpn,
            "with_blocker": self.with_blocker,
            "intent": self.intent,
            "pinned_endpoint": self.pinned_endpoint,
            "dns_originals": [dict(d) for d in self.dns_originals],
            "dns_applied": list(self.dns_applied),
            "protocol": self.protocol,
            "sanitized_removed": list(self.sanitized_removed),
            "openvpn_pid": self.openvpn_pid,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "TunnelState":
        if not isinstance(raw, dict):
            raise TunnelStoreError("the tunnel state record is not an object")
        name = raw.get("profile_name")
        if not name or not isinstance(name, str):
            raise TunnelStoreError(
                "the tunnel state record does not name its profile"
            )
        mode_before = raw.get("mode_before_vpn", "off")
        if mode_before not in ("off", "blocker"):
            raise TunnelStoreError(
                f"the tunnel state record names an unknown pre-VPN "
                f"mode ({mode_before!r})"
            )
        originals = raw.get("dns_originals", [])
        if not isinstance(originals, list) or any(
            not isinstance(d, dict) for d in originals
        ):
            raise TunnelStoreError(
                "the tunnel state record's saved DNS settings are damaged"
            )
        protocol = raw.get("protocol", "wireguard")
        if protocol not in ("wireguard", "openvpn"):
            raise TunnelStoreError(
                f"the tunnel state record names an unknown "
                f"protocol ({protocol!r})"
            )
        pid = raw.get("openvpn_pid")
        return cls(
            profile_name=name,
            mode_before_vpn=mode_before,
            with_blocker=bool(raw.get("with_blocker", False)),
            intent=bool(raw.get("intent", False)),
            pinned_endpoint=raw.get("pinned_endpoint"),
            dns_originals=[dict(d) for d in originals],
            dns_applied=[str(s) for s in raw.get("dns_applied", [])],
            protocol=protocol,
            sanitized_removed=[
                str(s) for s in raw.get("sanitized_removed", [])
            ],
            openvpn_pid=int(pid) if isinstance(pid, int) else None,
        )


class TunnelStore:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.profiles_file = self.data_dir / PROFILES_FILE_NAME
        self.state_file = self.data_dir / STATE_FILE_NAME

    # --- Profiles ---------------------------------------------------

    def _read_profiles_raw(self) -> List[dict]:
        if not self.profiles_file.is_file():
            return []
        try:
            raw = json.loads(self.profiles_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise TunnelStoreError(
                f"Sphinx's saved server profiles could not be read "
                f"({e}). The file was left exactly as found; fix or "
                f"remove {self.profiles_file.name} by hand to start "
                f"with an empty list."
            ) from e
        entries = raw.get("profiles") if isinstance(raw, dict) else None
        if not isinstance(entries, list):
            raise TunnelStoreError(
                "The saved server profiles file is damaged (no "
                "profile list in it). It was left exactly as found."
            )
        return entries

    def load_profiles(self) -> list:
        """Every stored profile, parsed. A stored profile that no
        longer parses refuses the whole load loudly — silently
        dropping it would lose the user's server (and its key)
        without a word."""
        profiles = []
        for entry in self._read_profiles_raw():
            if not isinstance(entry, dict) or not isinstance(
                entry.get("config_text"), str
            ):
                raise TunnelStoreError(
                    "A saved server profile is damaged (its config "
                    "text is missing). The file was left exactly as "
                    "found; nothing was changed."
                )
            try:
                profile = parse_profile(entry["config_text"])
            except TunnelRefusal as e:
                raise TunnelStoreError(
                    f"A saved server profile no longer parses "
                    f"({e.message}). The file was left exactly as "
                    f"found; nothing was changed."
                ) from e
            if entry.get("name"):
                profile.name = str(entry["name"])
            profiles.append(profile)
        return profiles

    def profile_names(self) -> List[str]:
        return [p.name for p in self.load_profiles() if p.name]

    def get_profile(self, name: str):
        for profile in self.load_profiles():
            if profile.name == name:
                return profile
        return None

    def _save_profiles(self, profiles: list) -> None:
        payload = {
            "version": 1,
            "profiles": [
                {"name": p.name, "config_text": p.to_config_text()}
                for p in profiles
            ],
        }
        write_atomically(
            self.profiles_file,
            json.dumps(payload, indent=1).encode("utf-8"),
        )
        # Verified by reading back, like every Sphinx save that
        # something's safety depends on: a save we cannot read is
        # not a save.
        if self.profile_names() != [p.name for p in profiles]:
            raise TunnelStoreError(
                "The server profiles could not be saved verifiably; "
                "the previous file may still be in place."
            )

    def add_profile(self, profile):
        """Store a parsed profile under its (resolved) name.
        Duplicate names are refused — two servers under one label
        would make the picker lie about which is which."""
        profiles = self.load_profiles()
        if any(p.name == profile.name for p in profiles):
            raise TunnelRefusal(
                "duplicate-name",
                f"A server named {profile.name!r} is already saved. "
                "Pick a different name — a name is only a label.",
            )
        profiles.append(profile)
        self._save_profiles(profiles)
        return profile

    def import_text(
        self,
        text: str,
        *,
        name: Optional[str] = None,
        filename: Optional[str] = None,
    ):
        """Parse + name + store an imported config. Any refusal
        leaves the store on disk exactly as it was."""
        profile = parse_profile(text)
        profile.name = resolve_name(profile, supplied=name, filename=filename)
        return self.add_profile(profile)

    def create_local_profile(
        self,
        name: str,
        *,
        endpoint: str,
        server_public_key: str,
        client_addresses: Sequence[str],
        allowed_ips: Sequence[str],
        dns: Sequence[str] = (),
        keypair=None,
    ) -> WireGuardProfile:
        """Create a profile whose client keypair is generated on
        this device. ``keypair`` is a (private, public) pair from
        a vetted generator (tunnelmgmt supplies it — the store
        itself never invents key material); the public half is
        what the user registers with their server."""
        if keypair is None:
            raise TunnelRefusal(
                "name-required",
                "A locally created profile needs a keypair generated "
                "on this device; none was supplied.",
            )
        private_key, _public_key = keypair
        _require_key(private_key, "private key")
        _require_key(server_public_key, "server public key")
        parse_endpoint(endpoint)
        profile = WireGuardProfile(
            name=name.strip(),
            private_key=private_key,
            client_addresses=_parse_cidr_list(
                ", ".join(client_addresses), what="Address", interfaces=True
            ),
            dns=list(dns),
            peers=[
                WgPeer(
                    public_key=server_public_key,
                    endpoint=endpoint,
                    allowed_ips=_parse_cidr_list(
                        ", ".join(allowed_ips),
                        what="AllowedIPs",
                        interfaces=False,
                    ),
                )
            ],
        )
        return self.add_profile(profile)

    def delete_profile(self, name: str) -> bool:
        profiles = self.load_profiles()
        kept = [p for p in profiles if p.name != name]
        if len(kept) == len(profiles):
            return False
        self._save_profiles(kept)
        return True

    def export_text(self, name: str) -> Optional[str]:
        """The user's explicit export of one profile — the only
        way a private key leaves the store, and only when the
        user asks for exactly that."""
        profile = self.get_profile(name)
        return profile.to_config_text() if profile is not None else None

    # --- Tunnel state record ------------------------------------------

    def load_state(self) -> Optional[TunnelState]:
        if not self.state_file.is_file():
            return None
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise TunnelStoreError(
                f"The tunnel state record could not be read ({e}). "
                "It was left exactly as found — Sphinx will not "
                "guess at a tunnel it cannot account for."
            ) from e
        return TunnelState.from_dict(raw)

    def save_state(self, state: TunnelState) -> None:
        write_atomically(
            self.state_file,
            json.dumps(state.to_dict(), indent=1).encode("utf-8"),
        )
        loaded = self.load_state()
        if loaded is None or loaded.to_dict() != state.to_dict():
            raise TunnelStoreError(
                "The tunnel state record could not be saved "
                "verifiably, so nothing was changed on the machine."
            )

    def clear_state(self) -> None:
        try:
            self.state_file.unlink(missing_ok=True)
        except OSError:
            pass
