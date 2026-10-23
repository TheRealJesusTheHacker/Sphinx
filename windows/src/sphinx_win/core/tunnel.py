"""Server profiles for VPN mode (docs/TUNNEL-SPEC.md): the
WireGuard config-text parser/serializer, the OpenVPN profile
recognizer, validation against the corpus refusal vocabulary, and
keypair generation through vetted means only.

Design rules, from the spec:

- Round-trip is lossless. A parsed profile keeps its original
  lines; exporting an unmodified profile reproduces the imported
  text (modulo a single trailing-newline normalization). Unknown
  keys and comments ride along in the lines themselves — the
  "extra bag" is the text, in order, never a re-serialization
  that could drop a field the edition does not use.
- Validation happens at import, with the corpus's refusal
  vocabulary: ``invalid-key``, ``endpoint-missing-port``,
  ``invalid-cidr``, ``missing-server-key``. A refusal names its
  reason; nothing is half-parsed into a store.
- Sphinx writes its profile name as a comment on the first line
  of its own exports (``# Sphinx profile: <name>``) and reads it
  back. The comment is metadata, never a config directive.
- Private keys are never logged and never appear in a repr.
- Keypairs are generated ONLY by a vetted Curve25519
  implementation: the official WireGuard tooling (``wg genkey`` /
  ``wg pubkey``) when it is on the machine, or the ``cryptography``
  library's X25519 when it is installed. There is no hand-rolled
  Curve25519 here and no fallback that invents one: when neither
  vetted means exists, generation refuses and says so.

This module is platform-neutral and unit-tested on any platform,
like the rest of the core.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

#: The corpus refusal vocabulary (docs/tunnel-corpus.json).
REFUSAL_INVALID_KEY = "invalid-key"
REFUSAL_ENDPOINT_MISSING_PORT = "endpoint-missing-port"
REFUSAL_INVALID_CIDR = "invalid-cidr"
REFUSAL_MISSING_SERVER_KEY = "missing-server-key"
#: Refusals beyond the corpus vocabulary (import-level, named the
#: same way: a short token plus a plain sentence for the user).
REFUSAL_UNRECOGNIZED = "unrecognized-profile"
REFUSAL_NAME_REQUIRED = "name-required"

NAME_COMMENT_PREFIX = "# Sphinx profile:"

#: Phase 1 named the OpenVPN refusal here; Phase 2 connects
#: OpenVPN profiles through the user's installed OpenVPN program
#: (tunnelmgmt.openvpn_base — the honest missing-client message
#: lives there now, as OPENVPN_NOT_INSTALLED_MESSAGE). These
#: spellings stay as a record of the Phase 1 refusal vocabulary;
#: nothing in the connect path raises them any more.


class TunnelRefusal(ValueError):
    """A profile was refused at import, with the reason named.

    ``reason`` is the corpus vocabulary token where the corpus has
    one; ``message`` is the plain sentence for the user.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message


class KeypairUnavailable(RuntimeError):
    """No vetted Curve25519 implementation is available on this
    machine, so Sphinx will not generate a keypair at all — it
    never hand-rolls one and never invents key material."""


# --- Key / endpoint / CIDR validation --------------------------------


def is_valid_key(value: str) -> bool:
    """A WireGuard key is 32 bytes as canonical base64: exactly 44
    characters, and re-encoding the decoded bytes reproduces the
    string exactly (canonical padding, no stray characters)."""
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return False
    if len(raw) != 32:
        return False
    return base64.b64encode(raw).decode("ascii") == value


def _require_key(value: str, what: str) -> str:
    if not is_valid_key(value):
        raise TunnelRefusal(
            REFUSAL_INVALID_KEY,
            f"The {what} is not a valid WireGuard key (keys are 32 "
            "bytes, written as 44 characters of base64). The profile "
            "was refused; nothing was stored.",
        )
    return value


def parse_endpoint(value: str) -> Tuple[str, int]:
    """Split ``host:port`` (or ``[v6-host]:port``). An endpoint
    without a port is the corpus refusal ``endpoint-missing-port``;
    a port that is not a number in range is refused the same way —
    it carries no usable port either."""
    text = value.strip()
    host: Optional[str] = None
    port_text: Optional[str] = None
    if text.startswith("["):
        closing = text.find("]")
        if closing > 0 and text[closing + 1 : closing + 2] == ":":
            host = text[1:closing]
            port_text = text[closing + 2 :]
    else:
        host_part, sep, port_part = text.rpartition(":")
        if sep:
            host, port_text = host_part, port_part
    if not host or port_text is None or port_text == "":
        raise TunnelRefusal(
            REFUSAL_ENDPOINT_MISSING_PORT,
            f"The endpoint {value!r} has no port. Endpoints are "
            "written host:port (for example vpn.example.com:51820). "
            "The profile was refused; nothing was stored.",
        )
    try:
        port = int(port_text)
    except ValueError:
        raise TunnelRefusal(
            REFUSAL_ENDPOINT_MISSING_PORT,
            f"The endpoint {value!r} does not end in a port number. "
            "The profile was refused; nothing was stored.",
        ) from None
    if not (1 <= port <= 65535):
        raise TunnelRefusal(
            REFUSAL_ENDPOINT_MISSING_PORT,
            f"The endpoint port {port} is outside 1-65535. The "
            "profile was refused; nothing was stored.",
        )
    return host, port


def endpoint_host(endpoint: str) -> str:
    return parse_endpoint(endpoint)[0]


def endpoint_port(endpoint: str) -> int:
    return parse_endpoint(endpoint)[1]


def _parse_cidr_list(value: str, *, what: str, interfaces: bool) -> List[str]:
    """Parse a comma-separated CIDR list, keeping the user's exact
    tokens (export reproduces them). Each token must parse."""
    tokens = [t.strip() for t in value.split(",") if t.strip()]
    if not tokens:
        raise TunnelRefusal(
            REFUSAL_INVALID_CIDR,
            f"The {what} list is empty. The profile was refused; "
            "nothing was stored.",
        )
    for token in tokens:
        try:
            if interfaces:
                ipaddress.ip_interface(token)
            else:
                ipaddress.ip_network(token, strict=False)
        except ValueError:
            raise TunnelRefusal(
                REFUSAL_INVALID_CIDR,
                f"{token!r} in the {what} list is not a valid CIDR "
                "address. The profile was refused; nothing was stored.",
            ) from None
    return tokens


def _parse_ip_list(value: str, *, what: str) -> List[str]:
    tokens = [t.strip() for t in value.split(",") if t.strip()]
    for token in tokens:
        try:
            ipaddress.ip_address(token)
        except ValueError:
            raise TunnelRefusal(
                REFUSAL_INVALID_CIDR,
                f"{token!r} in the {what} list is not an IP address. "
                "The profile was refused; nothing was stored.",
            ) from None
    return tokens


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# --- Profiles ----------------------------------------------------------


@dataclass
class WgPeer:
    public_key: str = field(repr=False)
    endpoint: Optional[str] = None
    allowed_ips: List[str] = field(default_factory=list)
    preshared_key: Optional[str] = field(default=None, repr=False)
    persistent_keepalive: Optional[int] = None


@dataclass
class WireGuardProfile:
    """A parsed WireGuard server profile (TUNNEL-SPEC fields).

    ``_lines`` is the lossless record: the imported config's lines,
    in order, unknown keys and comments included. Export of an
    unmodified profile reproduces them. A profile built in code
    has no ``_lines`` and is serialized canonically instead.
    """

    name: Optional[str]
    private_key: str = field(repr=False)
    client_addresses: List[str] = field(default_factory=list)
    dns: List[str] = field(default_factory=list)
    peers: List[WgPeer] = field(default_factory=list)
    mtu: Optional[int] = None
    listen_port: Optional[int] = None
    protocol: str = field(default="wireguard", init=False)

    _lines: Optional[List[str]] = field(default=None, repr=False)
    _parsed_name: Optional[str] = field(default=None, repr=False)

    # The profile *is* its first peer for picker purposes (the
    # corpus's profile facts); further peers ride in ``peers``.
    @property
    def endpoint(self) -> Optional[str]:
        return self.peers[0].endpoint if self.peers else None

    @property
    def server_public_key(self) -> Optional[str]:
        return self.peers[0].public_key if self.peers else None

    @property
    def allowed_ips(self) -> List[str]:
        return list(self.peers[0].allowed_ips) if self.peers else []

    @property
    def scope(self) -> str:
        """``all`` when the allowed-IPs union is a full tunnel
        (0.0.0.0/0 or ::/0 present), else ``some`` — the UI says
        "some traffic" for ``some``, in those words or plainer."""
        union = [ip for peer in self.peers for ip in peer.allowed_ips]
        return "all" if ("0.0.0.0/0" in union or "::/0" in union) else "some"

    def to_config_text(self) -> str:
        if self._lines is not None:
            lines = list(self._lines)
            if self.name != self._parsed_name:
                # The name changed after import (or was supplied for
                # an unnamed import): Sphinx's own exports carry it
                # as the first-line comment; everything else about
                # the imported text is untouched.
                lines = [
                    ln for ln in lines
                    if not ln.startswith(NAME_COMMENT_PREFIX)
                ]
                if self.name:
                    lines.insert(0, f"{NAME_COMMENT_PREFIX} {self.name}")
            return "\n".join(lines) + "\n"
        return serialize_wireguard(self)


@dataclass
class OpenVpnProfile:
    """An OpenVPN server profile (TUNNEL-SPEC). The config text is
    preserved losslessly in the store; connecting (Phase 2) runs
    the user's installed OpenVPN program over a SANITIZED working
    copy (core.openvpn_sanitize) — the stored text is never the
    text the client runs, and never edited by sanitization."""

    name: Optional[str]
    endpoint: Optional[str]
    config_text: str = field(repr=False)
    protocol: str = field(default="openvpn", init=False)
    scope: str = field(default="all", init=False)

    @property
    def dns(self) -> List[str]:
        """An OpenVPN profile names no DNS of its own: DNS arrives
        as the server's PUSH at connect time (the engine reports
        it; the mode model applies it under the tunnel record).
        This empty list keeps the mode model's shape honest —
        nothing is claimed before the push exists."""
        return []

    def to_config_text(self) -> str:
        text = self.config_text
        return text if text.endswith("\n") else text + "\n"


def serialize_wireguard(profile: WireGuardProfile) -> str:
    """The canonical serialization for a profile built in code
    (never a re-serialization of an import — imports keep their
    own lines). Field order matches the corpus's exports."""
    out: List[str] = []
    if profile.name:
        out.append(f"{NAME_COMMENT_PREFIX} {profile.name}")
    out.append("[Interface]")
    out.append(f"PrivateKey = {profile.private_key}")
    if profile.client_addresses:
        out.append("Address = " + ", ".join(profile.client_addresses))
    if profile.dns:
        out.append("DNS = " + ", ".join(profile.dns))
    if profile.mtu is not None:
        out.append(f"MTU = {profile.mtu}")
    if profile.listen_port is not None:
        out.append(f"ListenPort = {profile.listen_port}")
    for peer in profile.peers:
        out.append("")
        out.append("[Peer]")
        out.append(f"PublicKey = {peer.public_key}")
        if peer.preshared_key:
            out.append(f"PresharedKey = {peer.preshared_key}")
        if peer.endpoint:
            out.append(f"Endpoint = {peer.endpoint}")
        if peer.allowed_ips:
            out.append("AllowedIPs = " + ", ".join(peer.allowed_ips))
        if peer.persistent_keepalive is not None:
            out.append(f"PersistentKeepalive = {peer.persistent_keepalive}")
    return "\n".join(out) + "\n"


# --- Parsing -----------------------------------------------------------


def _split_sections(lines: Sequence[str]):
    """Yield (section_name, [lines]) in file order. Lines before
    the first section header come back under ``""``."""
    sections: List[Tuple[str, List[str]]] = []
    current: Tuple[str, List[str]] = ("", [])
    sections.append(current)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = (stripped[1:-1].strip().lower(), [])
            sections.append(current)
        else:
            current[1].append(line)
    return sections


def _section_kv(lines: Sequence[str]) -> dict:
    """Key/value pairs of one section (keys lowercased). Comments
    and unknown keys are not lost — they live in the profile's
    preserved lines; this is only the parsed view."""
    kv = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        key, sep, value = stripped.partition("=")
        if sep:
            kv[key.strip().lower()] = value.strip()
    return kv


def _name_from_lines(lines: Sequence[str]) -> Optional[str]:
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(NAME_COMMENT_PREFIX):
            name = stripped[len(NAME_COMMENT_PREFIX) :].strip()
            return name or None
        if stripped:
            break  # the name comment is Sphinx's FIRST line only
    return None


def parse_wireguard(text: str) -> WireGuardProfile:
    raw_lines = text.split("\n")
    # A single trailing newline is normalization, not content.
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    lines = [ln.rstrip("\r") for ln in raw_lines]
    name = _name_from_lines(lines)
    sections = _split_sections(lines)
    interface = None
    peer_sections = []
    for section_name, section_lines in sections:
        if section_name == "interface" and interface is None:
            interface = _section_kv(section_lines)
        elif section_name == "peer":
            peer_sections.append(_section_kv(section_lines))
    if interface is None:
        interface = {}
    private_key = interface.get("privatekey")
    if private_key is not None:
        _require_key(private_key, "private key")
    addresses: List[str] = []
    if interface.get("address"):
        addresses = _parse_cidr_list(
            interface["address"], what="Address", interfaces=True
        )
    dns: List[str] = []
    if interface.get("dns"):
        dns = _parse_ip_list(interface["dns"], what="DNS")
    mtu = None
    if interface.get("mtu"):
        try:
            mtu = int(interface["mtu"])
        except ValueError:
            raise TunnelRefusal(
                REFUSAL_INVALID_CIDR,
                "The MTU value is not a number. The profile was "
                "refused; nothing was stored.",
            ) from None
    listen_port = None
    if interface.get("listenport"):
        try:
            listen_port = int(interface["listenport"])
        except ValueError:
            listen_port = None

    if not peer_sections:
        raise TunnelRefusal(
            REFUSAL_MISSING_SERVER_KEY,
            "The profile has no [Peer] section, so it names no "
            "server key. The profile was refused; nothing was stored.",
        )
    peers: List[WgPeer] = []
    for kv in peer_sections:
        public_key = kv.get("publickey")
        if not public_key:
            raise TunnelRefusal(
                REFUSAL_MISSING_SERVER_KEY,
                "A [Peer] section has no PublicKey — the server's "
                "identity pin is missing, and a profile without one "
                "cannot authenticate its server. The profile was "
                "refused; nothing was stored.",
            )
        _require_key(public_key, "server public key")
        psk = kv.get("presharedkey")
        if psk is not None:
            _require_key(psk, "preshared key")
        endpoint = kv.get("endpoint")
        if endpoint is not None:
            parse_endpoint(endpoint)  # raises endpoint-missing-port
        allowed: List[str] = []
        if kv.get("allowedips"):
            allowed = _parse_cidr_list(
                kv["allowedips"], what="AllowedIPs", interfaces=False
            )
        keepalive = None
        if kv.get("persistentkeepalive"):
            try:
                keepalive = int(kv["persistentkeepalive"])
            except ValueError:
                keepalive = None
        peers.append(
            WgPeer(
                public_key=public_key,
                endpoint=endpoint,
                allowed_ips=allowed,
                preshared_key=psk,
                persistent_keepalive=keepalive,
            )
        )
    return WireGuardProfile(
        name=name,
        private_key=private_key or "",
        client_addresses=addresses,
        dns=dns,
        peers=peers,
        mtu=mtu,
        listen_port=listen_port,
        _lines=lines,
        _parsed_name=name,
    )


def looks_like_openvpn(text: str) -> bool:
    has_remote = False
    has_client_shape = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("remote "):
            has_remote = True
        if stripped in ("client", "dev tun", "dev tap") or stripped.startswith("<ca>"):
            has_client_shape = True
    return has_remote and has_client_shape


def parse_openvpn(text: str) -> OpenVpnProfile:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    name = _name_from_lines(lines)
    endpoint = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("remote "):
            parts = stripped.split()
            if len(parts) >= 3:
                endpoint = f"{parts[1]}:{parts[2]}"
            elif len(parts) == 2:
                endpoint = parts[1]
            break
    return OpenVpnProfile(name=name, endpoint=endpoint, config_text=text)


def parse_profile(text: str):
    """Parse imported config text into a profile, dispatching on
    its shape. Raises TunnelRefusal with the reason named."""
    if "[Interface]" in text or "[Peer]" in text:
        return parse_wireguard(text)
    if looks_like_openvpn(text):
        return parse_openvpn(text)
    raise TunnelRefusal(
        REFUSAL_UNRECOGNIZED,
        "That text is not a WireGuard or OpenVPN config Sphinx "
        "recognizes. Nothing was stored.",
    )


def resolve_name(profile, *, supplied: Optional[str] = None,
                 filename: Optional[str] = None) -> str:
    """The spec's name order: Sphinx comment (already on the
    profile), else the supplied name (the file name lands here too,
    or the user's answer), else refusal — the user is asked."""
    if profile.name:
        return profile.name
    if supplied and supplied.strip():
        return supplied.strip()
    if filename:
        stem = filename.replace("\\", "/").rsplit("/", 1)[-1]
        if "." in stem:
            stem = stem.rsplit(".", 1)[0]
        if stem.strip():
            return stem.strip()
    raise TunnelRefusal(
        REFUSAL_NAME_REQUIRED,
        "This profile has no name in its config. Give it a name "
        "and import it again — a name is only a label, never a "
        "location claim.",
    )


# --- Keypair generation (vetted means only) ----------------------------


def _keypair_via_wg() -> Optional[Tuple[str, str]]:
    wg = shutil.which("wg") or shutil.which("wg.exe")
    if wg is None:
        return None
    try:
        gen = subprocess.run(
            [wg, "genkey"], capture_output=True, text=True, timeout=15
        )
        if gen.returncode != 0:
            return None
        private_key = gen.stdout.strip()
        pub = subprocess.run(
            [wg, "pubkey"],
            input=private_key,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if pub.returncode != 0:
            return None
        public_key = pub.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    if is_valid_key(private_key) and is_valid_key(public_key):
        return private_key, public_key
    return None


def _keypair_via_cryptography() -> Optional[Tuple[str, str]]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
        )
    except Exception:
        return None
    key = X25519PrivateKey.generate()
    private_raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


#: The vetted backends, in order. Tests may substitute this list;
#: production code never adds a hand-rolled backend to it.
KEYPAIR_BACKENDS = (_keypair_via_wg, _keypair_via_cryptography)


def generate_keypair() -> Tuple[str, str]:
    """Generate a fresh (private, public) WireGuard keypair with a
    vetted Curve25519 implementation — the official ``wg`` tooling
    or the ``cryptography`` library's X25519. Raises
    KeypairUnavailable when neither exists on this machine."""
    for backend in KEYPAIR_BACKENDS:
        pair = backend()
        if pair is not None:
            return pair
    raise KeypairUnavailable(
        "Sphinx cannot generate a keypair on this machine: neither "
        "the official WireGuard tools (wg) nor a vetted Curve25519 "
        "library is available, and Sphinx never makes up key "
        "material of its own. Importing a provider config — which "
        "carries its key with it — works regardless."
    )
