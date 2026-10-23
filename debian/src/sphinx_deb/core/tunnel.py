"""Server profiles: the tunnel brain (docs/TUNNEL-SPEC.md).

Pure Python, standard library only, no platform APIs — the same
discipline as the rest of ``core/``. This module parses, validates,
and serializes WireGuard config text (Sphinx's import/export
format) and recognizes OpenVPN config text as a labeled, stored
profile record. It never touches the network, never runs a
command, and never generates key material: keypairs come from
``wg genkey`` / ``wg pubkey`` at the guard layer (see
``sphinx_deb.tunnel``) — Curve25519 is never implemented here.

The rules that matter, from TUNNEL-SPEC:

- Round-trip is lossless. Parse -> export reproduces the profile:
  every recognized field, every unrecognized line preserved in
  order (comments included), modulo a single trailing-newline
  normalization. A field this module cannot represent is refused
  at import, never silently dropped.
- Sphinx writes its profile name as a comment on the first line
  of its own exports (``# Sphinx profile: <name>``) and reads it
  back on import. The comment is metadata, never a directive.
- Validation happens at import, against the canonical corpus
  (docs/tunnel-corpus.json), with the corpus's refusal
  vocabulary: ``invalid-key``, ``endpoint-missing-port``,
  ``invalid-cidr``, ``missing-server-key``. A malformed profile
  is refused with the reason named; nothing is half-parsed into
  a usable profile.
- An OpenVPN profile parses, is stored and labeled
  ``protocol=openvpn`` with its config text preserved losslessly,
  and is refused at connect time in Phase 1 with the reason named
  (TUNNEL-SPEC, "Public volunteer servers").
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: The corpus's refusal vocabulary (docs/tunnel-corpus.json).
REFUSAL_INVALID_KEY = "invalid-key"
REFUSAL_ENDPOINT_MISSING_PORT = "endpoint-missing-port"
REFUSAL_INVALID_CIDR = "invalid-cidr"
REFUSAL_MISSING_SERVER_KEY = "missing-server-key"
REFUSALS = (
    REFUSAL_INVALID_KEY,
    REFUSAL_ENDPOINT_MISSING_PORT,
    REFUSAL_INVALID_CIDR,
    REFUSAL_MISSING_SERVER_KEY,
)

NAME_COMMENT_PREFIX = "# Sphinx profile:"

#: Plain-language text for each refusal, for the surfaces that show
#: a refusal to a person (the store and the CLI translate the
#: machine word; the word itself is the corpus contract).
REFUSAL_TEXT = {
    REFUSAL_INVALID_KEY: (
        "a key in the profile is not a valid WireGuard key "
        "(WireGuard keys are 32 bytes, written as 44 characters "
        "of base64 ending in '=')"
    ),
    REFUSAL_ENDPOINT_MISSING_PORT: (
        "the server endpoint does not name a port (an endpoint "
        "looks like vpn.example.com:51820)"
    ),
    REFUSAL_INVALID_CIDR: (
        "an address or allowed-IPs entry is not a valid CIDR "
        "range (like 10.8.0.2/32 or 0.0.0.0/0)"
    ),
    REFUSAL_MISSING_SERVER_KEY: (
        "the profile names no server public key — without it "
        "there is no server identity for the tunnel to verify"
    ),
}


class TunnelRefusal(ValueError):
    """A profile was refused at import. ``reason`` is always one
    of the corpus's refusal words; ``detail`` says which field."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        text = REFUSAL_TEXT.get(reason, reason)
        super().__init__(f"{text} ({detail})" if detail else text)


def is_valid_key(value: str) -> bool:
    """A WireGuard key: 32 bytes as canonical base64 — 44
    characters, correct padding, and re-encoding the decoded bytes
    reproduces the text exactly (no alternate spellings)."""
    text = value.strip()
    if len(text) != 44 or not text.endswith("="):
        return False
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return False
    if len(raw) != 32:
        return False
    return base64.b64encode(raw).decode("ascii") == text


def _check_key(value: str, what: str) -> str:
    text = value.strip()
    if not is_valid_key(text):
        raise TunnelRefusal(REFUSAL_INVALID_KEY, what)
    return text


def _check_cidr(value: str, what: str, *, interface: bool) -> str:
    text = value.strip()
    try:
        if interface:
            ipaddress.ip_interface(text)
        else:
            ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise TunnelRefusal(REFUSAL_INVALID_CIDR, f"{what}: {text!r}") from None
    return text


def _split_list(value: str) -> List[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def parse_endpoint(value: str, what: str = "Endpoint") -> tuple:
    """Split an endpoint into (host, port). The port is not
    optional: an endpoint without one is the corpus's
    ``endpoint-missing-port`` refusal. Bracketed IPv6 hosts
    (``[2001:db8::7]:51820``) parse as one host."""
    text = value.strip()
    host = ""
    port_text = ""
    if text.startswith("["):
        end = text.find("]")
        if end < 0 or end + 1 >= len(text) or text[end + 1] != ":":
            raise TunnelRefusal(REFUSAL_ENDPOINT_MISSING_PORT, what)
        host = text[1:end]
        port_text = text[end + 2:]
    else:
        host, sep, port_text = text.rpartition(":")
        if not sep:
            raise TunnelRefusal(REFUSAL_ENDPOINT_MISSING_PORT, what)
    try:
        port = int(port_text)
    except ValueError:
        raise TunnelRefusal(REFUSAL_ENDPOINT_MISSING_PORT, what) from None
    if not host or not (1 <= port <= 65535):
        raise TunnelRefusal(REFUSAL_ENDPOINT_MISSING_PORT, what)
    return host, port


def endpoint_host(endpoint: str) -> str:
    return parse_endpoint(endpoint)[0]


def endpoint_port(endpoint: str) -> int:
    return parse_endpoint(endpoint)[1]


def with_endpoint_host(endpoint: str, host: str) -> str:
    """The same endpoint with its host replaced — how a resolved,
    pinned address takes the hostname's place for a session."""
    _, port = parse_endpoint(endpoint)
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


@dataclass
class PeerProfile:
    server_public_key: str = ""
    endpoint: str = ""
    allowed_ips: List[str] = field(default_factory=list)
    preshared_key: Optional[str] = None
    persistent_keepalive: Optional[int] = None


@dataclass
class TunnelProfile:
    """One server profile. ``raw_lines`` is the lossless record:
    export reproduces it (with the name comment maintained), so
    unrecognized lines and comments survive untouched, in order.
    The structured fields are the validated view the rest of
    Sphinx acts on; the two never disagree, because export is
    built from the raw lines and the fields are parsed from them.
    """

    protocol: str  # "wireguard" or "openvpn"
    name: Optional[str] = None
    # WireGuard structured view (empty for OpenVPN records).
    private_key: str = ""
    client_addresses: List[str] = field(default_factory=list)
    dns: List[str] = field(default_factory=list)
    peers: List[PeerProfile] = field(default_factory=list)
    mtu: Optional[int] = None
    extras: Dict[str, object] = field(default_factory=dict)
    #: Every line of the imported text, in order, without line
    #: endings. Export is these lines (name comment maintained).
    raw_lines: List[str] = field(default_factory=list)
    _name_line: Optional[int] = field(default=None, repr=False)

    # --- the primary peer's facts (the profile IS its first peer's
    # pin; further peers ride along in ``peers``) -------------------

    @property
    def endpoint(self) -> str:
        return self.peers[0].endpoint if self.peers else ""

    @property
    def server_public_key(self) -> str:
        return self.peers[0].server_public_key if self.peers else ""

    @property
    def allowed_ips(self) -> List[str]:
        """The primary peer's allowed IPs — the corpus's
        profile-level fact, mirroring endpoint and server key.
        Every peer's own list rides in ``peers``; routing scope
        (below) considers the union, because any peer's route is
        a route the tunnel carries."""
        return list(self.peers[0].allowed_ips) if self.peers else []

    @property
    def _all_allowed_ips(self) -> List[str]:
        out: List[str] = []
        for peer in self.peers:
            for item in peer.allowed_ips:
                if item not in out:
                    out.append(item)
        return out

    @property
    def scope(self) -> str:
        """``"all"`` when the profile routes everything,
        ``"some"`` for a split tunnel (TUNNEL-SPEC: a split tunnel
        is never presented as full protection). All means the IPv4
        default route is covered, and the IPv6 default route too
        whenever the profile speaks IPv6 at all."""
        allowed = set(self._all_allowed_ips)
        if "0.0.0.0/0" not in allowed:
            return "some"
        speaks_v6 = any(":" in a for a in self.client_addresses) or any(
            ":" in a for a in allowed
        )
        if speaks_v6 and "::/0" not in allowed:
            return "some"
        return "all"

    def scope_words(self) -> str:
        return "all traffic" if self.scope == "all" else "some traffic"

    # --- naming -----------------------------------------------------

    def set_name(self, name: Optional[str]) -> None:
        """Set (or clear) the profile's name, maintaining the
        Sphinx name comment in the raw lines: replaced in place
        when one exists, inserted as the first line when it does
        not, removed when the name is cleared."""
        clean = (name or "").strip() or None
        self.name = clean
        if self.protocol != "wireguard":
            return  # an OpenVPN record's text is preserved as-is
        if self._name_line is not None and 0 <= self._name_line < len(self.raw_lines):
            if clean is None:
                del self.raw_lines[self._name_line]
                self._name_line = None
            else:
                self.raw_lines[self._name_line] = f"{NAME_COMMENT_PREFIX} {clean}"
            return
        if clean is not None:
            self.raw_lines.insert(0, f"{NAME_COMMENT_PREFIX} {clean}")
            self._name_line = 0

    # --- export -------------------------------------------------------

    def export_text(self) -> str:
        """The profile as config text: the raw lines exactly,
        joined, with a single trailing newline (the spec's one
        allowed normalization)."""
        return "\n".join(self.raw_lines) + "\n"


# --- WireGuard parsing ------------------------------------------------


def _parse_wireguard(text: str) -> TunnelProfile:
    lines = text.splitlines()
    name: Optional[str] = None
    name_line: Optional[int] = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(NAME_COMMENT_PREFIX):
            name = stripped[len(NAME_COMMENT_PREFIX):].strip() or None
            name_line = idx
            break
        if stripped and not stripped.startswith(("#", ";")):
            break

    profile = TunnelProfile(protocol="wireguard", name=name, raw_lines=list(lines))
    profile._name_line = name_line

    section: Optional[str] = None
    peer: Optional[PeerProfile] = None
    extras_lines: List[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            if section == "peer":
                peer = PeerProfile()
                profile.peers.append(peer)
            else:
                peer = None
            continue
        if not stripped or stripped.startswith(("#", ";")):
            continue
        key, sep, value = stripped.partition("=")
        if not sep:
            extras_lines.append(line)
            continue
        key_norm = key.strip().lower()
        value = value.strip()
        if section == "interface":
            if key_norm == "privatekey":
                profile.private_key = _check_key(value, "PrivateKey")
            elif key_norm == "address":
                profile.client_addresses = [
                    _check_cidr(v, "Address", interface=True)
                    for v in _split_list(value)
                ]
            elif key_norm == "dns":
                profile.dns = _split_list(value)
            elif key_norm == "mtu":
                try:
                    profile.mtu = int(value)
                except ValueError:
                    extras_lines.append(line)
                else:
                    profile.extras["mtu"] = profile.mtu
            else:
                extras_lines.append(line)
        elif section == "peer" and peer is not None:
            if key_norm == "publickey":
                peer.server_public_key = _check_key(value, "PublicKey")
            elif key_norm == "presharedkey":
                peer.preshared_key = _check_key(value, "PresharedKey")
                profile.extras["preshared_key"] = peer.preshared_key
            elif key_norm == "endpoint":
                parse_endpoint(value)  # validates; refusal names it
                peer.endpoint = value
            elif key_norm == "allowedips":
                peer.allowed_ips = [
                    _check_cidr(v, "AllowedIPs", interface=False)
                    for v in _split_list(value)
                ]
            elif key_norm == "persistentkeepalive":
                try:
                    peer.persistent_keepalive = int(value)
                except ValueError:
                    extras_lines.append(line)
                else:
                    profile.extras["persistent_keepalive"] = (
                        peer.persistent_keepalive
                    )
            else:
                extras_lines.append(line)
        else:
            extras_lines.append(line)
    profile.extras["unrecognized_lines"] = extras_lines

    # The corpus's refusal order: a missing server key is its own
    # word, distinct from a malformed one (which _check_key already
    # refused above, as it did a malformed client key).
    if not profile.peers or not profile.peers[0].server_public_key:
        raise TunnelRefusal(REFUSAL_MISSING_SERVER_KEY, "PublicKey")
    for extra_peer in profile.peers[1:]:
        if not extra_peer.server_public_key:
            raise TunnelRefusal(REFUSAL_MISSING_SERVER_KEY, "PublicKey")
    if profile.peers[0].endpoint:
        parse_endpoint(profile.peers[0].endpoint)
    else:
        raise TunnelRefusal(REFUSAL_ENDPOINT_MISSING_PORT, "Endpoint")
    return profile


# --- OpenVPN recognition ------------------------------------------------

_REMOTE_RE = re.compile(r"^remote\s+(\S+)(?:\s+(\d+))?\s*$")


def _looks_like_openvpn(lines: List[str]) -> bool:
    saw_remote = False
    saw_shape = False
    for line in lines:
        stripped = line.strip()
        if _REMOTE_RE.match(stripped):
            saw_remote = True
        if stripped in ("client", "dev tun", "dev tap") or stripped.startswith(
            ("proto ", "dev ")
        ):
            saw_shape = True
    return saw_remote and saw_shape


def _parse_openvpn(text: str) -> TunnelProfile:
    lines = text.splitlines()
    endpoint = ""
    for line in lines:
        match = _REMOTE_RE.match(line.strip())
        if match:
            host = match.group(1)
            port = match.group(2) or "1194"
            endpoint = f"{host}:{port}"
            break
    return TunnelProfile(
        protocol="openvpn",
        name=None,
        raw_lines=list(lines),
        peers=[PeerProfile(endpoint=endpoint)] if endpoint else [],
    )


def parse_config(text: str) -> TunnelProfile:
    """Parse config text into a profile, or raise TunnelRefusal
    with the corpus's word for what is wrong. WireGuard text is
    recognized by its [Interface]/[Peer] sections; OpenVPN text by
    its client shape and ``remote`` line; anything else is refused
    plainly (not with a corpus word — it is not a config at all).
    """
    if "[Interface]" in text or "[Peer]" in text:
        return _parse_wireguard(text)
    lines = text.splitlines()
    if _looks_like_openvpn(lines):
        return _parse_openvpn(text)
    raise TunnelRefusal(
        REFUSAL_MISSING_SERVER_KEY,
        "this is neither a WireGuard config nor an OpenVPN config "
        "Sphinx recognizes",
    )


def build_wireguard_text(
    *,
    name: Optional[str],
    private_key: str,
    addresses: List[str],
    dns: List[str],
    server_public_key: str,
    endpoint: str,
    allowed_ips: List[str],
    preshared_key: Optional[str] = None,
    persistent_keepalive: Optional[int] = None,
    mtu: Optional[int] = None,
) -> str:
    """Render a new profile's config text in the corpus's shape,
    validating every field on the way in (the same refusals as an
    import — a locally created profile is held to the same rules).
    """
    _check_key(private_key, "PrivateKey")
    _check_key(server_public_key, "PublicKey")
    if preshared_key:
        _check_key(preshared_key, "PresharedKey")
    parse_endpoint(endpoint)
    for addr in addresses:
        _check_cidr(addr, "Address", interface=True)
    for net in allowed_ips:
        _check_cidr(net, "AllowedIPs", interface=False)
    out: List[str] = []
    if name:
        out.append(f"{NAME_COMMENT_PREFIX} {name}")
    out.append("[Interface]")
    out.append(f"PrivateKey = {private_key}")
    out.append(f"Address = {', '.join(addresses)}")
    if dns:
        out.append(f"DNS = {', '.join(dns)}")
    if mtu:
        out.append(f"MTU = {mtu}")
    out.append("")
    out.append("[Peer]")
    out.append(f"PublicKey = {server_public_key}")
    if preshared_key:
        out.append(f"PresharedKey = {preshared_key}")
    out.append(f"Endpoint = {endpoint}")
    out.append(f"AllowedIPs = {', '.join(allowed_ips)}")
    if persistent_keepalive:
        out.append(f"PersistentKeepalive = {persistent_keepalive}")
    return "\n".join(out) + "\n"


def server_peer_stanza(
    *, client_public_key: str, addresses: List[str], allowed_ips: Optional[List[str]] = None
) -> str:
    """The [Peer] stanza an operator pastes into their server's
    config to enroll this device — what `sphinx profile create`
    prints alongside the new public key."""
    nets = allowed_ips if allowed_ips is not None else addresses
    return (
        "[Peer]\n"
        f"PublicKey = {client_public_key}\n"
        f"AllowedIPs = {', '.join(nets)}\n"
    )
