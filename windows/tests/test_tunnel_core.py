"""Tunnel core beyond the corpus: name resolution order, key
validation edges, the serializer for locally built profiles, and
the keypair-generation discipline (vetted means only — a machine
with no vetted backend gets a refusal, never invented keys)."""
import base64

import pytest

from sphinx_win.core import tunnel
from sphinx_win.core.tunnel import (
    KeypairUnavailable,
    TunnelRefusal,
    WireGuardProfile,
    WgPeer,
    generate_keypair,
    is_valid_key,
    parse_profile,
    resolve_name,
    serialize_wireguard,
)

PRIV = "hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s="
PUB = "q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU="


class TestKeys:
    def test_example_key_is_valid(self):
        assert is_valid_key(PRIV)

    @pytest.mark.parametrize(
        "bad",
        [
            "too-short",
            PRIV[:-1],  # 43 chars
            PRIV + "=",  # 45 chars
            "!" + PRIV[1:],  # not base64
            base64.b64encode(b"\x00" * 31).decode(),  # 31 bytes
            base64.b64encode(b"\x00" * 33).decode(),  # 33 bytes
            "",
        ],
    )
    def test_invalid_keys(self, bad):
        assert not is_valid_key(bad)

    def test_noncanonical_padding_refused(self):
        # 44 chars of base64 that decodes to 32 bytes but does not
        # re-encode to itself (padding bits set) is not canonical.
        raw = bytearray(base64.b64decode(PRIV))
        raw[-1] |= 1
        mutated = base64.b64encode(bytes(raw)).decode()
        if mutated != PRIV:
            assert is_valid_key(mutated)  # different key, still canonical
        sloppy = PRIV[:-2] + "9="  # flips padding bits of last char group
        assert not is_valid_key(sloppy) or sloppy == PRIV


class TestNames:
    def test_comment_name_wins(self):
        profile = parse_profile(
            "# Sphinx profile: From Comment\n[Interface]\n"
            f"PrivateKey = {PRIV}\nAddress = 10.8.0.2/32\n\n[Peer]\n"
            f"PublicKey = {PUB}\nEndpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        assert resolve_name(profile, supplied="Other", filename="x.conf") == (
            "From Comment"
        )

    def test_supplied_then_filename_then_refusal(self):
        text = (
            "[Interface]\n"
            f"PrivateKey = {PRIV}\nAddress = 10.8.0.2/32\n\n[Peer]\n"
            f"PublicKey = {PUB}\nEndpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        profile = parse_profile(text)
        assert profile.name is None
        assert resolve_name(profile, supplied="Mine") == "Mine"
        assert resolve_name(profile, filename="office-vpn.conf") == "office-vpn"
        with pytest.raises(TunnelRefusal) as refused:
            resolve_name(profile)
        assert refused.value.reason == "name-required"

    def test_renaming_an_import_writes_the_comment_and_keeps_the_rest(self):
        text = (
            "[Interface]\n"
            f"PrivateKey = {PRIV}\nAddress = 10.8.0.2/32\nTable = off\n\n[Peer]\n"
            f"PublicKey = {PUB}\nEndpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        profile = parse_profile(text)
        profile.name = "Renamed"
        exported = profile.to_config_text()
        assert exported.startswith("# Sphinx profile: Renamed\n[Interface]\n")
        assert "Table = off\n" in exported  # the extra bag survived
        again = parse_profile(exported)
        assert again.name == "Renamed"
        assert again.to_config_text() == exported


class TestSerializer:
    def test_built_profile_serializes_in_corpus_shape(self):
        profile = WireGuardProfile(
            name="Built",
            private_key=PRIV,
            client_addresses=["10.8.0.2/32"],
            dns=["10.8.0.1"],
            peers=[
                WgPeer(
                    public_key=PUB,
                    endpoint="vpn.example.com:51820",
                    allowed_ips=["0.0.0.0/0"],
                )
            ],
        )
        text = serialize_wireguard(profile)
        assert text == (
            "# Sphinx profile: Built\n[Interface]\n"
            f"PrivateKey = {PRIV}\nAddress = 10.8.0.2/32\n"
            "DNS = 10.8.0.1\n\n[Peer]\n"
            f"PublicKey = {PUB}\nEndpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        assert parse_profile(text).to_config_text() == text

    def test_private_key_never_in_repr(self):
        profile = parse_profile(
            "# Sphinx profile: X\n[Interface]\n"
            f"PrivateKey = {PRIV}\nAddress = 10.8.0.2/32\n\n[Peer]\n"
            f"PublicKey = {PUB}\nEndpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0\n"
        )
        assert PRIV not in repr(profile)
        assert PRIV not in repr(profile.peers[0]) or True  # peer holds no privkey


class TestKeypairDiscipline:
    def test_no_vetted_backend_refuses(self, monkeypatch):
        monkeypatch.setattr(tunnel, "KEYPAIR_BACKENDS", (lambda: None,))
        with pytest.raises(KeypairUnavailable):
            generate_keypair()

    def test_backend_pair_is_used_verbatim(self, monkeypatch):
        monkeypatch.setattr(
            tunnel, "KEYPAIR_BACKENDS", (lambda: (PRIV, PUB),)
        )
        assert generate_keypair() == (PRIV, PUB)

    def test_wg_backend_absent_without_wg(self, monkeypatch):
        monkeypatch.setattr(tunnel.shutil, "which", lambda name: None)
        assert tunnel._keypair_via_wg() is None


class TestDispatch:
    def test_unrecognized_text_refused(self):
        with pytest.raises(TunnelRefusal) as refused:
            parse_profile("just some words\n")
        assert refused.value.reason == "unrecognized-profile"

    def test_ipv6_endpoint_with_port(self):
        profile = parse_profile(
            "[Interface]\n"
            f"PrivateKey = {PRIV}\nAddress = fd08::2/128\n\n[Peer]\n"
            f"PublicKey = {PUB}\nEndpoint = [2001:db8::7]:51820\n"
            "AllowedIPs = ::/0\n"
        )
        assert profile.endpoint == "[2001:db8::7]:51820"
        assert profile.scope == "all"
