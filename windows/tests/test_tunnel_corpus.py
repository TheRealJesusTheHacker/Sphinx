"""The canonical tunnel corpus (docs/tunnel-corpus.json): every
edition's suite reads this one file — the same repo-root-relative
pattern as the bundled-list test, no forked copy. An edition that
disagrees with the corpus is wrong (TUNNEL-SPEC).

Every case runs: the parse verdict (profile facts or the named
refusal) and, for valid cases, the exact export text — round-trip
is lossless."""
import json
from pathlib import Path

import pytest

from sphinx_win.core.tunnel import TunnelRefusal, parse_profile

CORPUS = (
    Path(__file__).resolve().parent.parent.parent
    / "docs"
    / "tunnel-corpus.json"
)


def _cases():
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert data["version"] == 1
    return data["cases"]


CASES = _cases()


def _case(case_id):
    return next(c for c in CASES if c["id"] == case_id)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_corpus_case(case):
    expect = case["expect"]
    if not expect["valid"]:
        with pytest.raises(TunnelRefusal) as refused:
            parse_profile(case["input_text"])
        assert refused.value.reason == expect["refusal"]
        assert refused.value.reason in {
            "invalid-key",
            "endpoint-missing-port",
            "invalid-cidr",
            "missing-server-key",
        }
        return
    profile = parse_profile(case["input_text"])
    facts = expect["profile"]
    assert profile.protocol == facts["protocol"]
    assert profile.name == facts["name"]
    assert profile.endpoint == facts["endpoint"]
    if facts["protocol"] == "wireguard":
        assert profile.server_public_key == facts["server_public_key"]
        assert profile.client_addresses == facts["client_addresses"]
        assert profile.allowed_ips == facts["allowed_ips"]
        assert profile.dns == facts["dns"]
        assert profile.scope == expect["scope"]
    # Lossless round-trip: export equals the corpus's exact text.
    assert profile.to_config_text() == expect["export_text"]


def test_corpus_extras_are_preserved_and_parsed():
    profile = parse_profile(_case("wg-psk-keepalive-mtu")["input_text"])
    assert profile.mtu == 1280
    peer = profile.peers[0]
    assert peer.preshared_key == "p4G/fpNfUSa8CcAQ8Sxkji+c2kewIE93J4M3DIQTrL0="
    assert peer.persistent_keepalive == 25


def test_corpus_multi_peer_facts():
    profile = parse_profile(_case("wg-multi-peer")["input_text"])
    expect = _case("wg-multi-peer")["expect"]["profile"]
    assert [
        {
            "server_public_key": p.public_key,
            "endpoint": p.endpoint,
            "allowed_ips": p.allowed_ips,
        }
        for p in profile.peers
    ] == expect["peers"]


def test_corpus_openvpn_record_facts():
    # The corpus case pins the record's facts. (Phase 1 also
    # mandated a connect refusal for it; Phase 2 superseded
    # that — OpenVPN profiles now connect, exercised against
    # the mode model in test_openvpn_mode.py.)
    profile = parse_profile(_case("openvpn-profile-record")["input_text"])
    assert profile.protocol == "openvpn"
    assert profile.endpoint == "vpn-node.example.org:1194"
