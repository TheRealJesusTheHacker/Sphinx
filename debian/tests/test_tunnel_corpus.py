"""The canonical tunnel corpus: every edition reads the same file.

docs/tunnel-corpus.json is to the tunnel what the shared blocklist
pin is to the brain — one file, every edition's suite reads it, an
edition that disagrees with the corpus is wrong. It is located the
same way the bundled-list test locates the canonical asset:
relative to the repo root, no forked copy.
"""
import json
from pathlib import Path

import pytest

from sphinx_deb.core.tunnel import TunnelRefusal, parse_config

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS = REPO_ROOT / "docs" / "tunnel-corpus.json"


def _corpus():
    return json.loads(CORPUS.read_text(encoding="utf-8"))


CASES = _corpus()["cases"]


def test_corpus_refusal_vocabulary_is_the_specs():
    from sphinx_deb.core.tunnel import REFUSALS

    assert tuple(_corpus()["refusal_vocabulary"]) == tuple(REFUSALS)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_corpus_case(case):
    expect = case["expect"]
    if not expect["valid"]:
        with pytest.raises(TunnelRefusal) as refused:
            parse_config(case["input_text"])
        assert refused.value.reason == expect["refusal"]
        return
    profile = parse_config(case["input_text"])
    wanted = expect["profile"]
    assert profile.protocol == wanted["protocol"]
    assert profile.name == wanted["name"]
    assert profile.endpoint == wanted["endpoint"]
    if "server_public_key" in wanted:
        assert profile.server_public_key == wanted["server_public_key"]
    if "client_addresses" in wanted:
        assert profile.client_addresses == wanted["client_addresses"]
    if "allowed_ips" in wanted:
        assert profile.allowed_ips == wanted["allowed_ips"]
    if "dns" in wanted:
        assert profile.dns == wanted["dns"]
    if "extras" in wanted:
        for key, value in wanted["extras"].items():
            assert profile.extras[key] == value
    if "peers" in wanted:
        assert len(profile.peers) == len(wanted["peers"])
        for got, peer in zip(profile.peers, wanted["peers"]):
            assert got.server_public_key == peer["server_public_key"]
            assert got.endpoint == peer["endpoint"]
            assert got.allowed_ips == peer["allowed_ips"]
    if "scope" in expect:
        assert profile.scope == expect["scope"]
    if expect.get("export_text") is not None:
        assert profile.export_text() == expect["export_text"]


def test_export_after_naming_an_unnamed_profile_writes_the_comment():
    case = next(c for c in CASES if c["id"] == "wg-unnamed-profile")
    profile = parse_config(case["input_text"])
    assert profile.name is None
    profile.set_name("Later Named")
    assert profile.export_text().startswith("# Sphinx profile: Later Named\n")
    reparsed = parse_config(profile.export_text())
    assert reparsed.name == "Later Named"
    assert reparsed.export_text() == profile.export_text()
