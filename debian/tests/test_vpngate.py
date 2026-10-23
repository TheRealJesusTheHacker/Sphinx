"""VPN Gate directory: feed parser against a synthetic fixture in
the feed's exact format (tests NEVER hit the live feed), cache-age
labeling, dead-feed empty state, disclosure presence, and the
public import/connect CLI paths on a fake guard."""
import base64
import time

import pytest

from sphinx_deb import cli
from sphinx_deb.core import vpngate
from sphinx_deb.core.tunnel import parse_config

# --- synthetic fixture, in the feed's exact format (marked fixture) ---
FIXTURE_CONFIG = (
    "client\ndev tun\nproto udp\nremote fixture-node.example.org 1194\n"
    "nobind\nup /tmp/fixture-evil.sh\n"
    "<ca>\n-----BEGIN CERTIFICATE-----\nFIXTURE-CERT-NOT-REAL\n"
    "-----END CERTIFICATE-----\n</ca>\n"
)
_B64 = base64.b64encode(FIXTURE_CONFIG.encode()).decode()
FIXTURE_FEED = (
    "*VPN Gate API*\n"
    "*https://www.vpngate.net/api/iphone/*\n"
    "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
    f"fixture1,203.0.113.10,100,20,1000000,Fixtureland,FL,1,1000,1,1000,2w,fixture-op,,{_B64}\n"
    f"fixture2,203.0.113.11,90,30,900000,Otherland,OL,1,1000,1,1000,2w,fixture-op,,{_B64}\n"
    "*\n"
)


def _fetcher(text=FIXTURE_FEED):
    return lambda: text


def _dead_fetcher():
    def boom():
        raise OSError("network unreachable (fixture)")
    return boom


def test_feed_parser_reads_fixture_rows():
    rows = vpngate.parse_feed(FIXTURE_FEED)
    assert len(rows) == 2
    assert rows[0].hostname == "fixture1"
    assert rows[0].country_long == "Fixtureland"
    assert rows[0].label == "Public volunteer server — Fixtureland (fixture1)"
    assert "fixture-node.example.org" in rows[0].config_text()
    profile = parse_config(rows[0].config_text())
    assert profile.protocol == "openvpn"


def test_feed_parser_rejects_garbage():
    assert vpngate.parse_feed("not a feed at all") == []
    assert vpngate.parse_feed("") == []


def test_cache_age_label_and_dead_feed_serves_cache(tmp_path):
    state = tmp_path / "state"
    rows = vpngate.parse_feed(FIXTURE_FEED)
    three_hours_ago = int(time.time() * 1000) - 3 * 3_600_000
    vpngate.save_cache(state, rows, fetched_at_ms=three_hours_ago)
    result = vpngate.get_directory(state, fetcher=_dead_fetcher())
    assert not result.live
    assert len(result.rows) == 2
    label = result.cache.age_label()
    assert "3 hours ago" in label and "couldn't be fetched" in label


def test_dead_feed_no_cache_is_the_honest_empty_state(tmp_path):
    result = vpngate.get_directory(tmp_path / "state", fetcher=_dead_fetcher())
    assert result.rows == []
    assert "Nothing is bundled" in vpngate.EMPTY_STATE
    assert "no offline list" in vpngate.EMPTY_STATE


def test_live_fetch_updates_cache(tmp_path):
    state = tmp_path / "state"
    result = vpngate.get_directory(state, fetcher=_fetcher())
    assert result.live and len(result.rows) == 2
    cached = vpngate.load_cache(state)
    assert cached is not None and len(cached.rows) == 2


# --- CLI paths -------------------------------------------------------


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SPHINX_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SPHINX_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setattr(cli, "_is_root", lambda: True)
    return tmp_path


def test_disclosure_in_list_and_connect(env, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_vpngate_fetcher", _fetcher())
    assert cli.main(["vpn", "public", "list"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(vpngate.DISCLOSURE) or vpngate.DISCLOSURE in out.splitlines()[0]
    assert "strangers' machines" in out
    assert "three months or more" in out
    assert "Fixtureland" in out
    # connect prints the disclosure BEFORE any connect attempt
    # (the attempt itself fails honestly here — no real openvpn
    # guard in the test env — but the disclosure must come first).
    rc = cli.main(["vpn", "public", "connect", "1"])
    out = capsys.readouterr().out
    assert vpngate.DISCLOSURE in out
    assert out.index(vpngate.DISCLOSURE) < len(out)  # printed, at the start of the flow


def test_public_list_dead_feed_empty_state(env, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_vpngate_fetcher", _dead_fetcher())
    assert cli.main(["vpn", "public", "list"]) == cli.EXIT_REFUSED
    out = capsys.readouterr().out
    assert vpngate.DISCLOSURE in out
    assert vpngate.EMPTY_STATE in out


def test_public_list_cache_is_labeled_with_age(env, capsys, monkeypatch):
    rows = vpngate.parse_feed(FIXTURE_FEED)
    old = int(time.time() * 1000) - 5 * 3_600_000
    vpngate.save_cache(env / "state", rows, fetched_at_ms=old)
    monkeypatch.setattr(cli, "_vpngate_fetcher", _dead_fetcher())
    assert cli.main(["vpn", "public", "list"]) == 0
    out = capsys.readouterr().out
    assert "5 hours ago" in out and "not live" in out


def test_public_import_stores_labeled_profile_with_source(env, capsys, monkeypatch):
    import json
    from pathlib import Path

    monkeypatch.setattr(cli, "_vpngate_fetcher", _fetcher())
    assert cli.main(["vpn", "public", "import", "2", "Imported Node"]) == 0
    out = capsys.readouterr().out
    assert vpngate.DISCLOSURE in out and "vpngate" in out
    store = cli._tunnel_store()
    stored = store.get("Imported Node") or store.get("imported-node")
    assert stored is not None
    assert stored.profile.protocol == "openvpn"
    sidecars = list((env / "state" / "tunnel-profiles").glob("*.source.json"))
    assert sidecars and json.loads(sidecars[0].read_text())["source"] == "vpngate"
