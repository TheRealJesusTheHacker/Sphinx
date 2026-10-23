"""The VPN Gate directory model (Phase 2): the feed parser
against a SYNTHETIC fixture in the feed's exact format (marked
fixture — the tests never hit the live feed), the bounded fetch,
the cache-with-age discipline, the dead-feed honest empty state,
and the disclosure text that must ride at the point of use."""
import base64
import io

import pytest

from sphinx_win.core import vpngate
from sphinx_win.core.vpngate import (
    EMPTY_STATE_MESSAGE,
    VPNGATE_DISCLOSURE,
    DirectoryListing,
    VpnGateDirectory,
    fetch_feed_text,
    format_age,
    parse_feed,
)

# --- Synthetic fixture, in the feed's exact format -------------------
# Marked fixture data: example hosts, RFC 5737 addresses, and a
# config whose certificate is plainly not real. Nothing here came
# from the live feed.

FIXTURE_CONFIG_1 = (
    "client\ndev tun\nproto udp\n"
    "remote public-node-1.example.jp 1194\n"
    "resolv-retry infinite\nnobind\n"
    "<ca>\n-----BEGIN CERTIFICATE-----\n"
    "FIXTURE-CERTIFICATE-NOT-REAL\n"
    "-----END CERTIFICATE-----\n</ca>\n"
)
FIXTURE_CONFIG_2 = (
    "client\ndev tun\nproto udp\n"
    "remote public-node-2.example.kr 1194\n"
    "<ca>\n-----BEGIN CERTIFICATE-----\n"
    "FIXTURE-CERTIFICATE-NOT-REAL-2\n"
    "-----END CERTIFICATE-----\n</ca>\n"
)

FEED_HEADER = (
    "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,"
    "NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,"
    "Operator,Message,OpenVPN_ConfigData_Base64"
)


def _row(host, ip, country_long, country_short, config):
    b64 = base64.b64encode(config.encode()).decode()
    return (
        f"{host},{ip},100,20,123456,{country_long},{country_short},"
        f"5,1000,10,999,log,fixture-operator,,{b64}"
    )


FIXTURE_FEED = "\n".join(
    [
        "*vpn_servers",
        FEED_HEADER,
        _row("public-node-1.example.jp", "203.0.113.10", "Japan", "JP",
             FIXTURE_CONFIG_1),
        _row("public-node-2.example.kr", "203.0.113.11", "Korea Republic of",
             "KR", FIXTURE_CONFIG_2),
        "*",
    ]
) + "\n"


class TestParser:
    def test_fixture_feed_parses_rows_and_configs(self):
        servers = parse_feed(FIXTURE_FEED)
        assert len(servers) == 2
        first = servers[0]
        assert first.host_name == "public-node-1.example.jp"
        assert first.country_long == "Japan"
        assert first.config_text == FIXTURE_CONFIG_1
        # The row's connection-choice label, verbatim shape.
        assert first.label == (
            "Public volunteer server — Japan (public-node-1.example.jp)"
        )
        assert servers[1].label.startswith(
            "Public volunteer server — Korea Republic of ("
        )

    def test_a_row_with_undecodable_config_is_skipped_not_fatal(self):
        bad = "broken.example,203.0.113.12,1,1,1,Nowhere,NW,0,0,0,0,log,op,,!!!"
        feed = "\n".join(
            ["*vpn_servers", FEED_HEADER,
             _row("public-node-1.example.jp", "203.0.113.10", "Japan",
                  "JP", FIXTURE_CONFIG_1), bad, "*"]
        )
        servers = parse_feed(feed)
        assert [s.host_name for s in servers] == ["public-node-1.example.jp"]

    def test_text_without_the_feed_header_is_refused(self):
        with pytest.raises(vpngate.VpnGateFeedError):
            parse_feed("<html>not the feed</html>")


class TestFetchBounds:
    def test_fetch_is_https_only(self):
        with pytest.raises(vpngate.VpnGateFeedError):
            fetch_feed_text("http://www.vpngate.net/api/iphone/")

    def test_fetch_size_cap_refuses_an_oversized_response(self):
        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b"x" * n

        with pytest.raises(vpngate.VpnGateFeedError):
            fetch_feed_text(opener=lambda req, timeout=None: Resp(),
                            max_bytes=1024)

    def test_fetch_failure_is_the_honest_empty_state(self):
        def boom(req, timeout=None):
            raise OSError("no route")

        with pytest.raises(vpngate.VpnGateFeedError) as e:
            fetch_feed_text(opener=boom)
        assert "Couldn't fetch the list" in str(e.value)


class TestDirectoryCache:
    def test_live_fetch_caches_with_a_timestamp(self, tmp_path):
        directory = VpnGateDirectory(tmp_path, fetcher=lambda: FIXTURE_FEED)
        listing = directory.refresh(now=1_000_000.0)
        assert listing.source == "live"
        assert len(listing.servers) == 2
        assert listing.freshness_text(now=1_000_000.0) == (
            "List fetched just now, from VPN Gate."
        )
        cached = directory.cached_listing()
        assert cached is not None and cached.source == "cache"

    def test_dead_feed_shows_the_cache_with_its_age_labeled(self, tmp_path):
        directory = VpnGateDirectory(tmp_path, fetcher=lambda: FIXTURE_FEED)
        directory.refresh(now=1_000_000.0)

        def dead():
            raise OSError("feed down")

        directory2 = VpnGateDirectory(tmp_path, fetcher=dead)
        listing = directory2.refresh(now=1_000_000.0 + 2 * 3600)
        assert listing.source == "cache"
        assert len(listing.servers) == 2
        text = listing.freshness_text(now=1_000_000.0 + 2 * 3600)
        assert "2 hours ago" in text
        assert "not as today's" in text

    def test_dead_feed_and_no_cache_is_an_honest_empty_state(self, tmp_path):
        def dead():
            raise OSError("feed down")

        directory = VpnGateDirectory(tmp_path, fetcher=dead)
        listing = directory.refresh()
        assert listing.source == "empty"
        assert listing.servers == []
        assert listing.freshness_text() == EMPTY_STATE_MESSAGE
        assert "Couldn't fetch the list" in listing.freshness_text()

    def test_nothing_is_fetched_until_refresh_is_called(self, tmp_path):
        calls = []

        def counting():
            calls.append(1)
            return FIXTURE_FEED

        directory = VpnGateDirectory(tmp_path, fetcher=counting)
        assert calls == []  # never pre-enabled, never pre-fetched
        directory.refresh()
        assert calls == [1]


class TestDisclosure:
    def test_the_disclosure_text_is_the_specs_substance(self):
        # TUNNEL-SPEC, Phase 2: the warning at the point of use,
        # in these words' substance — pinned so it cannot quietly
        # soften.
        for phrase in (
            "strangers' machines",
            "VPN Gate, University of Tsukuba",
            "The operator can see your traffic",
            "keep connection logs",
            "three months or more",
            "not for anything sensitive",
        ):
            assert phrase in VPNGATE_DISCLOSURE, phrase

    def test_age_phrasing(self):
        assert format_age(30) == "under a minute ago"
        assert format_age(5 * 60) == "5 minutes ago"
        assert format_age(2 * 3600) == "2 hours ago"
        assert format_age(3 * 86400) == "3 days ago"
