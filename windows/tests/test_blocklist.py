"""Ports of the Android core's BlocklistTest spirit: parsing shapes,
safety rails, matching semantics."""
import pytest

from sphinx_win.core.blocklist import (
    Allowlist,
    Blocklist,
    FilterLists,
    normalize,
    normalize_entry,
    parse_entries,
)


class TestNormalize:
    def test_lowercases_and_strips_trailing_dot(self):
        assert normalize("ADS.Example.COM.") == "ads.example.com"

    def test_wildcard_prefix_means_bare_name(self):
        assert normalize("*.example.com") == "example.com"

    def test_rejects_ip_literal(self):
        assert normalize("1.2.3.4") is None

    def test_rejects_junk(self):
        assert normalize("") is None
        assert normalize(None) is None
        assert normalize("not a domain.example") is None
        assert normalize("under_score.example.com") is None
        assert normalize("-leading.example.com") is None


class TestNormalizeEntryRails:
    def test_single_label_refused(self):
        # A one-word entry would block a whole top-level domain.
        assert normalize_entry("com") is None
        assert normalize_entry("localhost") is None

    def test_reserved_names_refused(self):
        assert normalize_entry("localhost.localdomain") is None
        assert normalize_entry("ip6-localhost") is None

    def test_normal_entry_accepted(self):
        assert normalize_entry("Ads.Example.com") == "ads.example.com"


class TestParseEntries:
    def test_plain_format(self):
        assert parse_entries(["ads.example.com", "tracker.example.net"]) == {
            "ads.example.com",
            "tracker.example.net",
        }

    def test_hosts_format(self):
        assert parse_entries(["0.0.0.0 ads.example.com"]) == {"ads.example.com"}

    def test_hosts_format_multiple_names_one_line(self):
        entries = parse_entries(["0.0.0.0 a.example.com b.example.com"])
        assert entries == {"a.example.com", "b.example.com"}

    def test_hosts_format_ipv6_literal(self):
        assert parse_entries(["::1 ads.example.com"]) == {"ads.example.com"}
        assert parse_entries(["fe80::1 tracker.example.org"]) == {"tracker.example.org"}

    def test_comments_and_blanks_ignored(self):
        entries = parse_entries(
            ["# a comment", "", "   ", "ads.example.com # trailing note"]
        )
        assert entries == {"ads.example.com"}

    def test_reserved_and_single_labels_skipped(self):
        entries = parse_entries(
            [
                "127.0.0.1 localhost",
                "0.0.0.0 com",
                "::1 ip6-localhost ip6-loopback",
                "255.255.255.255 broadcasthost",
            ]
        )
        assert entries == set()

    def test_ip_literal_alone_is_not_an_entry(self):
        assert parse_entries(["1.2.3.4"]) == set()

    def test_wildcard_lines(self):
        assert parse_entries(["*.ads.example.com"]) == {"ads.example.com"}

    def test_case_and_duplicates_collapse(self):
        entries = parse_entries(["ADS.example.com", "ads.EXAMPLE.com"])
        assert entries == {"ads.example.com"}


class TestMatching:
    def setup_method(self):
        self.blocklist = Blocklist.from_lines(
            ["example.com", "ads.other.net"]
        )

    def test_exact_match(self):
        assert self.blocklist.is_blocked("example.com")

    def test_subdomain_match(self):
        assert self.blocklist.is_blocked("ads.example.com")
        assert self.blocklist.is_blocked("a.b.ads.example.com")

    def test_entry_does_not_block_parent(self):
        assert not Blocklist(["ads.example.com"]).is_blocked("example.com")

    def test_entry_does_not_block_sibling(self):
        assert not Blocklist(["ads.example.com"]).is_blocked("other.example.com")

    def test_no_match_allowed(self):
        assert not self.blocklist.is_blocked("unrelated.example.org")

    def test_case_and_trailing_dot_insensitive(self):
        assert self.blocklist.is_blocked("ADS.Example.COM.")

    def test_empty_and_root_not_blocked(self):
        assert not self.blocklist.is_blocked("")
        assert not self.blocklist.is_blocked(".")


class TestAllowlistWins:
    def test_allowlist_wins_at_same_level(self):
        lists = FilterLists(
            Blocklist(["example.com"]), Allowlist(["ads.example.com"])
        )
        assert not lists.is_blocked("ads.example.com")
        assert not lists.is_blocked("deep.ads.example.com")
        assert lists.is_blocked("other.example.com")

    def test_allowlist_broader_than_block_entry(self):
        lists = FilterLists(
            Blocklist(["ads.example.com"]), Allowlist(["example.com"])
        )
        assert not lists.is_blocked("ads.example.com")

    def test_allowlist_cover_walk(self):
        allow = Allowlist(["example.com"])
        assert allow.covers("a.b.example.com")
        assert not allow.covers("example.org")
