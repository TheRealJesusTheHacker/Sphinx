"""Matching + parsing vs docs/FILTER-SPEC.md — the spec's own
worked examples, the parsing shapes it defines, and the safety
rails it mandates. Same brain as every other edition."""
from sphinx_deb.core.blocklist import (
    Allowlist,
    Blocklist,
    FilterLists,
    normalize,
    normalize_entry,
    parse_entries,
)


# --- normalization (rule 1) ----------------------------------------


def test_names_compare_case_insensitively_without_trailing_dot():
    assert normalize("ADS.Example.COM.") == "ads.example.com"
    assert normalize("ads.example.com") == "ads.example.com"


def test_wildcard_prefix_means_the_bare_name():
    assert normalize("*.example.com") == "example.com"


def test_ip_literals_and_junk_never_normalize():
    assert normalize("0.0.0.0") is None
    assert normalize("not a domain") is None
    assert normalize("") is None
    assert normalize(None) is None


# --- matching (rules 3–4): the spec's worked examples ---------------


def test_entry_blocks_itself_and_every_subdomain():
    lists = Blocklist(["example.com"])
    assert lists.is_blocked("example.com")
    assert lists.is_blocked("ads.example.com")
    assert lists.is_blocked("a.b.ads.example.com")


def test_entry_never_blocks_its_parent_or_siblings():
    lists = Blocklist(["ads.example.com"])
    assert lists.is_blocked("ads.example.com")
    assert lists.is_blocked("x.ads.example.com")
    assert not lists.is_blocked("example.com")
    assert not lists.is_blocked("other.example.com")


def test_unlisted_names_are_allowed():
    lists = Blocklist(["example.com"])
    assert not lists.is_blocked("example.org")
    assert not lists.is_blocked("notexample.com")


def test_matching_ignores_case_and_trailing_dot():
    lists = Blocklist(["Example.COM"])
    assert lists.is_blocked("ADS.EXAMPLE.COM.")


# --- the allowlist (rule 5) -----------------------------------------


def test_allowlist_wins_at_the_same_or_deeper_level():
    pair = FilterLists(
        Blocklist(["example.com"]), Allowlist(["ads.example.com"])
    )
    assert not pair.is_blocked("ads.example.com")
    assert not pair.is_blocked("deep.ads.example.com")
    assert pair.is_blocked("other.example.com")
    assert pair.is_blocked("example.com")


def test_allowlisting_a_name_unblocks_it_and_all_its_subdomains():
    pair = FilterLists(Blocklist(["example.com"]), Allowlist(["example.com"]))
    assert not pair.is_blocked("example.com")
    assert not pair.is_blocked("anything.example.com")


# --- list-file parsing ("List files") --------------------------------


def test_plain_and_wildcard_lines():
    entries = parse_entries(["example.com", "*.ads.example.org", "", "  "])
    assert entries == {"example.com", "ads.example.org"}


def test_hosts_format_lines_every_name_counts():
    entries = parse_entries(
        [
            "0.0.0.0 ads.example.com tracker.example.org",
            ":: cdn.example.net",
            "127.0.0.1 localhost",
        ]
    )
    assert entries == {"ads.example.com", "tracker.example.org", "cdn.example.net"}


def test_comments_anywhere_and_blank_lines_are_ignored():
    entries = parse_entries(
        ["# a comment", "example.com # a trailing note", "", "   # another"]
    )
    assert entries == {"example.com"}


def test_parsing_safety_rails():
    entries = parse_entries(
        [
            "com",  # single label: would block a whole TLD
            "localhost",
            "localhost.localdomain",
            "broadcasthost",
            "0.0.0.0 ip6-localhost ip6-allnodes",
            "1.2.3.4",  # an address is not a name
            "ok.example.com",
        ]
    )
    assert entries == {"ok.example.com"}


def test_normalize_entry_applies_the_same_rails():
    assert normalize_entry("com") is None
    assert normalize_entry("localhost") is None
    assert normalize_entry("fine.example.com") == "fine.example.com"


def test_custom_entries_use_the_same_matching():
    # FILTER-SPEC, "Custom block entries": same rules as list entries.
    pair = FilterLists(
        Blocklist(parse_entries(["example.com", "mine.example.net"])),
        Allowlist([]),
    )
    assert pair.is_blocked("sub.mine.example.net")
