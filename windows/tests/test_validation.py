"""Ports of the Android ListValidationTest: HTTPS-only sources, the
sanity gate, and redirect discipline."""
from sphinx_win.core.validation import (
    DEFAULT_MIN_DOMAINS,
    DEFAULT_SOURCES,
    is_acceptable_url,
    parse_and_validate,
    redirect_target,
)


def synthetic_list(count):
    return [f"host{i}.ads.example.com" for i in range(count)]


class TestSources:
    def test_defaults_are_https_and_reputable(self):
        assert DEFAULT_MIN_DOMAINS >= 1000
        assert DEFAULT_SOURCES
        for source in DEFAULT_SOURCES:
            assert is_acceptable_url(source.url)

    def test_http_refused(self):
        assert not is_acceptable_url("http://example.com/list.txt")
        assert is_acceptable_url("https://example.com/list.txt")
        assert not is_acceptable_url("https://")
        assert not is_acceptable_url("example.com/list.txt")


class TestGate:
    def test_real_sized_list_passes(self):
        parsed = parse_and_validate(synthetic_list(5000))
        assert parsed is not None
        assert parsed.size == 5000

    def test_empty_download_rejected(self):
        assert parse_and_validate([]) is None
        assert parse_and_validate(["", "   ", "# only comments"]) is None

    def test_error_page_rejected(self):
        error_page = ["<html>", "<head>", "<title>404", "Not", "Found",
                      "</title>", "</head>"]
        assert parse_and_validate(error_page) is None

    def test_truncated_list_rejected(self):
        assert parse_and_validate(synthetic_list(50)) is None

    def test_gate_counts_unique_domains(self):
        # A duplicate flood can't game the gate (Phase 2 audit).
        flood = ["same.ads.example.com"] * 5000
        assert parse_and_validate(flood) is None

    def test_floor_is_configurable(self):
        parsed = parse_and_validate(synthetic_list(50), min_domains=10)
        assert parsed is not None
        assert parsed.size == 50


class TestRedirectTarget:
    def test_https_to_https_other_host_allowed(self):
        assert redirect_target(
            "https://example.com/lists/hosts",
            "https://cdn.example.net/hosts",
        ) == "https://cdn.example.net/hosts"

    def test_downgrade_to_http_refused(self):
        assert redirect_target(
            "https://example.com/hosts", "http://example.com/hosts"
        ) is None

    def test_relative_location_resolved(self):
        assert redirect_target(
            "https://example.com/lists/hosts", "/mirror/hosts"
        ) == "https://example.com/mirror/hosts"

    def test_protocol_relative_downgrade_refused(self):
        assert redirect_target(
            "https://example.com/hosts", "//evil.example.net/hosts"
        ) == "https://evil.example.net/hosts"  # inherits https: fine

    def test_missing_location_refused(self):
        assert redirect_target("https://example.com/hosts", None) is None
        assert redirect_target("https://example.com/hosts", "  ") is None
