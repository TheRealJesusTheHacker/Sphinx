"""The production DnsManager's read semantics (Windows audit,
Phase 1).

The guard's whole discipline rests on one contract: reads report
the CONFIGURED servers, where empty means "obtain DNS automatically
(DHCP)". Get-DnsClientServerAddress cannot honor that contract —
it reports the *effective* servers, DHCP-learned ones included — so
the implementation reads the per-interface ``NameServer`` registry
value that Set-DnsClientServerAddress itself writes. The
PowerShell itself only runs on Windows (CI's smoke step executes
it); what is pinned here is the interpretation of its output and
that the scripts keep asking the registry, not the cmdlet, for the
meaning of a read.
"""
import inspect

import sphinx_win.dnsmgmt.windows_impl as impl
from sphinx_win.dnsmgmt.windows_impl import WindowsDnsManager, parse_nameserver_value


class TestParseNameserverValue:
    def test_absent_or_empty_means_automatic(self):
        assert parse_nameserver_value(None) == []
        assert parse_nameserver_value("") == []
        assert parse_nameserver_value("   ") == []

    def test_static_values_split_on_commas_and_space(self):
        assert parse_nameserver_value("8.8.8.8") == ["8.8.8.8"]
        assert parse_nameserver_value("8.8.8.8,8.8.4.4") == ["8.8.8.8", "8.8.4.4"]
        assert parse_nameserver_value("8.8.8.8, 8.8.4.4") == ["8.8.8.8", "8.8.4.4"]
        assert parse_nameserver_value("fe80::1, 2001:4860:4860::8888") == [
            "fe80::1",
            "2001:4860:4860::8888",
        ]


class TestScriptsAskTheRegistry:
    def test_get_dns_reads_the_nameserver_value(self):
        source = inspect.getsource(WindowsDnsManager.get_dns)
        assert "NameServer" in source
        assert "Interfaces" in source
        # The effective-address cmdlet must not supply the answer.
        assert "ServerAddresses" not in source

    def test_active_adapters_read_the_nameserver_value(self):
        source = inspect.getsource(WindowsDnsManager.active_adapters)
        assert "NameServer" in source
        assert "Tcpip6" in source  # the IPv6 family has its own key


class TestReadMapping:
    def test_get_dns_maps_configured_through_the_parser(self, monkeypatch):
        monkeypatch.setattr(
            impl, "_run_powershell", lambda script: {"Configured": "1.1.1.1, 1.0.0.1"}
        )
        manager = WindowsDnsManager()
        assert manager.get_dns("Wi-Fi", "IPv4") == ["1.1.1.1", "1.0.0.1"]

    def test_get_dns_automatic_reads_as_empty(self, monkeypatch):
        monkeypatch.setattr(
            impl, "_run_powershell", lambda script: {"Configured": None}
        )
        manager = WindowsDnsManager()
        assert manager.get_dns("Wi-Fi", "IPv6") == []

    def test_active_adapters_maps_each_row(self, monkeypatch):
        rows = [
            {"InterfaceAlias": "Wi-Fi", "Family": "IPv4", "Configured": "192.168.1.1"},
            {"InterfaceAlias": "Wi-Fi", "Family": "IPv6", "Configured": None},
        ]
        monkeypatch.setattr(impl, "_run_powershell", lambda script: rows)
        manager = WindowsDnsManager()
        adapters = manager.active_adapters()
        assert [(a.interface_alias, a.family, a.servers) for a in adapters] == [
            ("Wi-Fi", "IPv4", ["192.168.1.1"]),
            ("Wi-Fi", "IPv6", []),  # automatic reads as empty, per contract
        ]


class TestParseEffectiveServers:
    """The floor's read: Get-DnsClientServerAddress rows flattened
    in order, duplicates removed, string-or-list shapes both."""

    def test_flattens_in_order_without_duplicates(self):
        rows = [
            {"InterfaceAlias": "Wi-Fi", "Family": "IPv4",
             "ServerAddresses": ["192.168.1.1", "1.1.1.1"]},
            {"InterfaceAlias": "Wi-Fi", "Family": "IPv6",
             "ServerAddresses": ["fe80::1"]},
            {"InterfaceAlias": "Ethernet", "Family": "IPv4",
             "ServerAddresses": "192.168.1.1"},
        ]
        assert impl.parse_effective_servers(rows) == [
            "192.168.1.1", "1.1.1.1", "fe80::1",
        ]

    def test_single_row_and_empty_shapes(self):
        assert impl.parse_effective_servers(None) == []
        assert impl.parse_effective_servers([]) == []
        assert impl.parse_effective_servers(
            {"ServerAddresses": ["8.8.8.8"]}
        ) == ["8.8.8.8"]
        assert impl.parse_effective_servers(
            [{"ServerAddresses": None}, {"ServerAddresses": []}, "junk"]
        ) == []

    def test_effective_read_uses_the_cmdlet_not_the_registry(self):
        # The mirror of the configured-read tests: effective
        # servers are the ONE thing the cmdlet is asked for.
        source = inspect.getsource(WindowsDnsManager.effective_dns_servers)
        assert "Get-DnsClientServerAddress" in source
        assert "ServerAddresses" in source

    def test_effective_servers_maps_through_the_parser(self, monkeypatch):
        monkeypatch.setattr(
            impl,
            "_run_powershell",
            lambda script: [{"ServerAddresses": ["192.168.1.1"]}],
        )
        manager = WindowsDnsManager()
        assert manager.effective_dns_servers() == ["192.168.1.1"]
