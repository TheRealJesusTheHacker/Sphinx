"""The engage/restore discipline, proven against the fake manager:
save-before-change, verified saves, never overwrite a backup, exact
restore, leftover detection."""
import pytest

from sphinx_win.dnsmgmt.base import AdapterDns, NotElevatedError
from sphinx_win.dnsmgmt.fake import FakeDnsManager
from sphinx_win.dnsmgmt.guard import DnsGuard, DnsState

HOME = [
    AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"]),
    AdapterDns("Wi-Fi", "IPv6", ["fe80::1"]),
    AdapterDns("Ethernet", "IPv4", []),  # DHCP
    AdapterDns("Ethernet", "IPv6", []),
]


def make_guard(tmp_path, adapters=HOME, elevated=True):
    manager = FakeDnsManager(adapters, elevated=elevated)
    return DnsGuard(manager, tmp_path), manager


class TestEngage:
    def test_engage_points_everything_at_loopback(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        result = guard.engage()
        assert result.ok
        assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]
        assert manager.get_dns("Wi-Fi", "IPv6") == ["::1"]
        assert manager.get_dns("Ethernet", "IPv4") == ["127.0.0.1"]
        assert guard.detect_state() is DnsState.ENGAGED

    def test_backup_holds_the_originals(self, tmp_path):
        guard, _ = make_guard(tmp_path)
        guard.engage()
        backup = guard.load_backup()
        by_key = {(a.interface_alias, a.family): a.servers for a in backup}
        assert by_key[("Wi-Fi", "IPv4")] == ["192.168.1.1"]
        assert by_key[("Wi-Fi", "IPv6")] == ["fe80::1"]
        assert by_key[("Ethernet", "IPv4")] == []  # DHCP recorded as DHCP

    def test_unelevated_changes_nothing(self, tmp_path):
        guard, manager = make_guard(tmp_path, elevated=False)
        with pytest.raises(NotElevatedError):
            guard.engage()
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert guard.load_backup() is None

    def test_failure_midway_rolls_back(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        manager.fail_on_set.add(("Wi-Fi", "IPv6"))
        result = guard.engage()
        assert not result.ok
        # The adapter changed before the failure is back to original.
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        # And the verified backup survives for a later restore.
        assert guard.load_backup() is not None

    def test_no_active_adapters(self, tmp_path):
        guard, _ = make_guard(tmp_path, adapters=[])
        result = guard.engage()
        assert not result.ok
        assert guard.load_backup() is None


class TestDisengage:
    def test_restore_is_exact_including_dhcp(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        guard.engage()
        result = guard.disengage()
        assert result.ok
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert manager.get_dns("Wi-Fi", "IPv6") == ["fe80::1"]
        assert manager.get_dns("Ethernet", "IPv4") == []
        assert guard.load_backup() is None  # backup removed after verify
        assert guard.detect_state() is DnsState.DISENGAGED

    def test_failed_restore_keeps_backup(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        guard.engage()
        manager.fail_on_set.add(("Ethernet", "IPv4"))
        result = guard.disengage()
        assert not result.ok
        assert guard.load_backup() is not None

    def test_disengage_without_backup_is_a_noop_success(self, tmp_path):
        guard, _ = make_guard(tmp_path)
        assert guard.disengage().ok


class TestLeftover:
    def test_backup_present_but_dns_moved_on_is_leftover(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        guard.engage()
        # The user (or another tool) pointed DNS elsewhere by hand.
        manager.set_dns("Wi-Fi", "IPv4", ["8.8.8.8"])
        assert guard.detect_state() is DnsState.LEFTOVER

    def test_reengage_never_overwrites_original_backup(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        guard.engage()
        manager.set_dns("Wi-Fi", "IPv4", ["8.8.8.8"])  # hand change
        result = guard.engage()
        assert result.ok
        # Originals are still the pre-Sphinx settings, not 8.8.8.8 and
        # never the loopback.
        backup = guard.load_backup()
        by_key = {(a.interface_alias, a.family): a.servers for a in backup}
        assert by_key[("Wi-Fi", "IPv4")] == ["192.168.1.1"]
        guard.disengage()
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]

    def test_dismiss_leftover(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        guard.engage()
        manager.set_dns("Wi-Fi", "IPv4", ["8.8.8.8"])
        assert guard.dismiss_leftover() is True
        assert guard.load_backup() is None
        # Dismissal changes no settings.
        assert manager.get_dns("Wi-Fi", "IPv4") == ["8.8.8.8"]


class TestUnknownState:
    def test_loopback_without_backup_is_unknown_and_refused(self, tmp_path):
        adapters = [
            AdapterDns("Wi-Fi", "IPv4", ["127.0.0.1"]),
            AdapterDns("Wi-Fi", "IPv6", ["::1"]),
        ]
        guard, _ = make_guard(tmp_path, adapters=adapters)
        assert guard.detect_state() is DnsState.UNKNOWN
        result = guard.engage()
        assert not result.ok  # never records loopback as an "original"
        assert guard.load_backup() is None
