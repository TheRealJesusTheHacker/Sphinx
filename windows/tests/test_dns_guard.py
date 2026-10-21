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


class TestPartialLoopbackRefusal:
    """Windows audit (Phase 1): the all-loopback refusal used to be
    the only guard, so a machine with ONE adapter/family already at
    a loopback got that loopback recorded as its "original" — and
    the restore then left it pointing at a dead resolver."""

    def test_one_looped_row_blocks_a_fresh_save(self, tmp_path):
        adapters = [
            AdapterDns("Wi-Fi", "IPv4", ["127.0.0.1"]),  # some other local resolver
            AdapterDns("Wi-Fi", "IPv6", ["2606:4700:4700::1111"]),
        ]
        guard, manager = make_guard(tmp_path, adapters=adapters)
        result = guard.engage()
        assert not result.ok
        assert guard.load_backup() is None  # nothing was recorded
        # And nothing was changed.
        assert manager.get_dns("Wi-Fi", "IPv6") == ["2606:4700:4700::1111"]


class TestBackupValidation:
    """A backup Sphinx could not have written (corrupt, torn, or
    hand-edited) must degrade entry by entry — and a pure-loopback
    "original" must never be applied to a live adapter."""

    def _write_backup(self, guard, adapters):
        import json

        payload = {
            "version": 1,
            "saved_at_ms": 1,
            "adapters": [
                {"interface_alias": a, "family": f, "servers": s}
                for a, f, s in adapters
            ],
        }
        guard.backup_file.write_text(json.dumps(payload), encoding="utf-8")

    def test_loopback_original_is_dropped_not_applied(self, tmp_path):
        guard, manager = make_guard(
            tmp_path, adapters=[AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"])]
        )
        self._write_backup(guard, [("Wi-Fi", "IPv4", ["127.0.0.1"])])
        assert guard.load_backup() is None
        result = guard.disengage()  # the leftover Restore path
        assert result.ok
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]

    def test_bad_entries_drop_individually(self, tmp_path):
        guard, _ = make_guard(tmp_path)
        self._write_backup(
            guard,
            [
                ("Wi-Fi", "IPv4", ["192.168.1.1"]),
                ("Wi-Fi", "IPv6", ["::1"]),  # impossible original
                ("Wi-Fi", "IPv9", ["8.8.8.8"]),  # unknown family
                ("", "IPv4", ["8.8.8.8"]),  # no alias
            ],
        )
        backup = guard.load_backup()
        assert [(a.interface_alias, a.family) for a in backup] == [
            ("Wi-Fi", "IPv4")
        ]
        # State detection survives the malformed record.
        assert guard.detect_state() is DnsState.LEFTOVER


class TestPartialFamilyEngage:
    """Engage may be restricted to the loopbacks the filter proved
    it answers on: unproven families are recorded but never moved,
    and the state still reads ENGAGED (Windows audit, Phase 1)."""

    def test_unproven_family_recorded_but_untouched(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        result = guard.engage(only_loopbacks={"127.0.0.1"})
        assert result.ok
        assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]
        assert manager.get_dns("Ethernet", "IPv4") == ["127.0.0.1"]
        # IPv6 was not moved — ::1 was never proven to answer.
        assert manager.get_dns("Wi-Fi", "IPv6") == ["fe80::1"]
        assert manager.get_dns("Ethernet", "IPv6") == []
        assert guard.detect_state() is DnsState.ENGAGED
        # The backup still holds every original, and the restore is
        # exact for all of them.
        backup = guard.load_backup()
        assert len(backup) == 4
        assert guard.disengage().ok
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert manager.get_dns("Wi-Fi", "IPv6") == ["fe80::1"]

    def test_nothing_switchable_fails_and_leaves_no_backup(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        result = guard.engage(only_loopbacks=set())
        assert not result.ok
        assert guard.load_backup() is None
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
