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

    def test_partial_loopback_without_backup_is_unknown(self, tmp_path):
        # W-3: ANY active adapter exactly at its family loopback,
        # with no backup, is UNKNOWN — one adapter pointing at a
        # possibly-dead loopback resolver is not "Sphinx is off".
        adapters = [
            AdapterDns("Wi-Fi", "IPv4", ["127.0.0.1"]),
            AdapterDns("Wi-Fi", "IPv6", ["fe80::1"]),
            AdapterDns("Ethernet", "IPv4", ["192.168.1.1"]),
            AdapterDns("Ethernet", "IPv6", []),
        ]
        guard, _ = make_guard(tmp_path, adapters=adapters)
        assert guard.detect_state() is DnsState.UNKNOWN

    def test_no_loopback_without_backup_is_disengaged(self, tmp_path):
        # The clean case stays DISENGAGED: no backup, and no active
        # adapter at its family loopback.
        guard, _ = make_guard(tmp_path)
        assert guard.detect_state() is DnsState.DISENGAGED


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


class TestReengageMessage:
    """W-5: re-engaging against an existing backup where every
    switchable adapter is already at loopback and some families
    are skipped used to build "DNS points at Sphinx on ." — an
    empty adapter list in a success sentence."""

    def test_reengage_message_names_the_adapters_already_at_loopback(
        self, tmp_path
    ):
        guard, manager = make_guard(tmp_path)
        first = guard.engage(only_loopbacks={"127.0.0.1"})
        assert first.ok
        second = guard.engage(only_loopbacks={"127.0.0.1"})
        assert second.ok
        assert "on ." not in second.message
        assert second.message.startswith("DNS points at Sphinx on ")
        assert "Wi-Fi" in second.message and "Ethernet" in second.message
        # The skipped family is still reported honestly.
        assert "IPv6" in second.message and "left unchanged" in second.message


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


class TestMixedLoopbackBackup:
    """Bug hunt 2026-10-23: load_backup used to refuse only the
    pure single-loopback "original" ([127.0.0.1] exactly). A record
    whose servers MIX a loopback with real addresses — 127.0.0.53
    beside the router, ::1 on an IPv4 row, any 127.0.0.0/8 address —
    passed validation and would be restored verbatim, aiming DNS
    at a loopback nothing honest listens on. Engage refuses to
    record ANY adapter already at a loopback, so such a record is
    corrupt by the same construction and every entry carrying one
    is now dropped."""

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

    def test_stub_loopback_mixed_with_a_real_server_is_dropped(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        self._write_backup(
            guard, [("Wi-Fi", "IPv4", ["127.0.0.53", "192.168.1.1"])]
        )
        assert guard.load_backup() is None

    def test_family_loopback_mixed_with_a_real_server_is_dropped(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        self._write_backup(
            guard, [("Wi-Fi", "IPv4", ["127.0.0.1", "8.8.8.8"])]
        )
        assert guard.load_backup() is None

    def test_other_loopback_shapes_are_dropped(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        self._write_backup(
            guard,
            [
                ("Wi-Fi", "IPv4", ["::1"]),  # the other family's loopback
                ("Wi-Fi", "IPv6", ["127.0.0.2"]),  # anywhere in 127.0.0.0/8
                ("Ethernet", "IPv4", ["192.168.1.1"]),  # the honest row
            ],
        )
        backup = guard.load_backup()
        assert [(a.interface_alias, a.family) for a in backup] == [
            ("Ethernet", "IPv4")
        ]


class TestFloorCapture:
    """The forwarding chain's floor (FILTER-SPEC): the machine's
    effective DNS servers, captured at engage time — before the
    change, while they are still the machine's own — and retired
    with the backup. The floor is never a restore value."""

    def test_engage_captures_the_effective_servers_as_floor(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        assert guard.load_floor() == []
        assert guard.engage().ok
        # Wi-Fi's static + link-local, in adapter order; the DHCP
        # rows contribute nothing the fake knows.
        assert guard.load_floor() == ["192.168.1.1", "fe80::1"]
        assert guard.floor_file.exists()

    def test_disengage_retires_the_floor(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        assert guard.engage().ok
        assert guard.disengage().ok
        assert guard.load_floor() == []
        assert not guard.floor_file.exists()

    def test_dismiss_retires_the_floor(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        assert guard.engage().ok
        # The user puts DNS back by hand: a leftover with a floor.
        for adapter in HOME:
            manager.set_dns(
                adapter.interface_alias, adapter.family, list(adapter.servers)
            )
        assert guard.detect_state() is DnsState.LEFTOVER
        assert guard.dismiss_leftover()
        assert guard.load_floor() == []
        assert not guard.floor_file.exists()

    def test_reengage_never_recaptures_over_an_existing_floor(self, tmp_path):
        guard, manager = make_guard(tmp_path)
        assert guard.engage().ok
        floor_before = guard.load_floor()
        # A re-engage against the existing record (the resume path):
        # the effective servers now read as loopbacks, and the
        # captured floor must survive untouched.
        assert guard.engage().ok
        assert guard.load_floor() == floor_before

    def test_a_hand_edited_floor_file_sheds_its_loopbacks(self, tmp_path):
        import json

        guard, manager = make_guard(tmp_path)
        guard.floor_file.write_text(
            json.dumps(
                {"version": 1, "servers": ["127.0.0.1", "192.168.1.1", "junk"]}
            ),
            encoding="utf-8",
        )
        assert guard.load_floor() == ["192.168.1.1"]
