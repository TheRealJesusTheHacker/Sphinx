"""The headless --restore-dns mode (app/main.py): the installer's
uninstall hook. It must restore exactly what the guard holds, keep
the record when a restore fails, and treat "nothing held" as
success. Plus the single-instance acquisition (same module): the
probe→claim race must not produce a rival host."""
from sphinx_win.app.main import acquire_instance, restore_dns_main
from sphinx_win.core.store import Store
from sphinx_win.dnsmgmt.base import AdapterDns
from sphinx_win.dnsmgmt.fake import FakeDnsManager
from sphinx_win.dnsmgmt.guard import DnsGuard

ADAPTERS = [
    AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"]),
    AdapterDns("Wi-Fi", "IPv6", []),
]


def engaged_manager(tmp_path):
    manager = FakeDnsManager(ADAPTERS, elevated=True)
    guard = DnsGuard(manager, tmp_path)
    result = guard.engage()
    assert result.ok
    assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]
    return manager, guard


def test_restore_puts_back_the_originals(tmp_path):
    manager, guard = engaged_manager(tmp_path)
    code = restore_dns_main(
        data_dir=tmp_path, manager_factory=lambda: manager, out=lambda *a: None
    )
    assert code == 0
    assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
    assert guard.load_backup() is None  # record retired on verified restore


def test_verified_restore_records_protection_intent_off(tmp_path):
    # W-1: the headless restore is a successful stop transition, so
    # it must record intent off exactly like controller.restore_dns
    # does — otherwise a later --autostart launch sees DISENGAGED +
    # intent on and re-engages DNS the user explicitly restored.
    manager, guard = engaged_manager(tmp_path)
    Store(tmp_path).set_protection_intent(True)
    code = restore_dns_main(
        data_dir=tmp_path, manager_factory=lambda: manager, out=lambda *a: None
    )
    assert code == 0
    assert guard.load_backup() is None
    assert Store(tmp_path).protection_intent() is False


def test_failed_restore_keeps_protection_intent_on(tmp_path):
    manager, guard = engaged_manager(tmp_path)
    Store(tmp_path).set_protection_intent(True)
    manager.fail_on_set.add(("Wi-Fi", "IPv4"))
    code = restore_dns_main(
        data_dir=tmp_path, manager_factory=lambda: manager, out=lambda *a: None
    )
    assert code == 3
    assert guard.load_backup() is not None
    assert Store(tmp_path).protection_intent() is True


def test_nothing_held_is_success(tmp_path):
    manager = FakeDnsManager(ADAPTERS, elevated=True)
    code = restore_dns_main(
        data_dir=tmp_path, manager_factory=lambda: manager, out=lambda *a: None
    )
    assert code == 0


def test_failed_restore_keeps_the_record_and_returns_3(tmp_path):
    manager, guard = engaged_manager(tmp_path)
    manager.fail_on_set.add(("Wi-Fi", "IPv4"))
    code = restore_dns_main(
        data_dir=tmp_path, manager_factory=lambda: manager, out=lambda *a: None
    )
    assert code == 3
    assert guard.load_backup() is not None  # never retired unverified


def test_unelevated_restore_changes_nothing(tmp_path):
    manager, guard = engaged_manager(tmp_path)
    manager._elevated = False
    code = restore_dns_main(
        data_dir=tmp_path, manager_factory=lambda: manager, out=lambda *a: None
    )
    assert code == 3
    assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]


class TestAcquireInstance:
    """The one-host-per-user claim (Windows Phase 2 audit): two
    launches in the same instant can both probe before either
    claims the channel. The loser of the claim must re-probe and
    become a "show" — never a rival host."""

    def test_free_channel_becomes_the_host(self):
        server = object()
        role, got = acquire_instance(
            lambda: False, lambda: server, sleep=lambda s: None
        )
        assert role == "host" and got is server

    def test_a_running_host_turns_this_launch_into_a_show(self):
        listens = []
        role, got = acquire_instance(
            lambda: True,
            lambda: listens.append(True) or object(),
            sleep=lambda s: None,
        )
        assert role == "show" and got is None
        assert listens == []  # never even tried to claim

    def test_losing_the_claim_race_reprobes_and_shows(self):
        probes = iter([False, True])  # free at first, host by retry
        role, got = acquire_instance(
            lambda: next(probes), lambda: None, sleep=lambda s: None
        )
        assert role == "show" and got is None

    def test_a_channel_that_never_opens_runs_solo(self):
        role, got = acquire_instance(
            lambda: False, lambda: None, attempts=3, sleep=lambda s: None
        )
        assert role == "solo" and got is None
