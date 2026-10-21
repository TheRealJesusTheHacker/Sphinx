"""The headless --restore-dns mode (app/main.py): the installer's
uninstall hook. It must restore exactly what the guard holds, keep
the record when a restore fails, and treat "nothing held" as
success."""
from sphinx_win.app.main import restore_dns_main
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
