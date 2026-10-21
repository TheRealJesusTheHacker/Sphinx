"""Controller orchestration: the start/stop ordering that keeps the
machine safe, proven with a fake server and the fake DNS manager.
(The real server's socket behavior is covered in test_server.py and
in CI.)"""
import pytest

from sphinx_win.app.controller import SphinxController, StartError
from sphinx_win.core.store import Store
from sphinx_win.dnsmgmt.base import AdapterDns, NotElevatedError
from sphinx_win.dnsmgmt.fake import FakeDnsManager
from sphinx_win.dnsmgmt.guard import DnsState

ADAPTERS = [
    AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"]),
    AdapterDns("Wi-Fi", "IPv6", []),
]


class FakeServer:
    def __init__(self, engine, answers=True, bound=None):
        self.engine = engine
        self._answers = answers
        self._bound = bound
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        return self._bound or [("127.0.0.1", 53), ("::1", 53)]

    def answers_on(self, address, timeout=2.0):
        return self._answers

    def stop(self):
        self.stopped = True


def make_controller(tmp_path, answers=True, elevated=True, manager=None):
    store = Store(tmp_path / "data")
    manager = manager or FakeDnsManager(ADAPTERS, elevated=elevated)
    holder = {}

    def factory(engine):
        holder["server"] = FakeServer(engine, answers=answers)
        return holder["server"]

    controller = SphinxController(
        store, manager, tmp_path / "data", server_factory=factory
    )
    return controller, manager, holder


class TestStartStop:
    def test_happy_path(self, tmp_path):
        controller, manager, holder = make_controller(tmp_path)
        message = controller.start()
        assert controller.running
        assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]
        assert controller.dns_state() is DnsState.ENGAGED

        controller.stop()
        assert not controller.running
        assert holder["server"].stopped
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert controller.dns_state() is DnsState.DISENGAGED

    def test_unanswering_filter_never_gets_dns(self, tmp_path):
        controller, manager, holder = make_controller(tmp_path, answers=False)
        with pytest.raises(StartError):
            controller.start()
        assert holder["server"].stopped  # server shut back down
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert controller.guard.load_backup() is None

    def test_unelevated_start_touches_nothing(self, tmp_path):
        controller, manager, holder = make_controller(tmp_path, elevated=False)
        with pytest.raises(NotElevatedError):
            controller.start()
        assert holder["server"].stopped
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]

    def test_failed_restore_keeps_filter_running(self, tmp_path):
        controller, manager, holder = make_controller(tmp_path)
        controller.start()
        manager.fail_on_set.add(("Wi-Fi", "IPv4"))
        with pytest.raises(StartError):
            controller.stop()
        # The filter stays up so DNS keeps working, and says so.
        assert controller.running
        assert not holder["server"].stopped


class TestReload:
    def test_reload_applies_all_state(self, tmp_path):
        controller, _, _ = make_controller(tmp_path)
        assert not controller._current_lists().is_blocked("mine.example.com")
        controller.store.save_custom_block_entries(["mine.example.com"])
        controller.reload_lists()
        assert controller._current_lists().is_blocked("mine.example.com")
        assert controller._current_lists().is_blocked("sub.mine.example.com")


class TestPartialBind:
    """Windows audit (Phase 1): when the server could only bind one
    loopback family, the controller used to point BOTH families'
    DNS at it anyway — the unbound family aimed at a resolver that
    isn't answering. Only proven loopbacks are engaged now."""

    def test_unbound_family_dns_is_left_alone(self, tmp_path):
        store = Store(tmp_path / "data")
        manager = FakeDnsManager(ADAPTERS, elevated=True)
        controller = SphinxController(
            store,
            manager,
            tmp_path / "data",
            server_factory=lambda e: FakeServer(e, bound=[("127.0.0.1", 53)]),
        )
        controller.start()
        assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]
        assert manager.get_dns("Wi-Fi", "IPv6") == []  # never moved
        assert controller.dns_state() is DnsState.ENGAGED
        controller.stop()
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
        assert manager.get_dns("Wi-Fi", "IPv6") == []


class TestIntentRecording:
    """Windows Phase 2: the controller records the protection intent
    the tray host's sign-in resume honors — at successful transitions
    only, never at failed ones."""

    def test_start_and_stop_record_intent(self, tmp_path):
        controller, _, _ = make_controller(tmp_path)
        assert controller.store.protection_intent() is False
        controller.start()
        assert controller.store.protection_intent() is True
        controller.stop()
        assert controller.store.protection_intent() is False

    def test_failed_start_records_nothing(self, tmp_path):
        controller, _, _ = make_controller(tmp_path, answers=False)
        with pytest.raises(StartError):
            controller.start()
        assert controller.store.protection_intent() is False

    def test_failed_stop_keeps_intent_on(self, tmp_path):
        controller, manager, _ = make_controller(tmp_path)
        controller.start()
        manager.fail_on_set.add(("Wi-Fi", "IPv4"))
        with pytest.raises(StartError):
            controller.stop()
        # Protection is still on, so the intent still says on.
        assert controller.store.protection_intent() is True

    def test_leftover_restore_and_dismiss_record_off(self, tmp_path):
        controller, manager, _ = make_controller(tmp_path)
        controller.start()
        assert controller.store.protection_intent() is True
        # Simulate a crash + hand fix: DNS no longer points at the
        # filter, the backup remains — a leftover.
        manager.set_dns("Wi-Fi", "IPv4", ["192.168.1.1"])
        manager.set_dns("Wi-Fi", "IPv6", [])
        assert controller.dns_state() is DnsState.LEFTOVER
        assert controller.dismiss_leftover() is True
        assert controller.store.protection_intent() is False

    def test_hosting_settings_round_trip(self, tmp_path):
        controller, _, _ = make_controller(tmp_path)
        store = controller.store
        assert store.autostart_enabled() is False
        store.set_autostart_enabled(True)
        assert store.autostart_enabled() is True
        store.set_protection_intent(True)
        assert store.protection_intent() is True


class TestLogToggle:
    def test_turning_recording_off_does_not_erase_the_log(self, tmp_path):
        controller, _, _ = make_controller(tmp_path)
        controller.engine.query_log.record("ads.example.com", True, 1000)
        controller.set_log_enabled(False)
        # "Off" and "clear" are separate controls (FILTER-SPEC).
        assert len(controller.engine.query_log) == 1
        assert not controller.engine.log_enabled
