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
    def __init__(self, engine, answers=True):
        self.engine = engine
        self._answers = answers
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        return [("127.0.0.1", 53), ("::1", 53)]

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
