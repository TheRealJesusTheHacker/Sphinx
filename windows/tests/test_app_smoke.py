"""UI construction smoke test. Skipped wherever PySide6 isn't
installed (the pure core suites carry the logic); CI installs it."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from sphinx_win.app.controller import SphinxController  # noqa: E402
from sphinx_win.core.store import Store  # noqa: E402
from sphinx_win.dnsmgmt.base import AdapterDns  # noqa: E402
from sphinx_win.dnsmgmt.fake import FakeDnsManager  # noqa: E402

ADAPTERS = [
    AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"]),
    AdapterDns("Wi-Fi", "IPv6", []),
]


class FakeServer:
    def __init__(self, engine):
        self.engine = engine
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        return [("127.0.0.1", 53), ("::1", 53)]

    def answers_on(self, address, timeout=2.0):
        return True

    def stop(self):
        self.stopped = True


def make_window(tmp_path, elevated=True):
    from PySide6.QtWidgets import QApplication

    from sphinx_win.app.tray_app import MainWindow

    app = QApplication.instance() or QApplication([])
    store = Store(tmp_path / "data")
    manager = FakeDnsManager(ADAPTERS, elevated=elevated)
    controller = SphinxController(
        store, manager, tmp_path / "data", server_factory=FakeServer
    )
    window = MainWindow(controller, elevated=elevated)
    return app, window, controller, manager


def test_main_window_constructs(tmp_path):
    app, window, controller, manager = make_window(tmp_path)
    window.show()
    app.processEvents()
    assert window.windowTitle().startswith("Sphinx")
    assert "off" in window.status_label.text().lower()
    assert window.toggle_button.isEnabled()
    window.close()
    app.processEvents()


class TestTrayHost:
    def build_host(self, tmp_path, elevated=True, **host_kw):
        from sphinx_win.app.host import LaunchOptions
        from sphinx_win.app.tray_app import TrayHost

        app, window, controller, manager = make_window(
            tmp_path, elevated=elevated
        )
        host = TrayHost(
            window,
            controller,
            elevated=elevated,
            launch=host_kw.pop("launch", LaunchOptions()),
            **host_kw,
        )
        return app, window, controller, manager, host

    def test_host_attaches_and_reads_autostart_state(self, tmp_path):
        from sphinx_win.app.autostart import AutostartManager

        class DictRegistry:
            def __init__(self):
                self.values = {}

            def get_value(self, name):
                return self.values.get(name)

            def set_value(self, name, value):
                self.values[name] = value

            def delete_value(self, name):
                self.values.pop(name, None)

        registry = DictRegistry()
        mgr = AutostartManager(registry, command='"X" --autostart')
        app, window, controller, manager, host = self.build_host(
            tmp_path, autostart_manager=mgr
        )
        assert window._host is host
        assert host.autostart_state() is False
        assert window.autostart_checkbox.isChecked() is False
        assert host.set_autostart(True) is True
        assert controller.store.autostart_enabled() is True
        assert host.set_autostart(False) is False

    def test_close_goes_to_the_tray_and_stops_nothing(
        self, tmp_path, monkeypatch
    ):
        from PySide6.QtGui import QCloseEvent

        app, window, controller, manager, host = self.build_host(tmp_path)
        controller.start()
        assert controller.running
        monkeypatch.setattr(host, "tray_available", lambda: True)
        event = QCloseEvent()
        window.closeEvent(event)
        assert not event.isAccepted()  # hidden, not closed
        assert controller.running  # protection untouched

    def test_quit_runs_the_audited_stop(self, tmp_path):
        quit_calls = []
        app, window, controller, manager, host = self.build_host(
            tmp_path, quit_fn=lambda: quit_calls.append(True)
        )
        controller.start()
        assert host.quit() is True
        assert quit_calls == [True]
        assert not controller.running
        assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]

    def test_quit_refuses_when_the_restore_fails(
        self, tmp_path, monkeypatch
    ):
        import sphinx_win.app.tray_app as tray_app

        monkeypatch.setattr(
            tray_app.QMessageBox, "warning", staticmethod(lambda *a, **k: 0)
        )
        quit_calls = []
        app, window, controller, manager, host = self.build_host(
            tmp_path, quit_fn=lambda: quit_calls.append(True)
        )
        controller.start()
        manager.fail_on_set.add(("Wi-Fi", "IPv4"))
        assert host.quit() is False
        assert quit_calls == []  # never quit over a failed restore
        assert controller.running

    def test_quit_while_engaged_but_not_running_needs_confirmation(
        self, tmp_path, monkeypatch
    ):
        # W-2: after a reboot into NEEDS_ADMIN the host is idle but
        # DNS still points at Sphinx. Quitting then must warn that
        # the machine stays pointed at an unserved resolver and
        # require an explicit confirmation — never exit silently.
        import sphinx_win.app.tray_app as tray_app

        answers = []
        asked = []

        def fake_question(*a, **k):
            asked.append(a)
            return answers.pop(0)

        monkeypatch.setattr(
            tray_app.QMessageBox, "question", staticmethod(fake_question)
        )
        quit_calls = []
        app, window, controller, manager, host = self.build_host(
            tmp_path, quit_fn=lambda: quit_calls.append(True)
        )
        controller.start()  # engage, as the previous run did
        controller.server.stop()
        controller.running = False  # this host serves nothing
        from sphinx_win.dnsmgmt.guard import DnsState

        assert controller.dns_state() is DnsState.ENGAGED

        answers.append(tray_app.QMessageBox.StandardButton.No)
        assert host.quit() is False
        assert quit_calls == []  # not confirmed: the host stays
        assert len(asked) == 1
        text = " ".join(str(part) for part in asked[0])
        assert "still points at Sphinx" in text
        assert "administrator" in text

        answers.append(tray_app.QMessageBox.StandardButton.Yes)
        assert host.quit() is True
        assert quit_calls == [True]  # confirmed: the host may go
        # Quitting changes no DNS settings (that needs elevation).
        assert manager.get_dns("Wi-Fi", "IPv4") == ["127.0.0.1"]

    def test_quit_while_disengaged_needs_no_confirmation(
        self, tmp_path, monkeypatch
    ):
        import sphinx_win.app.tray_app as tray_app

        def fail_question(*a, **k):  # pragma: no cover - must not run
            raise AssertionError("no warning expected when disengaged")

        monkeypatch.setattr(
            tray_app.QMessageBox, "question", staticmethod(fail_question)
        )
        quit_calls = []
        app, window, controller, manager, host = self.build_host(
            tmp_path, quit_fn=lambda: quit_calls.append(True)
        )
        assert host.quit() is True
        assert quit_calls == [True]

    def test_startup_resumes_an_existing_engagement(self, tmp_path):
        app, window, controller, manager, host = self.build_host(tmp_path)
        controller.start()  # engage, as the previous run did
        controller.server.stop()
        controller.running = False
        outcome = host.run_startup()
        assert controller.running  # RESUME re-served the engagement
        assert not outcome.exit_now and not outcome.attention

    def test_startup_needs_admin_without_a_prompt_loop(self, tmp_path):
        from sphinx_win.app.host import LaunchOptions

        elevate_calls = []
        app, window, controller, manager, host = self.build_host(
            tmp_path,
            elevated=False,
            launch=LaunchOptions(autostart=True),
            elevate_fn=lambda args: elevate_calls.append(args) or False,
        )
        controller.store.set_protection_intent(True)
        outcome = host.run_startup()
        assert host.needs_admin
        assert not outcome.exit_now
        assert len(elevate_calls) == 1  # asked once, then waits
        assert not controller.running
