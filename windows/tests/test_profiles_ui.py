"""The Profiles section of the window (Phase 3), headless: the
section exists, and its dialog-free helpers do what the buttons
promise — create snapshots the live rules, a switch lands the
whole profile in the live editors and the filter, a delete removes
only the snapshot. Plus the tray icon's three palette states.

Skipped wherever PySide6 isn't installed (the store suites carry
the logic); CI installs it.
"""
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


def make_window(tmp_path):
    from PySide6.QtWidgets import QApplication

    from sphinx_win.app.tray_app import MainWindow

    app = QApplication.instance() or QApplication([])
    store = Store(tmp_path / "data")
    manager = FakeDnsManager(ADAPTERS, elevated=True)
    controller = SphinxController(
        store, manager, tmp_path / "data", server_factory=FakeServer
    )
    window = MainWindow(controller, elevated=True)
    return app, window, controller


def editor_texts(widget):
    return [widget.item(i).text() for i in range(widget.count())]


def test_window_has_an_empty_profiles_section(tmp_path):
    app, window, controller = make_window(tmp_path)
    assert "No profiles yet" in window.profile_status_label.text()
    assert window.profile_combo.count() == 0
    assert not window.profile_switch_button.isEnabled()
    app.processEvents()


def test_create_switch_delete_through_the_window(tmp_path):
    app, window, controller = make_window(tmp_path)
    store = controller.store

    # Rules for profile A, created through the window's helper.
    store.save_custom_block_entries(["a.example.com"])
    assert window.create_profile_named("A") is True
    assert window.create_profile_named("A") is False  # duplicate refused
    assert window.create_profile_named("bad\tname") is False
    assert "A" in window.profile_status_label.text()

    # A second profile, B, holding different rules.
    assert window.create_profile_named("B") is True
    store.save_custom_block_entries(["b.example.com"])  # write-through to B
    store.save_allowlist(["bank.example.com"])

    # Switch to A: the editors and the filter both land on A whole.
    assert window.switch_profile_named("A") is True
    assert editor_texts(window.custom_editor) == ["a.example.com"]
    assert editor_texts(window.allow_editor) == []
    assert controller._current_lists().is_blocked("a.example.com")
    assert not controller._current_lists().is_blocked("b.example.com")
    # B's snapshot survived the switch untouched.
    profile_b = store.load_profile_set().profile("B")
    assert profile_b.state.custom_block_entries == {"b.example.com"}
    assert profile_b.state.allowlist_entries == {"bank.example.com"}

    # Switching to a profile that doesn't exist changes nothing.
    assert window.switch_profile_named("Ghost") is False
    assert editor_texts(window.custom_editor) == ["a.example.com"]

    # Deleting the active profile keeps the live rules in force.
    assert window.delete_profile_named("A") is True
    assert store.load_profile_set().active_name is None
    assert editor_texts(window.custom_editor) == ["a.example.com"]
    assert window.profile_combo.count() == 1
    app.processEvents()


def test_tray_icon_states_carry_the_palette():
    from PySide6.QtGui import QImage
    from PySide6.QtWidgets import QApplication

    from sphinx_win.app import theme
    from sphinx_win.app.tray_app import sphinx_icon

    QApplication.instance() or QApplication([])

    def colors_present(state):
        pixmap = sphinx_icon(state).pixmap(64, 64)
        image = pixmap.toImage().convertToFormat(QImage.Format.Format_ARGB32)
        found = set()
        for y in range(image.height()):
            for x in range(image.width()):
                found.add(image.pixelColor(x, y).name().lower())
        return found

    off = colors_present("off")
    on = colors_present("on")
    attention = colors_present("attention")
    assert theme.BRONZE_MUTED.lower() in off
    assert theme.BRONZE.lower() in on
    assert theme.BRONZE_SOFT.lower() in on
    assert theme.DANGER.lower() in attention
    assert theme.DANGER.lower() not in on
