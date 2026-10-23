"""The window's VPN section: the picker starts EMPTY (the spec's
honest first-run state), import paths add servers with refusals
named, the mode statements sit where the mode is offered, and
connect/disconnect drive the controller's mode model."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from sphinx_win.app.controller import SphinxController
from sphinx_win.app.tray_app import MainWindow
from sphinx_win.core.store import Store
from sphinx_win.dnsmgmt.base import AdapterDns
from sphinx_win.dnsmgmt.fake import FakeDnsManager
from sphinx_win.tunnelmgmt.fake import FakeTunnelManager

from test_vpn_mode import WG_HOME, WG_OFFICE, FakeServer


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def make_window(tmp_path, elevated=True):
    store = Store(tmp_path / "data")
    manager = FakeDnsManager(
        [AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"])], elevated=True
    )
    controller = SphinxController(
        store,
        manager,
        tmp_path / "data",
        server_factory=lambda e: FakeServer(e),
        tunnel_manager=FakeTunnelManager(),
        resolver=lambda host: "198.51.100.23",
        handshake_wait_s=0.5,
    )
    return MainWindow(controller, elevated=elevated), controller


def test_server_picker_starts_empty(app, tmp_path):
    window, _ = make_window(tmp_path)
    assert window.vpn_combo.count() == 0
    assert "No servers yet" in window.vpn_status_label.text()


def test_import_adds_a_server_and_refusals_are_named(app, tmp_path):
    window, _ = make_window(tmp_path)
    assert window.import_vpn_text(WG_HOME) is True
    assert window.vpn_combo.count() == 1
    assert window.vpn_combo.currentText() == "Home Server"
    assert window.import_vpn_text("[Interface]\nPrivateKey = nope\n") is False
    assert "valid WireGuard key" in window.vpn_status_label.text()
    assert window.vpn_combo.count() == 1  # nothing half-stored


def test_mode_statements_where_offered(app, tmp_path):
    window, _ = make_window(tmp_path)
    window.import_vpn_text(WG_OFFICE)  # a split tunnel
    assert "some traffic" in window.vpn_mode_note.text()
    window.vpn_blocker_checkbox.setChecked(False)
    assert "ads are not blocked" in window.vpn_mode_note.text().lower()
    window.vpn_blocker_checkbox.setChecked(True)
    assert "VPN + Blocker" in window.vpn_mode_note.text()


def test_connect_disconnect_through_the_window(app, tmp_path):
    window, controller = make_window(tmp_path)
    window.import_vpn_text(WG_HOME)
    window._on_vpn_connect()
    assert controller.vpn_active()
    assert "VPN on — Home Server" in window.vpn_status_label.text()
    window._on_vpn_disconnect()
    assert not controller.vpn_active()
    assert "VPN is off" in window.vpn_status_label.text()


def test_unelevated_window_disables_connect_and_says_why(app, tmp_path):
    window, _ = make_window(tmp_path, elevated=False)
    assert not window.vpn_connect_button.isEnabled()
    window.import_vpn_text(WG_HOME)
    window._on_vpn_connect()
    assert "administrator" in window.vpn_status_label.text()
    assert "will not ask in a loop" in window.vpn_status_label.text() or \
        "not ask in a loop" in window.vpn_status_label.text()
