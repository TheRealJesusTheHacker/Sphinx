"""The window's Public volunteer servers section (Phase 2): a
distinct section that is never pre-enabled, the disclosure at
the point of use AND in the connect confirmation, fetching only
on purpose, dead-feed honesty, and connecting a row through the
mode model. The feed here is the synthetic fixture — the suite
never touches the live feed."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from sphinx_win.app.controller import SphinxController
from sphinx_win.app.tray_app import MainWindow
from sphinx_win.core.store import Store
from sphinx_win.core.vpngate import VPNGATE_DISCLOSURE
from sphinx_win.dnsmgmt.base import AdapterDns
from sphinx_win.dnsmgmt.fake import FakeDnsManager
from sphinx_win.tunnelmgmt.fake import FakeTunnelManager
from sphinx_win.tunnelmgmt.openvpn_fake import FakeOpenVpnManager

from test_vpngate import FIXTURE_FEED
from test_vpn_mode import FakeServer


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def make_window(tmp_path, elevated=True, fetcher=None, openvpn=None):
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
        openvpn_manager=openvpn
        if openvpn is not None
        else FakeOpenVpnManager(pushed_dns=["10.8.0.53"]),
        resolver=lambda host: "198.51.100.23",
        handshake_wait_s=0.5,
    )
    window = MainWindow(controller, elevated=elevated, public_fetcher=fetcher)
    return window, controller


def test_section_is_distinct_and_never_pre_enabled(app, tmp_path):
    calls = []

    def counting_fetcher():
        calls.append(1)
        return FIXTURE_FEED

    window, _ = make_window(tmp_path, fetcher=counting_fetcher)
    # The section exists as its own place, with its own words…
    assert window.public_disclosure_label.text() == VPNGATE_DISCLOSURE
    assert "strangers" in window.public_disclosure_label.text()
    # …the list starts EMPTY and unfetched — opened on purpose,
    # never pre-enabled…
    assert window.public_servers_list.count() == 0
    assert calls == []
    # …and it is not the user's picker: the profile combo is
    # untouched by the section's existence.
    assert window.vpn_combo.count() == 0


def test_fetch_populates_labeled_rows_with_freshness(app, tmp_path):
    window, _ = make_window(tmp_path, fetcher=lambda: FIXTURE_FEED)
    listing = window.fetch_public_servers()
    assert listing.source == "live"
    labels = [
        window.public_servers_list.item(i).text()
        for i in range(window.public_servers_list.count())
    ]
    assert labels == [
        "Public volunteer server — Japan (public-node-1.example.jp)",
        "Public volunteer server — Korea Republic of "
        "(public-node-2.example.kr)",
    ]
    assert "fetched just now" in window.public_status_label.text()


def test_dead_feed_no_cache_is_an_honest_empty_ui(app, tmp_path):
    def dead():
        raise OSError("feed down")

    window, _ = make_window(tmp_path, fetcher=dead)
    window.fetch_public_servers()
    assert window.public_servers_list.count() == 0
    assert "Couldn't fetch the list" in window.public_status_label.text()


def test_disclosure_rides_the_connect_confirmation(app, tmp_path):
    window, _ = make_window(tmp_path, fetcher=lambda: FIXTURE_FEED)
    text = window.public_connect_confirmation_text(
        "Public volunteer server — Japan (public-node-1.example.jp)"
    )
    assert VPNGATE_DISCLOSURE in text
    assert "The operator can see your traffic" in text
    assert "three months or more" in text


def test_connect_requires_the_confirmation(app, tmp_path):
    window, controller = make_window(tmp_path, fetcher=lambda: FIXTURE_FEED)
    window.fetch_public_servers()
    window.public_servers_list.setCurrentRow(0)
    # Unconfirmed: refused, nothing connected, nothing stored.
    assert window.connect_selected_public_server(confirmed=False) is False
    assert not controller.vpn_active()
    assert controller.tunnel_store.profile_names() == []
    # Confirmed: the row becomes an OpenVPN profile under its
    # public label and connects through the mode model.
    assert window.connect_selected_public_server(confirmed=True) is True
    assert controller.vpn_active()
    assert controller.vpn_status().profile_name == (
        "Public volunteer server — Japan (public-node-1.example.jp)"
    )
    assert controller.tunnel_store.profile_names() == [
        "Public volunteer server — Japan (public-node-1.example.jp)"
    ]
    window._on_vpn_disconnect()
    assert not controller.vpn_active()


def test_public_connect_without_openvpn_installed_says_so(app, tmp_path):
    window, controller = make_window(
        tmp_path,
        fetcher=lambda: FIXTURE_FEED,
        openvpn=FakeOpenVpnManager(installed=False),
    )
    window.fetch_public_servers()
    window.public_servers_list.setCurrentRow(0)
    assert window.connect_selected_public_server(confirmed=True) is False
    assert "OpenVPN isn't installed" in window.public_status_label.text()
    assert not controller.vpn_active()
