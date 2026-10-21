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


def test_main_window_constructs(tmp_path):
    from PySide6.QtWidgets import QApplication

    from sphinx_win.app.tray_app import MainWindow

    app = QApplication.instance() or QApplication([])
    store = Store(tmp_path / "data")
    manager = FakeDnsManager(
        [AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"])], elevated=True
    )
    controller = SphinxController(store, manager, tmp_path / "data")
    window = MainWindow(controller, elevated=True)
    window.show()
    app.processEvents()
    assert window.windowTitle().startswith("Sphinx")
    assert "off" in window.status_label.text().lower()
    assert window.toggle_button.isEnabled()
    window.close()
    app.processEvents()
