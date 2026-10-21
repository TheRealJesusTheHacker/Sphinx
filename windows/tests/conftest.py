import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def _qt_widgets_do_not_outlive_their_test():
    """Deterministic Qt teardown after every test (Windows Phase 3
    audit item).

    The UI tests build real windows and tray hosts. A MainWindow
    carries a one-second refresh timer, and a host carries a tray
    icon and its menu. Tests that simply drop their references
    leave those QObjects alive — timers armed, in Qt's registries —
    for the rest of the process. Later tests pump the event loop,
    and at interpreter shutdown PySide6 destroys the accumulated
    objects in arbitrary order: the suite printed a green summary
    and then segfaulted or aborted in Qt teardown (reproduced:
    test_app_smoke.py + test_profiles_ui.py together aborted 3/3;
    the full suite likewise). The shipped app's lifecycle — one
    window, one host, quit through QApplication — probes clean;
    this is a suite-hygiene defect, fixed here: after each test,
    every top-level widget has its timers stopped and is destroyed
    through deleteLater with the deferred deletes pumped dry, so
    no Qt object outlives the test that created it. Destruction
    deliberately bypasses closeEvent: the close discipline is
    product behavior, exercised directly by the tests that call
    close()/closeEvent themselves — teardown must not re-enter it
    (a refused close would raise message boxes mid-teardown).

    A no-op wherever PySide6 isn't installed (the pure-core runs)
    or no application exists yet.
    """
    yield
    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication, QSystemTrayIcon
    except Exception:
        return
    app = QApplication.instance()
    if app is None:
        return
    for widget in list(app.topLevelWidgets()):
        for tray in widget.findChildren(QSystemTrayIcon):
            menu = tray.contextMenu()
            if menu is not None:
                menu.deleteLater()
            tray.hide()
        for timer in widget.findChildren(QTimer):
            timer.stop()
        widget.deleteLater()
    app.processEvents()
    app.sendPostedEvents()
    app.processEvents()
