"""Sphinx for Windows — entry point.

Run from source:  python -m sphinx_win.app.main
Frozen (PyInstaller one-file): Sphinx.exe

Launch shapes:
  Sphinx.exe                     the tray host + window (Phase 2's host:
                                 one process owns the filter, the tray,
                                 and the window — see tray_app.TrayHost)
  Sphinx.exe --autostart         the same host, launched by sign-in
                                 (the Run value writes exactly this)
  Sphinx.exe --restore-dns       headless: put back the DNS settings
                                 Sphinx holds, if any, and exit with a
                                 code — the installer's uninstall hook
                                 (0 = restored or nothing to restore,
                                 3 = restore failed or impossible)

A second launch of the host does not start a rival: it asks the
running host to show its window and exits (QLocalServer, one per
user).

Data lives in one directory:
  - SPHINX_DATA_DIR, when set;
  - next to the exe (a "data" folder) when a portable.txt marker sits
    beside a frozen exe — the portable edition;
  - otherwise %LOCALAPPDATA%\\Sphinx (falling back to ~/Sphinx).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Absolute imports throughout this module, deliberately: PyInstaller
# executes the entry script outside the package, where relative
# imports fail. The rest of the package uses relative imports and is
# imported *through* this module (or as sphinx_win.app.main via -m),
# so both launch shapes work.
from sphinx_win.core.store import Store
from sphinx_win.dnsmgmt.base import NotElevatedError
from sphinx_win.dnsmgmt.guard import DnsGuard
from sphinx_win.dnsmgmt.windows_impl import WindowsDnsManager, is_user_admin
from sphinx_win.app.controller import SphinxController
from sphinx_win.app.host import instance_name, parse_launch_args


def default_data_dir() -> Path:
    override = os.environ.get("SPHINX_DATA_DIR")
    if override:
        return Path(override)
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        if (exe_dir / "portable.txt").exists():
            return exe_dir / "data"
        base = os.environ.get("LOCALAPPDATA")
        return (Path(base) if base else Path.home()) / "Sphinx"
    return Path.home() / ".sphinx"


def build_controller(data_dir: Path) -> SphinxController:
    store = Store(data_dir)
    manager = WindowsDnsManager()
    return SphinxController(store, manager, data_dir)


def restore_dns_main(data_dir=None, manager_factory=None, out=print) -> int:
    """The headless restore: if Sphinx holds saved DNS settings,
    put them back (the guard verifies each one and retires the
    record only on a verified restore); if it holds none, there is
    nothing to do and that is success. Exit code 3 means the
    restore could not be completed — the record is kept, and the
    message says why. Used by the installer's uninstaller, which
    aborts rather than strand a machine when this fails."""
    data_dir = Path(data_dir) if data_dir is not None else default_data_dir()
    try:
        manager = (manager_factory or WindowsDnsManager)()
        guard = DnsGuard(manager, data_dir)
        if guard.load_backup() is None:
            out("Sphinx holds no saved DNS settings; nothing to restore.")
            return 0
        result = guard.disengage()
    except NotElevatedError as e:
        out(str(e))
        return 3
    except Exception as e:
        out(f"Sphinx could not restore the saved DNS settings ({e}).")
        return 3
    out(result.message)
    return 0 if result.ok else 3


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    launch = parse_launch_args(argv)
    if launch.restore_dns:
        return restore_dns_main()

    from PySide6.QtNetwork import QLocalServer, QLocalSocket
    from PySide6.QtWidgets import QApplication

    from sphinx_win.app.autostart import AutostartManager, WindowsRunRegistry
    from sphinx_win.app.tray_app import MainWindow, TrayHost

    app = QApplication(sys.argv)
    app.setApplicationName("Sphinx")
    app.setOrganizationName("Sentinel Safeguard")
    # The tray is the app's home now: closing every window must not
    # quit the host (the window's close goes to the tray instead).
    app.setQuitOnLastWindowClosed(False)

    # Single instance per user: a second launch shows the running
    # host's window and exits — two hosts would fight over one DNS
    # state, and the state has exactly one owner by design.
    name = instance_name()
    probe = QLocalSocket()
    probe.connectToServer(name)
    if probe.waitForConnected(500):
        probe.write(b"show")
        probe.flush()
        probe.waitForBytesWritten(500)
        probe.disconnectFromServer()
        return 0
    server = QLocalServer()
    QLocalServer.removeServer(name)  # clear a crashed host's leftover
    if not server.listen(name):
        server = None  # best effort: run without the single-instance net

    def release_instance():
        if server is not None:
            server.close()
            QLocalServer.removeServer(name)

    controller = build_controller(default_data_dir())
    elevated = is_user_admin()
    try:
        autostart_manager = AutostartManager(WindowsRunRegistry())
    except RuntimeError:
        autostart_manager = None  # not Windows: nothing to manage
    window = MainWindow(controller, elevated=elevated)
    host = TrayHost(
        window,
        controller,
        elevated=elevated,
        launch=launch,
        autostart_manager=autostart_manager,
        release_instance=release_instance,
    )
    if server is not None:

        def _on_new_connection():
            pending = server.nextPendingConnection()
            if pending is not None:
                pending.readAll()
                pending.disconnectFromServer()
            window.showNormal()
            window.raise_()
            window.activateWindow()

        server.newConnection.connect(_on_new_connection)

    outcome = host.run_startup()
    if outcome.exit_now:
        release_instance()
        return 0
    if not launch.autostart or outcome.attention:
        window.show()
    elif outcome.summary:
        host.notify(outcome.summary)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
