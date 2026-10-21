"""Sphinx for Windows — entry point.

Run from source:  python -m sphinx_win.app.main
Frozen (PyInstaller one-file): Sphinx.exe

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
from sphinx_win.dnsmgmt.windows_impl import WindowsDnsManager, is_user_admin
from sphinx_win.app.controller import SphinxController


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


def main() -> int:
    from PySide6.QtWidgets import QApplication

    from sphinx_win.app.tray_app import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Sphinx")
    app.setOrganizationName("Sentinel Safeguard")
    controller = build_controller(default_data_dir())
    window = MainWindow(controller, elevated=is_user_admin())
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
