"""Start-at-sign-in: the per-user Run registry value.

Windows' standard per-user mechanism for "start this when I sign
in" is one value under
``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run``. Sphinx
keeps exactly one value there, named ``Sphinx``, holding the
command that launches the tray host with ``--autostart`` (the flag
is what distinguishes a sign-in launch from the user opening the
app by hand — the host's startup discipline treats them
differently; see host.py).

This module is the whole of the mechanism, split so the policy is
testable off Windows:

- :func:`autostart_command` builds the command for the current
  launch shape (frozen exe, or the Python module from source).
- A *backend* reads/writes/deletes the one value. The production
  backend (:class:`WindowsRunRegistry`) uses ``winreg``; tests use
  a dict-backed stand-in with the same three methods.
- :class:`AutostartManager` holds the policy: "enabled" means the
  stored value *is* the command this build would write (a value
  left by an older install location is stale — reported as not
  enabled, and enabling again rewrites it to point at the current
  one). Nothing else about the registry is ever touched.
"""
from __future__ import annotations

import sys
from typing import Optional, Protocol

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE_NAME = "Sphinx"

#: The flag that marks a launch as "started by sign-in, not by hand".
AUTOSTART_FLAG = "--autostart"


def autostart_command() -> str:
    """The command the Run value holds for this build."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" {AUTOSTART_FLAG}'
    return f'"{sys.executable}" -m sphinx_win.app.main {AUTOSTART_FLAG}'


class RegistryBackend(Protocol):
    """The three operations the policy needs from the registry."""

    def get_value(self, name: str) -> Optional[str]: ...
    def set_value(self, name: str, value: str) -> None: ...
    def delete_value(self, name: str) -> None: ...


class WindowsRunRegistry:
    """The production backend: HKCU's Run key, via winreg.

    Raises RuntimeError off Windows — constructing it is the
    caller's signal that start-at-sign-in cannot be managed here.
    """

    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("The Run registry exists only on Windows.")
        import winreg

        self._winreg = winreg

    def _open(self, access):
        return self._winreg.OpenKey(
            self._winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, access
        )

    def get_value(self, name: str) -> Optional[str]:
        try:
            with self._open(self._winreg.KEY_READ) as key:
                value, _ = self._winreg.QueryValueEx(key, name)
        except FileNotFoundError:
            return None
        return str(value)

    def set_value(self, name: str, value: str) -> None:
        with self._open(self._winreg.KEY_SET_VALUE) as key:
            self._winreg.SetValueEx(key, name, 0, self._winreg.REG_SZ, value)

    def delete_value(self, name: str) -> None:
        try:
            with self._open(self._winreg.KEY_SET_VALUE) as key:
                self._winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass  # already gone — deletion is idempotent


class AutostartManager:
    """Policy over one Run value, given a backend and the command
    this build registers."""

    def __init__(self, backend: RegistryBackend, command: Optional[str] = None):
        self._backend = backend
        self.command = command if command is not None else autostart_command()

    def current_value(self) -> Optional[str]:
        return self._backend.get_value(RUN_VALUE_NAME)

    def is_enabled(self) -> bool:
        """True only when the stored value is this build's command.
        A value pointing anywhere else is a leftover from another
        location: not this build's autostart, and the shell shows
        it as off (offering to rewrite it by toggling on)."""
        return self.current_value() == self.command

    def enable(self) -> None:
        self._backend.set_value(RUN_VALUE_NAME, self.command)

    def disable(self) -> None:
        self._backend.delete_value(RUN_VALUE_NAME)

    def sync(self, enabled: bool) -> bool:
        """Make the registry match ``enabled``; returns the state
        actually in force afterwards (re-read, never assumed)."""
        if enabled:
            if not self.is_enabled():
                self.enable()
        else:
            if self.current_value() is not None:
                self.disable()
        return self.is_enabled()
