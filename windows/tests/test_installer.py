"""The installer script's load-bearing promises, pinned as text:
Inno Setup cannot run on this VM, and a future edit must not be
able to silently drop the pieces a user's networking depends on.
CI compiling the script is the other half of the proof."""
import sys
from pathlib import Path

ISS = (
    Path(__file__).resolve().parent.parent / "packaging" / "Sphinx.iss"
).read_text(encoding="utf-8")


def test_uninstall_restores_dns_before_removing_anything():
    # InitializeUninstall is the hook that runs before any file is
    # removed; it must call the headless restore and abort on failure.
    assert "InitializeUninstall" in ISS
    assert "--restore-dns" in ISS
    assert "Result := False" in ISS
    # The abort fires on ANY nonzero exit from the headless restore
    # (its contract is 0 = restored or nothing held, 3 = failed) —
    # not on one magic value the two sides could drift apart on.
    assert "ResultCode <> 0" in ISS


def test_signin_entry_is_the_apps_own_value_and_removed_on_uninstall():
    assert "CurrentVersion\\Run" in ISS
    assert 'ValueName: "Sphinx"' in ISS
    assert "--autostart" in ISS
    assert "uninsdeletevalue" in ISS


def test_installer_version_matches_the_package():
    from sphinx_win import __version__

    assert f'#define AppVersion "{__version__}"' in ISS


def _iss_run_valuedata() -> str:
    """The decoded sign-in command the installer writes: the
    ValueData parameter with Inno's doubled-quote escapes undone
    ({app} left in place for the caller to substitute)."""
    raw = ISS.split("ValueData:", 1)[1].split(";", 1)[0].strip()
    assert raw.startswith('"') and raw.endswith('"')
    return raw[1:-1].replace('""', '"')


def test_installer_writes_the_apps_own_run_key(monkeypatch):
    # One mechanism, two writers: the installer's key path and
    # value name must be the app's own constants, so the two can
    # never drift into two different entries (Windows Phase 2
    # audit).
    from sphinx_win.app import autostart

    assert f'Subkey: "{autostart.RUN_KEY_PATH}"' in ISS
    assert f'ValueName: "{autostart.RUN_VALUE_NAME}"' in ISS


def test_installer_signin_value_is_the_apps_autostart_command(monkeypatch):
    # The app's checkbox reads "enabled" only when the stored value
    # is exactly the command this build would write. The installer
    # is the other writer of that value: if its command differed
    # by so much as the quoting, an installer-set sign-in start
    # would show as OFF in the app while Windows still launched it
    # — the status would lie. Pin the two writers to one string.
    from sphinx_win.app import autostart

    install_dir = r"C:\Program Files\Sphinx"
    monkeypatch.setattr(sys, "executable", install_dir + r"\Sphinx.exe")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    written = _iss_run_valuedata().replace("{app}", install_dir)
    assert written == autostart.autostart_command()
    assert written.endswith(autostart.AUTOSTART_FLAG)
