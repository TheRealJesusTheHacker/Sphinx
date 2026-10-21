"""The installer script's load-bearing promises, pinned as text:
Inno Setup cannot run on this VM, and a future edit must not be
able to silently drop the pieces a user's networking depends on.
CI compiling the script is the other half of the proof."""
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


def test_signin_entry_is_the_apps_own_value_and_removed_on_uninstall():
    assert "CurrentVersion\\Run" in ISS
    assert 'ValueName: "Sphinx"' in ISS
    assert "--autostart" in ISS
    assert "uninsdeletevalue" in ISS


def test_installer_version_matches_the_package():
    from sphinx_win import __version__

    assert f'#define AppVersion "{__version__}"' in ISS
