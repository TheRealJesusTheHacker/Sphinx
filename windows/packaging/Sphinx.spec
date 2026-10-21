# PyInstaller spec for the one-file Windows build: Sphinx.exe
#
# Run from the windows/ directory:
#   python -m PyInstaller packaging/Sphinx.spec --noconfirm \
#       --distpath dist --workpath build/pyi
#
# The bundled blocklist rides inside the exe as package data, at the
# same relative path the source tree uses (sphinx_win/data/), so the
# store finds it unchanged when frozen.
# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

WINDOWS_DIR = Path(SPECPATH).resolve().parent
SRC = WINDOWS_DIR / "src"

a = Analysis(
    [str(SRC / "sphinx_win" / "app" / "main.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=[
        (
            str(SRC / "sphinx_win" / "data" / "bundled-blocklist.txt"),
            "sphinx_win/data",
        )
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Sphinx",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    # No UAC manifest on purpose: a non-admin user must still be able
    # to open Sphinx and read its status. The app detects the missing
    # elevation itself and explains, in plain language, that turning
    # the filter on needs administrator rights.
    uac_admin=False,
)
