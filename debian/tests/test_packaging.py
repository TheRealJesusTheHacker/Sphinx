"""The .deb itself: it builds, it carries exactly the intended
payload, its blocklist is byte-identical to the canonical asset, its
metadata is honest, and its maintainer scripts keep the discipline
(postinst never touches DNS; prerm restores before removing)."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

DEBIAN_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = DEBIAN_DIR.parent
SRC = DEBIAN_DIR / "src" / "sphinx_deb"
CANONICAL_LIST = REPO_ROOT / "app" / "src" / "main" / "assets" / "bundled-blocklist.txt"

pytestmark = pytest.mark.skipif(
    shutil.which("dpkg-deb") is None, reason="dpkg-deb is not available"
)


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("dist")
    proc = subprocess.run(
        ["sh", str(DEBIAN_DIR / "packaging" / "build-deb.sh"), str(out)],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    debs = list(out.glob("sphinx_*_all.deb"))
    assert len(debs) == 1
    return debs[0]


def _field(deb, name):
    proc = subprocess.run(
        ["dpkg-deb", "-f", str(deb), name], capture_output=True, text=True
    )
    assert proc.returncode == 0
    return proc.stdout.strip()


def _payload_files(deb):
    proc = subprocess.run(
        ["dpkg-deb", "-c", str(deb)], capture_output=True, text=True
    )
    assert proc.returncode == 0
    files = set()
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 6 and not parts[-1].endswith("/"):
            files.add(parts[-1])
            # No payload file is group- or world-writable, whatever
            # the build host's umask was.
            perms = parts[0]
            assert perms[5] != "w" and perms[8] != "w", (perms, parts[-1])
    return files


def test_metadata(built):
    sys.path.insert(0, str(DEBIAN_DIR / "src"))
    import sphinx_deb

    assert _field(built, "Package") == "sphinx"
    assert _field(built, "Version") == sphinx_deb.__version__ == "0.2.1"
    # Pure Python + data: architecture "all" is the honest answer.
    assert _field(built, "Architecture") == "all"


def test_payload_is_exactly_the_intended_set(built):
    expected = {
        "./etc/sphinx/sphinx.conf",
        "./lib/systemd/system/sphinx.service",
        "./usr/bin/sphinx",
        "./usr/share/doc/sphinx/README.md",
        "./usr/share/sphinx/bundled-blocklist.txt",
    }
    for py in SRC.rglob("*.py"):
        expected.add(f"./usr/lib/sphinx/{py.relative_to(SRC.parent)}")
    payload = _payload_files(built)
    assert payload == expected
    assert not any("__pycache__" in p for p in payload)
    # Phase 2's parity modules ship inside the package — the store,
    # the updater, and the profile model the installed command and
    # daemon import. (Implied by the exact-set check above; pinned
    # by name because the phase's promise is that they are inside.)
    for module in ("core/store.py", "core/updater.py", "core/profiles.py"):
        assert f"./usr/lib/sphinx/sphinx_deb/{module}" in payload


def test_payload_blocklist_is_the_canonical_asset_byte_for_byte(built, tmp_path):
    root = tmp_path / "root"
    subprocess.run(["dpkg-deb", "-x", str(built), str(root)], check=True)
    shipped = root / "usr" / "share" / "sphinx" / "bundled-blocklist.txt"
    assert shipped.read_bytes() == CANONICAL_LIST.read_bytes()


def test_maintainer_scripts_present_and_disciplined(built, tmp_path):
    control_dir = tmp_path / "control"
    subprocess.run(["dpkg-deb", "-e", str(built), str(control_dir)], check=True)
    names = {p.name for p in control_dir.iterdir()}
    assert {"postinst", "prerm", "postrm", "conffiles"} <= names
    postinst = (control_dir / "postinst").read_text()
    prerm = (control_dir / "prerm").read_text()
    # Installing never changes DNS and never starts filtering. The
    # check runs on the script's executable lines — its echo text
    # legitimately *tells the user* the commands; what postinst must
    # never do is run them itself.
    executable = "\n".join(
        line
        for line in postinst.splitlines()
        if not line.strip().startswith(("#", "echo"))
    )
    for forbidden in (
        "resolvectl",
        "resolv.conf",
        "engage",
        "systemctl enable",
        "systemctl start",
        "systemctl restart",
    ):
        assert forbidden not in executable
    # Removal restores first, and a failed restore stops the removal.
    assert "sphinx restore" in prerm
    assert "exit 1" in prerm
    # The restore is gated on a saved record actually existing
    # (audit finding 4): with no record there is nothing Sphinx owns
    # to restore, and removal must not be trapped by an unrelated
    # loopback resolver on the machine.
    assert "dns-backup.json" in prerm


def test_maintainer_scripts_are_shellcheck_clean():
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("shellcheck is not available")
    scripts = [
        DEBIAN_DIR / "packaging" / name
        for name in ("postinst", "prerm", "postrm", "build-deb.sh", "sphinx")
    ]
    proc = subprocess.run(
        [shellcheck, "-s", "sh", *[str(s) for s in scripts]],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_installed_command_runs(built, tmp_path):
    root = tmp_path / "install"
    subprocess.run(["dpkg-deb", "-x", str(built), str(root)], check=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "usr" / "lib" / "sphinx")
    env["SPHINX_LIST"] = str(root / "usr" / "share" / "sphinx" / "bundled-blocklist.txt")
    env["SPHINX_STATE_DIR"] = str(tmp_path / "state")
    env["SPHINX_RUNTIME_DIR"] = str(tmp_path / "run")
    proc = subprocess.run(
        [sys.executable, "-m", "sphinx_deb", "status"],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Sphinx on this machine" in proc.stdout
    assert "71,491 domains" in proc.stdout
