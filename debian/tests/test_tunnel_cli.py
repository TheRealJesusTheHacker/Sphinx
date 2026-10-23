"""The `sphinx vpn` command surface: profile import/export/
remove/create, the OpenVPN connect refusal, and status honesty —
in the edition's existing CLI voice."""
import shutil

import pytest

from sphinx_deb import cli

WG = (
    "# Sphinx profile: Home Server\n"
    "[Interface]\n"
    "PrivateKey = hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=\n"
    "Address = 10.8.0.2/32\n"
    "DNS = 10.8.0.1\n"
    "\n"
    "[Peer]\n"
    "PublicKey = q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=\n"
    "Endpoint = vpn.example.com:51820\n"
    "AllowedIPs = 0.0.0.0/0\n"
)

OPENVPN = (
    "client\ndev tun\nproto udp\nremote vpn-node.example.org 1194\n"
    "resolv-retry infinite\nnobind\npersist-key\npersist-tun\n"
    "<ca>\n-----BEGIN CERTIFICATE-----\nEXAMPLE-CERTIFICATE-NOT-REAL\n"
    "-----END CERTIFICATE-----\n</ca>\n"
)

BAD = WG.replace("hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=", "too-short")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SPHINX_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SPHINX_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setattr(cli, "_is_root", lambda: True)
    return tmp_path


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return str(path)


def test_profile_import_list_export_remove(env, capsys):
    path = _write(env, "home.conf", WG)
    assert cli.main(["vpn", "profile", "import", path]) == 0
    out = capsys.readouterr().out
    assert "Home Server" in out and "WireGuard" in out
    assert cli.main(["vpn", "profile", "list"]) == 0
    out = capsys.readouterr().out
    assert "Home Server" in out and "all traffic" in out
    assert cli.main(["vpn", "profile", "export", "Home Server"]) == 0
    assert capsys.readouterr().out == WG
    assert cli.main(["vpn", "profile", "remove", "Home Server"]) == 0
    assert cli.main(["vpn", "profile", "list"]) == 0
    assert "starts" in capsys.readouterr().out  # the empty-list truth


def test_profile_import_refusal_names_the_corpus_reason(env, capsys):
    path = _write(env, "bad.conf", BAD)
    assert cli.main(["vpn", "profile", "import", path]) == cli.EXIT_REFUSED
    out = capsys.readouterr().out
    assert "invalid-key" in out
    # And nothing was imported.
    assert cli.main(["vpn", "profile", "list"]) == 0
    assert "No server profiles yet" in capsys.readouterr().out


def test_openvpn_imports_labeled_and_connect_is_refused(env, capsys):
    path = _write(env, "node.ovpn", OPENVPN)
    assert cli.main(["vpn", "profile", "import", "--name", "Node", path]) == 0
    out = capsys.readouterr().out
    assert "OpenVPN" in out and "Phase 2" not in out  # Phase 2: connectable now
    assert cli.main(["vpn", "profile", "list"]) == 0
    assert "OpenVPN" in capsys.readouterr().out
    # Connecting on a test machine (not root / no openvpn) is an
    # honest refusal, never a claim of connection.
    assert cli.main(["vpn", "connect", "Node"]) == cli.EXIT_REFUSED


def test_vpn_status_is_honest_when_off(env, capsys):
    assert cli.main(["vpn", "status"]) == 0
    assert "VPN: off" in capsys.readouterr().out


def test_profile_create_without_wg_is_an_honest_refusal(env, capsys):
    if shutil.which("wg") is not None:
        pytest.skip("wg is installed here; the refusal path is CI's fake-runner tests")
    rc = cli.main([
        "vpn", "profile", "create", "Mine",
        "--server-key", "q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=",
        "--endpoint", "vpn.example.com:51820",
        "--address", "10.8.0.2/32",
    ])
    assert rc == cli.EXIT_REFUSED
    assert "wireguard-tools" in capsys.readouterr().out
