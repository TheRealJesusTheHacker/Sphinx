"""The installer's VPN promises, pinned as text (Inno Setup
cannot run on this VM; CI compiling the script is the other
half): the tunnel teardown runs BEFORE the DNS restore and
before any file removal, and the bundled WireGuardNT component
ships with its license."""
from pathlib import Path

PACKAGING = Path(__file__).resolve().parent.parent / "packaging"
ISS = (PACKAGING / "Sphinx.iss").read_text(encoding="utf-8")
SPEC = (PACKAGING / "Sphinx.spec").read_text(encoding="utf-8")
PS1 = (PACKAGING / "build-portable.ps1").read_text(encoding="utf-8")


def test_uninstall_tears_down_vpn_before_dns_and_files():
    assert "InitializeUninstall" in ISS
    assert "--restore-vpn" in ISS
    # Order inside the hook: VPN teardown first, DNS second —
    # the spec's teardown order (tunnel down, then DNS restore).
    hook = ISS.split("function InitializeUninstall", 1)[1]
    assert hook.index("--restore-vpn") < hook.index("--restore-dns")
    # Both abort on ANY nonzero exit (0 = restored/nothing held,
    # 3 = could not be verified).
    assert ISS.count("ResultCode <> 0") >= 2
    assert "Result := False" in ISS


def test_installer_ships_the_bundled_dll_and_its_license():
    assert 'Source: "third-party\\wireguard.dll"' in ISS
    assert 'Source: "third-party\\WireGuardNT-LICENSE.txt"' in ISS


def test_spec_bundles_the_dll_and_license():
    assert "wireguard.dll" in SPEC
    assert "WireGuardNT-LICENSE.txt" in SPEC
    assert '"sphinx_win/tunnel"' in SPEC or "'sphinx_win/tunnel'" in SPEC \
        or 'sphinx_win", "tunnel' in SPEC or "sphinx_win/tunnel" in SPEC


def test_portable_script_ships_the_dll_and_license():
    assert "wireguard.dll" in PS1
    assert "WireGuardNT-LICENSE.txt" in PS1


def test_restore_vpn_headless_contract(tmp_path):
    """--restore-vpn's logic (main.restore_vpn_main): nothing
    held is success; a held record is torn down (manager down +
    DNS originals restored + record retired); a DNS restore that
    cannot be verified keeps the record and returns 3."""
    from sphinx_win.app.main import restore_vpn_main
    from sphinx_win.core.tunnelstore import TunnelState, TunnelStore
    from sphinx_win.dnsmgmt.base import AdapterDns
    from sphinx_win.dnsmgmt.fake import FakeDnsManager

    data = tmp_path / "data"
    messages = []
    assert restore_vpn_main(data, out=messages.append) == 0

    store = TunnelStore(data)
    store.save_state(
        TunnelState(
            profile_name="Home Server",
            intent=True,
            dns_originals=[
                {
                    "interface_alias": "Wi-Fi",
                    "family": "IPv4",
                    "servers": ["192.168.1.1"],
                }
            ],
        )
    )
    manager = FakeDnsManager(
        [AdapterDns("Wi-Fi", "IPv4", ["10.8.0.1"])], elevated=True
    )

    class _Tunnel:
        down_called = False

        def down(self):
            _Tunnel.down_called = True

    assert (
        restore_vpn_main(
            data,
            tunnel_manager_factory=_Tunnel,
            dns_manager_factory=lambda: manager,
            out=messages.append,
        )
        == 0
    )
    assert _Tunnel.down_called
    assert manager.get_dns("Wi-Fi", "IPv4") == ["192.168.1.1"]
    assert store.load_state() is None

    # Unverifiable restore: record kept, exit 3.
    store.save_state(
        TunnelState(
            profile_name="Home Server",
            intent=True,
            dns_originals=[
                {
                    "interface_alias": "Wi-Fi",
                    "family": "IPv4",
                    "servers": ["192.168.1.1"],
                }
            ],
        )
    )
    manager.fail_on_set.add(("Wi-Fi", "IPv4"))
    assert (
        restore_vpn_main(
            data,
            tunnel_manager_factory=_Tunnel,
            dns_manager_factory=lambda: manager,
            out=messages.append,
        )
        == 3
    )
    assert store.load_state() is not None
