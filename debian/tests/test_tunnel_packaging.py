"""The VPN's packaging discipline: wireguard-tools is a declared
dependency (invoked, never bundled), and prerm tears a live
tunnel down — tunnel first — before removal, or stops loudly."""
from pathlib import Path

DEBIAN_DIR = Path(__file__).resolve().parents[1]


def test_control_declares_wireguard_tools_invoked_not_bundled():
    control = (DEBIAN_DIR / "packaging" / "control").read_text()
    assert "wireguard-tools" in control
    depends = next(l for l in control.splitlines() if l.startswith("Depends:"))
    assert "wireguard-tools" in depends


def test_prerm_tears_the_tunnel_down_first_or_stops():
    prerm = (DEBIAN_DIR / "packaging" / "prerm").read_text()
    assert "tunnel-state.json" in prerm
    assert "sphinx vpn disconnect" in prerm
    # Tunnel teardown precedes the DNS restore block in the script.
    assert prerm.index("tunnel-state.json") < prerm.index("dns-backup.json")
    tunnel_block = prerm[: prerm.index("dns-backup.json")]
    assert "exit 1" in tunnel_block  # a tunnel that stays up stops removal

def test_control_recommends_openvpn_not_hard_depends():
    control = (DEBIAN_DIR / "packaging" / "control").read_text()
    depends = next(l for l in control.splitlines() if l.startswith("Depends:"))
    recommends = next(l for l in control.splitlines() if l.startswith("Recommends:"))
    assert "openvpn" in recommends
    assert "openvpn" not in depends  # WireGuard must work without it
