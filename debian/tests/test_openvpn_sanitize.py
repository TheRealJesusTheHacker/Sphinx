"""Sanitizer pins: every normative dangerous directive is stripped
and named; safe lines and inline cert blocks survive."""
from sphinx_deb.core.openvpn_sanitize import (
    STRIPPED_DIRECTIVES,
    render_session_config,
    sanitize_openvpn_config,
)

DANGEROUS = """client
dev tun
proto udp
remote vpn.example.org 1194
up /tmp/evil-up.sh
down /tmp/evil-down.sh
route-up /tmp/evil.sh
route-pre-down /tmp/evil.sh
plugin /tmp/evil.so
script-security 2
management 127.0.0.1 7505
iproute /tmp/evil-ip
tls-verify /tmp/evil.sh
auth-user-pass /tmp/creds.txt
cd /tmp
chroot /tmp/jail
daemon
writepid /tmp/ovpn.pid
status /tmp/ovpn.status 10
log /tmp/ovpn.log
log-append /tmp/ovpn.log
syslog
client-connect /tmp/evil.sh
learn-address /tmp/evil.sh
setenv EVIL 1
auth-user-pass
nobind
<ca>
-----BEGIN CERTIFICATE-----
EXAMPLE-CERTIFICATE-NOT-REAL
up this-is-inside-a-cert-block-not-a-directive
-----END CERTIFICATE-----
</ca>
"""

EXPECTED_STRIPPED = {
    "up", "down", "route-up", "route-pre-down", "plugin",
    "script-security", "management", "iproute", "tls-verify",
    "cd", "chroot", "daemon", "writepid", "status", "log",
    "log-append", "syslog",
}


def test_every_normative_directive_is_stripped_and_named():
    result = sanitize_openvpn_config(DANGEROUS)
    removed_names = {r.split(" ")[0].split(" (")[0] for r in result.removed}
    assert EXPECTED_STRIPPED <= removed_names
    assert "auth-user-pass (with a file argument)" in result.removed
    for directive in EXPECTED_STRIPPED:
        assert directive in STRIPPED_DIRECTIVES
    # No stripped directive survives as a directive line carrying
    # its original (dangerous) argument. (Text inside the <ca>
    # block is data and is checked separately below.)
    for fragment in ("/tmp/evil-up.sh", "/tmp/evil-down.sh", "/tmp/evil.sh",
                     "/tmp/evil.so", "script-security 2", "management 127.0.0.1",
                     "/tmp/evil-ip", "/tmp/creds.txt", "chroot", "writepid",
                     "status /tmp", "log /tmp", "log-append"):
        assert fragment not in result.text


def test_safe_lines_and_inline_blocks_survive():
    result = sanitize_openvpn_config(DANGEROUS)
    assert "remote vpn.example.org 1194" in result.text
    assert "nobind" in result.text
    assert "auth-user-pass\n" in result.text  # bare form kept (prompt)
    assert "EXAMPLE-CERTIFICATE-NOT-REAL" in result.text
    # Inside a <ca> block, text is data, not a directive.
    assert "up this-is-inside-a-cert-block-not-a-directive" in result.text


def test_session_config_rejects_pushed_dns():
    result = render_session_config("client\ndev tun\nremote h 1194\n")
    assert 'pull-filter ignore "dhcp-option DNS"' in result.text
    assert 'pull-filter ignore "dhcp-option DOMAIN"' in result.text


def test_clean_config_removes_nothing():
    result = sanitize_openvpn_config("client\ndev tun\nremote h 1194\n")
    assert result.removed == []
    assert "remote h 1194" in result.text
