"""The OpenVPN config sanitizer (Phase 2, security-critical):
a stranger's config must not execute anything on the user's
machine. The dangerous-directive list is pinned; removals are
named in the result (never silent); the stored profile text is
never the sanitized text and is never edited by sanitizing."""
import pytest

from sphinx_win.core.openvpn_sanitize import (
    DANGEROUS_DIRECTIVES,
    is_dangerous,
    sanitize_openvpn_config,
)

EVIL_CONFIG = """client
dev tun
proto udp
remote vpn-node.example.org 1194
resolv-retry infinite
nobind
persist-key
script-security 2
up /tmp/evil-up.sh
down /tmp/evil-down.sh
route-up /tmp/evil-route.sh
route-pre-down /tmp/evil-pre.sh
plugin /tmp/evil.dll auth
management 127.0.0.1 7505
management-hold
iproute /tmp/evil-iproute
tls-verify /tmp/evil-verify.sh
auth-user-pass /tmp/creds.txt
cd /tmp
chroot /tmp/jail
daemon
writepid /tmp/ovpn.pid
status /tmp/ovpn.status
log /tmp/ovpn.log
log-append /tmp/ovpn.log
learn-address /tmp/evil-learn.sh
<ca>
-----BEGIN CERTIFICATE-----
FIXTURE-CERTIFICATE-NOT-REAL
-----END CERTIFICATE-----
</ca>
"""

CLEAN_CONFIG = """client
dev tun
proto udp
remote vpn-node.example.org 1194
resolv-retry infinite
nobind
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
FIXTURE-CERTIFICATE-NOT-REAL
-----END CERTIFICATE-----
</ca>
"""


class TestSanitizer:
    def test_every_dangerous_directive_is_removed_and_named(self):
        result = sanitize_openvpn_config(EVIL_CONFIG)
        for directive in (
            "script-security", "up", "down", "route-up",
            "route-pre-down", "plugin", "management",
            "management-hold", "iproute", "tls-verify",
            "auth-user-pass", "cd", "chroot", "daemon", "writepid",
            "status", "log", "log-append", "learn-address",
        ):
            assert directive in result.removed, directive
        # Nothing executable survives anywhere in the working copy.
        assert "/tmp/evil" not in result.text
        assert "/tmp/creds.txt" not in result.text
        assert "script-security" not in result.text
        # The tunnel description itself survives intact.
        assert "remote vpn-node.example.org 1194" in result.text
        assert "client" in result.text
        # Inline data blocks are data: the cert rides untouched.
        assert "FIXTURE-CERTIFICATE-NOT-REAL" in result.text

    def test_the_pinned_list_is_the_spec_list(self):
        # TUNNEL-SPEC / the Phase 2 directive list, verbatim: the
        # list can only change on purpose, in the open.
        for directive in (
            "up", "down", "route-up", "route-pre-down", "plugin",
            "script-security", "management", "iproute",
            "tls-verify", "cd", "chroot", "daemon", "writepid",
            "status", "log", "log-append",
        ):
            assert directive in DANGEROUS_DIRECTIVES, directive

    def test_auth_user_pass_with_a_file_goes_bare_form_stays(self):
        assert is_dangerous("auth-user-pass", ["/tmp/creds.txt"])
        assert not is_dangerous("auth-user-pass", [])
        result = sanitize_openvpn_config(CLEAN_CONFIG)
        assert result.removed == []
        assert result.text == CLEAN_CONFIG

    def test_removals_are_surfaced_never_silent(self):
        result = sanitize_openvpn_config(EVIL_CONFIG)
        summary = result.removal_summary()
        assert "removed" in summary
        assert "up" in summary and "plugin" in summary
        clean = sanitize_openvpn_config(CLEAN_CONFIG)
        assert "nothing in it had to be removed" in (
            clean.removal_summary()
        )

    def test_dashdash_prefixed_directives_are_caught(self):
        result = sanitize_openvpn_config(
            "client\ndev tun\nremote h.example.org 1194\n--up /tmp/x.sh\n"
        )
        assert result.removed == ["up"]
        assert "/tmp/x.sh" not in result.text

    def test_block_contents_are_not_directives(self):
        # A line inside an inline block that happens to start
        # with a dangerous word is certificate data, not a
        # directive — it must ride through, or real configs break.
        text = (
            "client\ndev tun\nremote h.example.org 1194\n<key>\n"
            "up is a word inside key material\n</key>\n"
        )
        result = sanitize_openvpn_config(text)
        assert result.removed == []
        assert "up is a word inside key material" in result.text

    def test_input_text_is_never_mutated(self):
        original = EVIL_CONFIG
        sanitize_openvpn_config(EVIL_CONFIG)
        assert EVIL_CONFIG == original
