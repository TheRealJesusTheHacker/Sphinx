"""The real system view's pure parsing helpers, on canned tool
output — the discipline tests use fakes, so these pin the seams
where the production view reads real machine output."""
from sphinx_deb.resolver.systemview import (
    is_loopback,
    nameservers_in,
    parse_default_link,
    parse_nm_connected_devices,
    parse_resolvectl_dns,
)


def test_nameservers_in_reads_only_nameserver_lines():
    data = (
        b"# a comment\n"
        b"search home.lan\n"
        b"nameserver 192.168.1.1\n"
        b"nameserver 2001:db8::1  # inline note\n"
        b"options ndots:2\n"
        b"; nameserver 10.0.0.1\n"
    )
    assert nameservers_in(data) == ["192.168.1.1", "2001:db8::1"]


def test_parse_resolvectl_dns():
    assert parse_resolvectl_dns("Link 2 (eth0): 192.168.1.1 9.9.9.9\n") == [
        "192.168.1.1",
        "9.9.9.9",
    ]
    assert parse_resolvectl_dns("Link 2 (eth0):\n") == []
    assert parse_resolvectl_dns("") == []


def test_parse_default_link():
    assert (
        parse_default_link('[{"dst":"default","gateway":"192.168.1.1","dev":"wlan0"}]')
        == "wlan0"
    )
    assert parse_default_link("[]") is None
    assert parse_default_link("not json") is None


def test_parse_nm_connected_devices():
    out = "eth0:connected\nlo:unmanaged\nwlan0:disconnected\n"
    assert parse_nm_connected_devices(out) == {"eth0"}


def test_is_loopback():
    assert is_loopback("127.0.0.1")
    assert is_loopback("127.0.0.53")
    assert is_loopback("::1")
    assert not is_loopback("192.168.1.1")
    assert not is_loopback("not-an-address")
