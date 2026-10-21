"""The control socket: the command line's proof and stats come from
the running daemon itself — and a missing daemon is reported as
missing, never guessed at."""
import socket

import pytest

from conftest import requires_udp
from sphinx_deb.control import ControlClient, ControlServer, control_socket_path
from sphinx_deb.core.blocklist import Allowlist, Blocklist, FilterLists
from sphinx_deb.core.dnswire import build_query
from sphinx_deb.core.server import DnsFilterServer, FilterEngine

PORT = 18554


@pytest.fixture()
def daemon(tmp_path):
    lists = FilterLists(Blocklist(["ads.example.com"]), Allowlist([]))

    def forward(query: bytes) -> bytes:
        out = bytearray(query)
        out[2:4] = (0x8000 | 0x0080).to_bytes(2, "big")
        return bytes(out)

    engine = FilterEngine(lists_provider=lambda: lists, forwarder=forward)
    server = DnsFilterServer(engine, port=PORT)
    server.start()
    control = ControlServer(
        control_socket_path(tmp_path),
        proof=lambda address: server.answers_on(address),
        stats=lambda: {
            "blocked": engine.blocked_count,
            "allowed": engine.allowed_count,
            "list_size": lists.blocklist.size,
        },
    )
    control.start()
    yield ControlClient(control_socket_path(tmp_path)), engine
    control.stop()
    server.stop()


@requires_udp
def test_proof_and_stats_round_trip(daemon):
    client, engine = daemon
    assert client.proof("127.0.0.1") is True
    # A real blocked query through the server moves the real counter.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        sock.connect(("127.0.0.1", PORT))
        sock.send(build_query("ads.example.com", query_id=77))
        sock.recvfrom(65535)
    stats = client.stats()
    assert stats is not None
    assert stats["blocked"] == 1
    assert stats["list_size"] == 1


def test_no_daemon_is_none_not_a_guess(tmp_path):
    client = ControlClient(control_socket_path(tmp_path))
    assert client.stats() is None
    assert client.proof("127.0.0.1") is False


def test_permission_denied_is_distinguished_from_absent(tmp_path, monkeypatch):
    # Audit finding 3: the installed socket is mode 0660 (daemon
    # user/group + root). An unprivileged caller gets EACCES, which
    # must not be reported as "the daemon is not there".
    import sphinx_deb.control as control_mod

    class DeniedSocket:
        def __init__(self, *a, **k):
            raise PermissionError("denied (fake)")

    monkeypatch.setattr(control_mod.socket, "socket", DeniedSocket)
    client = ControlClient(control_socket_path(tmp_path))
    assert client.stats() is None
    assert client.last_error == "permission"
