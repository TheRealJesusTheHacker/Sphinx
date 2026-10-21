"""Shared fixtures: the canonical bundled-list asset, and the fakes
the engage/restore discipline is proven on.

The fakes implement the guard's ResolverView protocol entirely in
memory and a temp directory — the suite never reads or writes the
host's real resolver configuration (no /etc/resolv.conf, no
resolvectl, no systemctl)."""
from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path
from typing import Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

REPO_ROOT = Path(__file__).resolve().parents[2]
CANONICAL_LIST = REPO_ROOT / "app" / "src" / "main" / "assets" / "bundled-blocklist.txt"


def _udp_loopback_works() -> bool:
    """Can this environment actually exchange UDP datagrams on
    loopback? Some sandboxes block UDP sends outright (EPERM on
    sendto) while TCP and Unix sockets work fine. The probe is raw
    sockets only — independent of the code under test — so where it
    passes, the UDP tests below run in full; where it fails, they
    are skipped with the reason stated, and CI (no such sandbox) is
    their proof."""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def echo():
            try:
                data, addr = server.recvfrom(1024)
                server.sendto(data, addr)
            except OSError:
                pass

        threading.Thread(target=echo, daemon=True).start()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1.5)
        client.connect(("127.0.0.1", port))
        client.send(b"ping")
        return client.recv(1024) == b"ping"
    except OSError:
        return False


UDP_LOOPBACK = _udp_loopback_works()

requires_udp = pytest.mark.skipif(
    not UDP_LOOPBACK,
    reason=(
        "UDP loopback is unavailable in this environment (UDP sends "
        "are blocked); runs in CI"
    ),
)


class FakeView:
    """An in-memory ResolverView.

    ``links`` is the resolved stack's per-link DNS as ``resolvectl``
    would report it; ``revert_to`` is what ``resolvectl revert``
    returns a link to (its configured/automatic servers).
    """

    def __init__(
        self,
        *,
        root: bool = True,
        resolv: bytes = b"nameserver 192.168.1.1\n",
        symlink: Optional[str] = None,
        resolved_active: bool = False,
        nm_manages: bool = False,
        default_link: Optional[str] = "eth0",
        links: Optional[Dict[str, List[str]]] = None,
        revert_to: Optional[Dict[str, List[str]]] = None,
    ):
        self._root = root
        self.resolv = resolv
        self.symlink = symlink
        self.resolved = resolved_active
        self.nm = nm_manages
        self.link = default_link
        self.links = {k: list(v) for k, v in (links or {"eth0": ["192.168.1.1"]}).items()}
        self.revert_to = {
            k: list(v) for k, v in (revert_to or self.links).items()
        }
        self.fail_writes = False
        self.fail_set = False
        self.calls: list = []

    def is_root(self) -> bool:
        return self._root

    def resolv_conf_bytes(self) -> bytes:
        return self.resolv

    def resolv_conf_symlink_target(self) -> Optional[str]:
        return self.symlink

    def systemd_resolved_active(self) -> bool:
        return self.resolved

    def network_manager_manages_default(self) -> bool:
        return self.nm

    def default_link(self) -> Optional[str]:
        return self.link

    def link_dns(self, link: str) -> List[str]:
        return list(self.links.get(link, []))

    def set_link_dns(self, link: str, servers: List[str]) -> None:
        self.calls.append(("set", link, list(servers)))
        if self.fail_set:
            raise OSError("resolvectl refused (fake)")
        self.links[link] = list(servers)

    def revert_link(self, link: str) -> None:
        self.calls.append(("revert", link))
        self.links[link] = list(self.revert_to.get(link, []))

    def write_resolv_conf(self, data: bytes) -> None:
        self.calls.append(("write", data))
        if self.fail_writes:
            raise OSError("the file refused the write (fake)")
        self.resolv = data

    def service_active(self, unit: str) -> Optional[bool]:
        return None


class GarblingView(FakeView):
    """A view whose writes land garbled — the read-back verification
    has to catch it, and the guard has to roll back."""

    def write_resolv_conf(self, data: bytes) -> None:
        self.calls.append(("write", data))
        self.resolv = data + b"nameserver 203.0.113.99\n"


class FakeProofer:
    def __init__(self, answers: Optional[Dict[str, bool]] = None, stub: bool = True):
        self.answers = (
            answers
            if answers is not None
            else {"127.0.0.1": True, "::1": True}
        )
        self.stub = stub
        self.calls: list = []

    def loopback_answers(self, address: str) -> bool:
        self.calls.append(("loopback", address))
        return self.answers.get(address, False)

    def stub_answers(self) -> bool:
        self.calls.append(("stub",))
        return self.stub


def stub_resolved_view(**overrides) -> FakeView:
    """A standard systemd-resolved stub machine: resolv.conf is the
    stub symlink, the default link's DNS came from DHCP."""
    base = dict(
        resolv=b"# stub\nnameserver 127.0.0.53\noptions edns0 trust-ad\n",
        symlink="../run/systemd/resolve/stub-resolv.conf",
        resolved_active=True,
        links={"eth0": ["192.168.1.1"]},
    )
    base.update(overrides)
    return FakeView(**base)
