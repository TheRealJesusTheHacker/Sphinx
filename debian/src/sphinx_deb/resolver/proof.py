"""How the command line proves the filter answers (the guard's
Proofer for the real machine).

Two kinds of proof, both real exchanges, no shortcuts:

- **Loopback proof** asks the running daemon, over its control
  socket, to run its own liveness proof on an address (the daemon's
  exchange is neither counted nor logged). If no daemon answers the
  socket, a direct wire proof is used instead: a question for a name
  on the loaded blocklist must come back with the sinkhole answer —
  only Sphinx answers that way, so a stranger resolver squatting on
  the loopback cannot pass for the filter.
- **Stub proof** (the resolved stack's end-to-end check, run after
  DNS has been pointed) questions systemd-resolved's stub at
  127.0.0.53 for a blocked name: the sinkhole answer can only have
  come through the chain stub → resolved → Sphinx.
"""
from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Optional

from .. import paths
from ..control import ControlClient, control_socket_path
from ..core.blocklist import Blocklist
from ..core.dnswire import TYPE_A, build_query, parse_query
from .systemview import RESOLVED_STUB

#: Well-known names any shipped copy of the bundled list carries;
#: used to pick the name the wire proof asks about.
_PROOF_NAME_CANDIDATES = ("doubleclick.net", "googlesyndication.com", "adservice.google.com")


def _sinkhole_ok(data: bytes, query_id: int) -> bool:
    """The response is Sphinx's sinkhole: matching ID, response bit,
    one A answer whose address is 0.0.0.0."""
    parsed = parse_query(data)
    if parsed is None or not parsed.is_response or parsed.id != query_id:
        return False
    p = parsed.question_end
    if len(data) < p + 12:
        return False
    rdata_len = (data[p + 10] << 8) | data[p + 11]
    rdata = data[p + 12 : p + 12 + rdata_len]
    return rdata_len == 4 and rdata == b"\x00\x00\x00\x00"


class WireProofer:
    def __init__(self, list_file: Optional[Path] = None):
        self._client = ControlClient(control_socket_path(paths.runtime_dir()))
        self._list_file = list_file if list_file is not None else paths.list_path()
        self._proof_name: Optional[str] = None

    def _blocked_name(self) -> Optional[str]:
        if self._proof_name is not None:
            return self._proof_name
        try:
            lines = self._list_file.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            return None
        parsed = Blocklist.from_lines(lines)
        for candidate in _PROOF_NAME_CANDIDATES:
            if parsed.is_blocked(candidate):
                self._proof_name = candidate
                return candidate
        if parsed.size:
            self._proof_name = sorted(parsed.domains)[0]
            return self._proof_name
        return None

    def loopback_answers(self, address: str) -> bool:
        # The daemon's own proof first (uncounted, unlogged).
        reply = self._client.request({"cmd": "proof", "address": address})
        if reply is not None:
            return bool(reply.get("ok"))
        # No control socket: prove it on the wire, the sinkhole way.
        name = self._blocked_name()
        if name is None:
            return False
        query_id = int.from_bytes(os.urandom(2), "big")
        packet = build_query(name, qtype=TYPE_A, query_id=query_id)
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.5)
                sock.connect((address, paths.dns_port()))
                sock.send(packet)
                data, _ = sock.recvfrom(65535)
        except OSError:
            return False
        return _sinkhole_ok(data, query_id)

    def stub_answers(self) -> bool:
        name = self._blocked_name()
        if name is None:
            return False
        query_id = int.from_bytes(os.urandom(2), "big")
        packet = build_query(name, qtype=TYPE_A, query_id=query_id)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2.5)
                sock.connect((RESOLVED_STUB, 53))
                sock.send(packet)
                data, _ = sock.recvfrom(65535)
        except OSError:
            return False
        return _sinkhole_ok(data, query_id)
