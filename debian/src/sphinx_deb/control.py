"""The daemon's local control socket: how the command line learns
the truth from the running filter.

The daemon owns the filter; the ``sphinx`` command owns the resolver
record. They meet here — a Unix socket in the runtime directory
(/run/sphinx/control.sock), one JSON object per line each way:

- ``{"cmd": "proof", "address": "127.0.0.1"}`` → ``{"ok": bool}``:
  the daemon proves it answers on that loopback, with its own
  liveness exchange (not counted, not logged — the same proof the
  other editions run before DNS is pointed at the filter).
- ``{"cmd": "stats"}`` → the daemon's real counters: queries
  blocked / let through, the loaded list's size, the loopbacks it
  bound, its version and uptime.

Nothing else is exposed, the socket never leaves the machine, and a
missing socket means the service is not running — callers report
exactly that rather than guessing.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Optional

CONTROL_SOCKET_NAME = "control.sock"


def control_socket_path(runtime_dir: Path) -> Path:
    return Path(runtime_dir) / CONTROL_SOCKET_NAME


class ControlClient:
    def __init__(self, socket_path: Path, timeout: float = 3.0):
        self._path = Path(socket_path)
        self._timeout = timeout
        #: Why the last request failed, when it did: "permission"
        #: (the socket exists but this user may not use it — it is
        #: mode 0660, owned by the daemon's user and group) or
        #: "unreachable" (no daemon there). Callers use this to tell
        #: the truth instead of reporting a running daemon as absent.
        #: (Debian Phase 1 audit, finding 3.)
        self.last_error: Optional[str] = None

    def request(self, payload: dict) -> Optional[dict]:
        """One request/response round trip; None when the daemon is
        not reachable (not running, or the socket is not its)."""
        self.last_error = None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self._timeout)
                sock.connect(str(self._path))
                sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
                chunks = bytearray()
                while b"\n" not in chunks:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.extend(chunk)
        except PermissionError:
            self.last_error = "permission"
            return None
        except OSError:
            self.last_error = "unreachable"
            return None
        try:
            line = bytes(chunks).split(b"\n", 1)[0]
            raw = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return raw if isinstance(raw, dict) else None

    def proof(self, address: str) -> bool:
        reply = self.request({"cmd": "proof", "address": address})
        return bool(reply and reply.get("ok"))

    def stats(self) -> Optional[dict]:
        return self.request({"cmd": "stats"})


class ControlServer:
    """Serves the control socket for the daemon's lifetime.

    ``proof`` maps an address to the daemon's own liveness proof;
    ``stats`` returns the daemon's counters dict.
    """

    def __init__(
        self,
        socket_path: Path,
        proof: Callable[[str], bool],
        stats: Callable[[], dict],
    ):
        self._path = Path(socket_path)
        self._proof = proof
        self._stats = stats
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stopped = threading.Event()

    def start(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._path.unlink(missing_ok=True)  # a stale socket from a dead run
        except OSError:
            pass
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(str(self._path))
        try:
            os.chmod(self._path, 0o660)
        except OSError:
            pass
        self._socket.listen(8)
        self._socket.settimeout(0.2)
        self._thread = threading.Thread(
            target=self._serve, name="sphinx-control", daemon=True
        )
        self._thread.start()

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stopped.is_set():
            try:
                conn, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    self._handle(conn)
                except OSError:
                    pass

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        chunks = bytearray()
        while b"\n" not in chunks and len(chunks) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.extend(chunk)
        try:
            request = json.loads(bytes(chunks).split(b"\n", 1)[0].decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            request = {}
        reply = self._dispatch(request if isinstance(request, dict) else {})
        conn.sendall(json.dumps(reply).encode("utf-8") + b"\n")

    def _dispatch(self, request: dict) -> dict:
        cmd = request.get("cmd")
        if cmd == "proof":
            address = str(request.get("address", ""))
            try:
                return {"ok": bool(self._proof(address))}
            except Exception:
                return {"ok": False}
        if cmd == "stats":
            try:
                return {"ok": True, **self._stats()}
            except Exception:
                return {"ok": False}
        return {"ok": False, "error": "unknown command"}

    def stop(self) -> None:
        self._stopped.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        try:
            self._path.unlink(missing_ok=True)
        except OSError:
            pass


def monotonic_started() -> float:
    return time.monotonic()
