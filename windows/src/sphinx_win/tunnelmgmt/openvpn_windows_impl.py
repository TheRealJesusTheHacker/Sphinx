"""The production OpenVPN manager: supervises the user's own
installed ``openvpn.exe`` as a child process (route (a) — see
openvpn_base.py for the evaluation).

How Sphinx runs the client, and nothing else:

- The config the client receives is the SANITIZED working copy
  the controller hands in (core.openvpn_sanitize) — never the
  stored profile text. It is written to a per-session file in
  the data folder's ``openvpn`` subfolder and removed at
  teardown.
- Sphinx's own controlled flags only: its own management
  endpoint on loopback (an ephemeral port, this process only),
  ``--script-security 0`` (even a surviving script directive
  could not run), and log capture to a session log Sphinx reads
  for establishment proof and pushed DNS. No flag comes from
  the config, ever.
- "Connected" is proven, never spawned into existence:
  status() asks the management interface for the client's state
  and counts the tunnel established only on CONNECTED,SUCCESS;
  the session log's "Initialization Sequence Completed" line is
  the fallback proof. The pushed DNS set is read from the
  client's own PUSH_REPLY lines in that log.
- The child is Sphinx's: down() signals it through the
  management interface (SIGTERM), falling back to terminate().
  A child that dies on its own is reported as
  exited_unexpectedly — the mode model's kill-switch posture
  hangs off that fact.

Honesty boundary: this module imports cleanly on any platform
and its pure parts (the executable search, the log parsers, the
command line builder) are unit-tested on Linux, but actually
supervising a client, its TAP/Wintun adapter, and its routes
can only be PROVEN on a real Windows machine with OpenVPN
installed — that pass is a named release gate, not something
this code claims by existing.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

from .base import TunnelError, TunnelNotElevated, TunnelStatus
from .openvpn_base import OPENVPN_NOT_INSTALLED_MESSAGE

#: Where the user's own OpenVPN may live, in search order: an
#: explicit override, PATH (the community installer adds its
#: bin), then the community installer's standard folder.
_PROGRAM_FILES_CANDIDATES = (
    Path("C:/Program Files/OpenVPN/bin/openvpn.exe"),
    Path("C:/Program Files (x86)/OpenVPN/bin/openvpn.exe"),
)

_PUSHED_DNS_RE = re.compile(r"dhcp-option\s+DNS\s+([0-9A-Fa-f:.]+)")


def openvpn_candidates() -> List[Path]:
    candidates: List[Path] = []
    override = os.environ.get("SPHINX_OPENVPN_EXE")
    if override:
        candidates.append(Path(override))
    which = shutil.which("openvpn") or shutil.which("openvpn.exe")
    if which:
        candidates.append(Path(which))
    candidates.extend(_PROGRAM_FILES_CANDIDATES)
    return candidates


def find_openvpn() -> Optional[Path]:
    for candidate in openvpn_candidates():
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def parse_pushed_dns(log_text: str) -> List[str]:
    """The pushed DNS servers, in push order, deduplicated —
    read from the client's own PUSH_REPLY / option lines."""
    found: List[str] = []
    for match in _PUSHED_DNS_RE.finditer(log_text or ""):
        value = match.group(1)
        if value not in found:
            found.append(value)
    return found


def log_proves_established(log_text: str) -> bool:
    return "Initialization Sequence Completed" in (log_text or "")


def build_command(
    exe: Path, config_path: Path, management_port: int, log_path: Path
) -> List[str]:
    """Sphinx's controlled command line — every flag is
    Sphinx's; nothing is taken from the stranger's config."""
    return [
        str(exe),
        "--config", str(config_path),
        # Even a script directive that somehow survived
        # sanitization could not run: Sphinx forbids scripts at
        # the client's own security level.
        "--script-security", "0",
        # Sphinx's own management endpoint, loopback only.
        "--management", "127.0.0.1", str(management_port),
        "--log", str(log_path),
        "--verb", "3",
    ]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class WindowsOpenVpnManager:
    """OpenVpnManager backed by the user's installed client."""

    def __init__(
        self,
        exe_path: Optional[Path] = None,
        work_dir: Optional[Path] = None,
    ):
        self._exe_path = (
            Path(exe_path) if exe_path is not None else find_openvpn()
        )
        self._work_dir = Path(work_dir) if work_dir is not None else None
        self._proc: Optional[subprocess.Popen] = None
        self._management_port: Optional[int] = None
        self._config_path: Optional[Path] = None
        self._log_path: Optional[Path] = None
        self._intentional_down = False

    # --- Contract -------------------------------------------------

    def is_elevated(self) -> bool:
        if sys.platform != "win32":
            return False
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def availability(self) -> Tuple[bool, str]:
        if self._exe_path is None or not Path(self._exe_path).is_file():
            return False, OPENVPN_NOT_INSTALLED_MESSAGE
        return True, ""

    @property
    def process_id(self):
        if self._proc is not None and self._proc.poll() is None:
            return self._proc.pid
        return None

    # --- Lifecycle --------------------------------------------------

    def up(self, profile, *, sanitized_config: str) -> None:
        if not self.is_elevated():
            raise TunnelNotElevated(
                "Bringing a VPN tunnel up needs administrator "
                "rights (it creates a network adapter and changes "
                "routes). Nothing was changed."
            )
        ok, reason = self.availability()
        if not ok:
            raise TunnelError(reason)
        work = self._work_dir or (
            Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Sphinx"
        )
        session_dir = work / "openvpn"
        session_dir.mkdir(parents=True, exist_ok=True)
        self._config_path = session_dir / "sphinx-openvpn.ovpn"
        self._log_path = session_dir / "sphinx-openvpn.log"
        # The sanitized working copy only — never the stored text.
        self._config_path.write_text(sanitized_config, encoding="utf-8")
        if self._log_path.exists():
            self._log_path.unlink()
        self._management_port = _free_port()
        command = build_command(
            Path(self._exe_path),
            self._config_path,
            self._management_port,
            self._log_path,
        )
        self._intentional_down = False
        try:
            self._proc = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as e:
            raise TunnelError(
                f"The installed OpenVPN program could not be "
                f"started ({e}). Nothing was connected."
            ) from e

    def down(self) -> None:
        self._intentional_down = True
        proc, self._proc = self._proc, None
        if proc is not None and proc.poll() is None:
            if not self._signal_via_management("signal SIGTERM"):
                try:
                    proc.terminate()
                except OSError:
                    pass
            try:
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                except OSError:
                    pass
        # The sanitized working copy does not outlive the session.
        if self._config_path is not None:
            try:
                self._config_path.unlink(missing_ok=True)
            except OSError:
                pass
            self._config_path = None

    def terminate_pid(self, pid: int) -> bool:
        """Terminate a recorded OpenVPN child by pid — the
        headless --restore-vpn path's reach: the tray host owns
        the child, but the tunnel record holds its pid, and an
        uninstall must be able to end a Sphinx-started client
        even when the host is already gone. Acts only on a pid
        the record names; used by main.restore_vpn_main."""
        if not pid:
            return False
        try:
            completed = subprocess.run(
                ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                capture_output=True, text=True, timeout=30,
            )
            return completed.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    # --- Status / proof --------------------------------------------

    def _read_log(self) -> str:
        if self._log_path is None:
            return ""
        try:
            return self._log_path.read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            return ""

    def _signal_via_management(self, command: str) -> bool:
        if self._management_port is None:
            return False
        try:
            with socket.create_connection(
                ("127.0.0.1", self._management_port), timeout=1.0
            ) as conn:
                conn.settimeout(1.0)
                conn.recv(4096)  # the banner
                conn.sendall((command + "\n").encode("ascii"))
                conn.recv(4096)
            return True
        except OSError:
            return False

    def _management_state(self) -> Optional[str]:
        """The client's state line from its management interface
        (``>STATE:...,CONNECTED,SUCCESS,...``), or None when the
        interface does not answer."""
        if self._management_port is None:
            return None
        try:
            with socket.create_connection(
                ("127.0.0.1", self._management_port), timeout=1.0
            ) as conn:
                conn.settimeout(1.0)
                banner = conn.recv(4096).decode("utf-8", "replace")
                if "CONNECTED" in banner and "SUCCESS" in banner:
                    return banner
                conn.sendall(b"state\n")
                data = conn.recv(8192).decode("utf-8", "replace")
                return data
        except OSError:
            return None

    def status(self) -> TunnelStatus:
        if self._proc is None:
            return TunnelStatus(adapter_up=False)
        if self._proc.poll() is not None:
            # The child is gone. Intentional (down() ran) reads as
            # plain down; anything else is the unexpected exit the
            # kill-switch posture is built on.
            return TunnelStatus(
                adapter_up=False,
                exited_unexpectedly=not self._intentional_down,
            )
        state = self._management_state()
        established = bool(
            state and "CONNECTED" in state and "SUCCESS" in state
        ) or log_proves_established(self._read_log())
        return TunnelStatus(
            adapter_up=True,
            latest_handshake_ms=(
                int(time.time() * 1000) if established else None
            ),
        )

    def pushed_dns(self) -> List[str]:
        if self._proc is None:
            return []
        return parse_pushed_dns(self._read_log())
