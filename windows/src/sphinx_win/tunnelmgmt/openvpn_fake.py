"""An in-memory OpenVPN manager for tests and dry runs.

It models the contract the mode model depends on, at the level
this fake honestly supports:

- ``up`` records the profile and THE SANITIZED CONFIG it was
  handed — the model must sanitize before it engages, and the
  manager must be given the cleaned copy, never the stored text.
- ``status`` reports establishment with a fresh "proof"
  timestamp (the fake's stand-in for the management interface
  reporting CONNECTED); ``simulate_unexpected_exit()`` kills the
  child WITHOUT a down() — the process is gone, its routes are
  gone with it (that is what the real client does), and the
  status says the exit was unexpected, which is what puts the
  mode model into the announced kill-switch posture instead of
  a silent unwrap.
- ``pushed_dns`` returns the DNS set the test configured as the
  server's push.
- A missing client is modeled with ``installed=False``: the
  honest "OpenVPN isn't installed" availability state.
"""
from __future__ import annotations

import time
from typing import List, Optional

from .base import TunnelError, TunnelNotElevated, TunnelStatus
from .openvpn_base import OPENVPN_NOT_INSTALLED_MESSAGE


class FakeOpenVpnManager:
    def __init__(
        self,
        elevated: bool = True,
        installed: bool = True,
        pushed_dns: Optional[List[str]] = None,
        established: bool = True,
    ):
        self._elevated = elevated
        self._installed = installed
        self._pushed_dns = list(pushed_dns or [])
        self._established = established
        self.running = False
        self.profile = None
        self.sanitized_config: Optional[str] = None
        self.up_calls: List = []
        self.down_calls = 0
        self.fail_on_up: Optional[Exception] = None
        self._exited_unexpectedly = False
        self._pid = 4242
        self.terminated_pids: List[int] = []

    # --- Contract -------------------------------------------------

    def is_elevated(self) -> bool:
        return self._elevated

    def availability(self):
        if not self._installed:
            return False, OPENVPN_NOT_INSTALLED_MESSAGE
        return True, ""

    def up(self, profile, *, sanitized_config: str) -> None:
        if not self._elevated:
            raise TunnelNotElevated(
                "Changing routes for a VPN needs administrator "
                "rights; nothing was changed."
            )
        if not self._installed:
            raise TunnelError(OPENVPN_NOT_INSTALLED_MESSAGE)
        if self.fail_on_up is not None:
            raise self.fail_on_up
        self.up_calls.append((profile, sanitized_config))
        self.profile = profile
        self.sanitized_config = sanitized_config
        self.running = True
        self._exited_unexpectedly = False

    def down(self) -> None:
        self.down_calls += 1
        self.running = False
        self.profile = None
        self._exited_unexpectedly = False

    def status(self) -> TunnelStatus:
        if self._exited_unexpectedly:
            return TunnelStatus(
                adapter_up=False, exited_unexpectedly=True
            )
        if not self.running:
            return TunnelStatus(adapter_up=False)
        proof = (
            int(time.time() * 1000) if self._established else None
        )
        return TunnelStatus(
            adapter_up=True, latest_handshake_ms=proof
        )

    def pushed_dns(self) -> List[str]:
        return list(self._pushed_dns) if self.running else []

    @property
    def process_id(self):
        return self._pid if self.running else None

    def terminate_pid(self, pid) -> bool:
        """The fake's stand-in for ending a recorded child by pid
        (the leftover path): records the pid it was asked to end."""
        self.terminated_pids.append(pid)
        if pid == self._pid:
            self.running = False
            self._exited_unexpectedly = False
        return True

    # --- Test controls --------------------------------------------

    def simulate_unexpected_exit(self) -> None:
        """The child dies on its own (crash, kill, the server
        dropping it hard): no down() was called, the process and
        its routes are gone, and the exit was NOT intentional."""
        self.running = False
        self._exited_unexpectedly = True

    def set_established(self, established: bool) -> None:
        self._established = established
