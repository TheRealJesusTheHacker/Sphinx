"""The production DnsManager: drives Windows through PowerShell's
DnsClient cmdlets (Get/Set-DnsClientServerAddress, Get-NetAdapter,
Get-NetRoute), exchanging JSON so server lists survive the round
trip exactly.

Only adapters that are Up and carry a default route (0.0.0.0/0 or
::/0) count as "active" — the adapters actually serving the machine's
connections. Loopback and disconnected adapters are never touched.

This module imports cleanly on any platform (the Windows calls are
made lazily, per operation); it can only do its work on Windows.
"""
from __future__ import annotations

import ctypes
import json
import subprocess
import sys
from typing import List

from .base import FAMILY_V4, FAMILY_V6, AdapterDns

_FAMILY_TO_PS = {FAMILY_V4: "IPv4", FAMILY_V6: "IPv6"}


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_user_admin() -> bool:
    """True when this process runs elevated. On non-Windows: False —
    there is no Windows DNS to manage there anyway."""
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_powershell(script: str) -> object:
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "PowerShell failed: " + (completed.stderr or completed.stdout).strip()
        )
    output = completed.stdout.strip()
    return json.loads(output) if output else None


class WindowsDnsManager:
    """DnsManager backed by the DnsClient PowerShell cmdlets."""

    def is_elevated(self) -> bool:
        return is_user_admin()

    def active_adapters(self) -> List[AdapterDns]:
        script = r"""
$aliases = @()
foreach ($family in @('IPv4','IPv6')) {
  $dest = if ($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
  $routes = Get-NetRoute -AddressFamily $family -DestinationPrefix $dest -ErrorAction SilentlyContinue
  foreach ($r in $routes) { $aliases += $r.InterfaceAlias }
}
$aliases = $aliases | Select-Object -Unique
$result = @()
foreach ($alias in $aliases) {
  $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
  if ($null -eq $adapter -or $adapter.Status -ne 'Up') { continue }
  foreach ($family in @('IPv4','IPv6')) {
    $entry = Get-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily $family -ErrorAction SilentlyContinue
    if ($null -ne $entry) {
      $result += [PSCustomObject]@{
        InterfaceAlias = $alias
        Family = $family
        Servers = @($entry.ServerAddresses)
      }
    }
  }
}
$result | ConvertTo-Json -Compress
"""
        raw = _run_powershell(script)
        if raw is None:
            return []
        if isinstance(raw, dict):
            raw = [raw]
        return [
            AdapterDns(
                interface_alias=str(item["InterfaceAlias"]),
                family=str(item["Family"]),
                servers=[str(s) for s in item.get("Servers") or []],
            )
            for item in raw
        ]

    def get_dns(self, interface_alias: str, family: str) -> List[str]:
        ps_family = _FAMILY_TO_PS[family]
        alias = interface_alias.replace("'", "''")
        script = (
            f"(Get-DnsClientServerAddress -InterfaceAlias '{alias}' "
            f"-AddressFamily {ps_family}).ServerAddresses | ConvertTo-Json -Compress"
        )
        raw = _run_powershell(script)
        if raw is None:
            return []
        if isinstance(raw, str):
            return [raw]
        return [str(s) for s in raw]

    def set_dns(self, interface_alias: str, family: str, servers: List[str]) -> None:
        ps_family = _FAMILY_TO_PS[family]
        alias = interface_alias.replace("'", "''")
        if not servers:
            # Empty means "obtain DNS automatically" (DHCP): the
            # reset restores exactly that state.
            script = (
                f"Set-DnsClientServerAddress -InterfaceAlias '{alias}' "
                f"-AddressFamily {ps_family} -ResetServerAddresses"
            )
        else:
            server_list = ",".join(
                "'" + s.replace("'", "''") + "'" for s in servers
            )
            script = (
                f"Set-DnsClientServerAddress -InterfaceAlias '{alias}' "
                f"-AddressFamily {ps_family} -ServerAddresses @({server_list})"
            )
        _run_powershell(script + "\n'ok' | ConvertTo-Json -Compress")
