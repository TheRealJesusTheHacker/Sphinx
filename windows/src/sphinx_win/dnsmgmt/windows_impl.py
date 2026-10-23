"""The production DnsManager: drives Windows through PowerShell's
DnsClient cmdlets (Get/Set-DnsClientServerAddress, Get-NetAdapter,
Get-NetRoute), exchanging JSON so server lists survive the round
trip exactly.

Only adapters that are Up and carry a default route (0.0.0.0/0 or
::/0) count as "active" — the adapters actually serving the machine's
connections. Loopback and disconnected adapters are never touched.

**Configured vs. effective — the distinction this module lives
on.** The DnsManager contract (see base.py) speaks of the
*configured* servers: an empty list means "obtain DNS automatically
(DHCP)". ``Get-DnsClientServerAddress`` cannot express that: it
reports the *effective* servers — on a DHCP adapter, the addresses
DHCP handed out — so reading it directly would record a DHCP
snapshot as if it were a static configuration, and a later restore
would pin those addresses statically instead of returning the
adapter to automatic. The audit therefore reads what
``Set-DnsClientServerAddress`` itself writes: the per-interface
``NameServer`` registry value (Tcpip for IPv4, Tcpip6 for IPv6,
under the interface's GUID key). Absent or empty = automatic; a
comma/space-separated list = the static configuration. The cmdlet
is still used to enumerate which adapters/families exist and for
all writes; only the *meaning* of a read comes from the registry.

This module imports cleanly on any platform (the Windows calls are
made lazily, per operation); it can only do its work on Windows.
"""
from __future__ import annotations

import ctypes
import json
import re
import subprocess
import sys
from typing import List, Optional

from .base import FAMILY_V4, FAMILY_V6, AdapterDns

_FAMILY_TO_PS = {FAMILY_V4: "IPv4", FAMILY_V6: "IPv6"}
_FAMILY_TO_SERVICE = {FAMILY_V4: "Tcpip", FAMILY_V6: "Tcpip6"}


def parse_nameserver_value(raw: Optional[str]) -> List[str]:
    """Interpret a registry ``NameServer`` value: the adapter's
    *configured* DNS servers. Absent/empty means the adapter obtains
    DNS automatically (DHCP) — the empty list the DnsManager
    contract promises. Static values are comma-separated (older
    tooling sometimes space-separated)."""
    if not raw:
        return []
    return [part for part in re.split(r"[,\s]+", raw.strip()) if part]


def parse_effective_servers(rows) -> List[str]:
    """Interpret Get-DnsClientServerAddress output rows: the
    EFFECTIVE DNS servers (DHCP-learned ones included), flattened
    in row order, duplicates removed. This is the one place the
    cmdlet's effective view is wanted — the forwarding chain's
    floor (see base.py); configured reads never come from here."""
    seen: List[str] = []
    if rows is None:
        return seen
    if isinstance(rows, dict):
        rows = [rows]
    for row in rows:
        if not isinstance(row, dict):
            continue
        addresses = row.get("ServerAddresses")
        if isinstance(addresses, str):
            addresses = [addresses]
        for address in addresses or []:
            address = str(address)
            if address and address not in seen:
                seen.append(address)
    return seen


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
  $guid = $adapter.InterfaceGuid.ToString('B')
  foreach ($family in @('IPv4','IPv6')) {
    $entry = Get-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily $family -ErrorAction SilentlyContinue
    if ($null -ne $entry) {
      $svc = if ($family -eq 'IPv4') { 'Tcpip' } else { 'Tcpip6' }
      $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Parameters\Interfaces\$guid"
      $configured = (Get-ItemProperty -Path $regPath -Name NameServer -ErrorAction SilentlyContinue).NameServer
      $result += [PSCustomObject]@{
        InterfaceAlias = $alias
        Family = $family
        Configured = $configured
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
                # The CONFIGURED servers (see the module docstring):
                # a DHCP adapter reads as an empty list, never as
                # the addresses DHCP happened to hand out.
                servers=parse_nameserver_value(item.get("Configured")),
            )
            for item in raw
        ]

    def get_dns(self, interface_alias: str, family: str) -> List[str]:
        """The adapter's CONFIGURED servers for ``family`` — empty
        when it obtains DNS automatically (DHCP). This is the value
        the guard records, compares, and verifies against; the
        effective (DHCP-learned) addresses are never reported here."""
        service = _FAMILY_TO_SERVICE[family]
        alias = interface_alias.replace("'", "''")
        script = (
            f"$adapter = Get-NetAdapter -Name '{alias}' "
            "-ErrorAction SilentlyContinue\n"
            "if ($null -eq $adapter) { throw 'adapter not found' }\n"
            "$guid = $adapter.InterfaceGuid.ToString('B')\n"
            f"$regPath = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\"
            f"{service}\\Parameters\\Interfaces\\$guid\"\n"
            "$configured = (Get-ItemProperty -Path $regPath "
            "-Name NameServer -ErrorAction SilentlyContinue).NameServer\n"
            "[PSCustomObject]@{ Configured = $configured } "
            "| ConvertTo-Json -Compress"
        )
        raw = _run_powershell(script)
        if isinstance(raw, dict):
            return parse_nameserver_value(raw.get("Configured"))
        if isinstance(raw, str):
            return parse_nameserver_value(raw)
        return []

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

    def effective_dns_servers(self) -> List[str]:
        """The machine's EFFECTIVE DNS servers, via the cmdlet
        whose output configured reads deliberately avoid (see the
        module docstring): Get-DnsClientServerAddress reports the
        addresses actually in use, DHCP-learned ones included —
        exactly the forwarding floor. Read over the same active
        adapters active_adapters() enumerates (up, carrying a
        default route); loopback and disconnected adapters are
        never consulted."""
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
        ServerAddresses = $entry.ServerAddresses
      }
    }
  }
}
$result | ConvertTo-Json -Compress
"""
        return parse_effective_servers(_run_powershell(script))
