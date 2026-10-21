"""The seam between the engage/restore discipline and the machine.

``ResolverView`` is everything :class:`DnsGuard` needs to know or
change about the machine's resolver setup, and nothing more.
Production uses :class:`RealSystemView` (files under /etc, plus
``resolvectl`` / ``systemctl`` / ``ip`` / ``nmcli``); tests use an
in-memory fake implementing the same protocol against a temp-dir
resolv.conf, so the discipline is proven without ever touching the
host's real resolver configuration.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Protocol

RESOLV_CONF = Path("/etc/resolv.conf")

#: The systemd-resolved stub listener's address. On a resolved
#: machine this is what /etc/resolv.conf points at, and it is
#: resolved's own address: Sphinx never binds it, never records it
#: as its own, and never forwards upstream to it.
RESOLVED_STUB = "127.0.0.53"


def write_atomically(target: Path, data: bytes) -> None:
    """Write ``data`` to ``target`` so the file is never left torn:
    write a temp file, then rename it over the target. If the rename
    ever refuses, stage the copy under a second name and rename
    *that* — copying straight over the target is not an option,
    because a crash mid-copy would leave half a file behind. If even
    the staged rename fails, the old file stays and the temps are
    cleaned up. (The fleet's store discipline, shared with the other
    editions.)"""
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.name + ".tmp")
    temp.write_bytes(data)
    try:
        os.replace(temp, target)
        return
    except OSError:
        pass
    swap = target.with_name(target.name + ".swap")
    try:
        shutil.copyfile(temp, swap)
        os.replace(swap, target)
    except OSError:
        try:
            swap.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def nameservers_in(resolv_conf: bytes) -> List[str]:
    """The nameserver addresses a resolv.conf carries, in order."""
    found: List[str] = []
    for line in resolv_conf.decode("utf-8", "replace").splitlines():
        text = line.strip()
        for marker in ("#", ";"):
            at = text.find(marker)
            if at >= 0:
                text = text[:at].strip()
        if not text:
            continue
        parts = text.split()
        if len(parts) == 2 and parts[0] == "nameserver":
            found.append(parts[1])
    return found


def is_loopback(address: str) -> bool:
    """True for any loopback address (127.0.0.0/8 or ::1)."""
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def is_ip_literal(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def parse_resolvectl_dns(output: str) -> List[str]:
    """Parse ``resolvectl dns <link>`` output into server addresses.

    Output shape: ``Link 2 (eth0): 192.168.1.1 9.9.9.9`` — or nothing
    after the colon when the link has no servers. Only tokens that
    parse as IP addresses are kept.
    """
    servers: List[str] = []
    for line in output.splitlines():
        if ":" not in line:
            continue
        _, _, rest = line.partition(":")
        for token in rest.split():
            if is_ip_literal(token):
                servers.append(token)
    return servers


def parse_default_link(ip_route_json: str) -> Optional[str]:
    """The device carrying the default route, from
    ``ip -j route show default`` output."""
    try:
        routes = json.loads(ip_route_json)
    except ValueError:
        return None
    for route in routes if isinstance(routes, list) else []:
        if isinstance(route, dict) and route.get("dst") == "default":
            dev = route.get("dev")
            if isinstance(dev, str) and dev:
                return dev
    return None


def parse_nm_connected_devices(nmcli_output: str) -> set:
    """Devices NetworkManager reports as connected, from
    ``nmcli -t -f DEVICE,STATE device status`` output."""
    devices = set()
    for line in nmcli_output.splitlines():
        device, _, state = line.partition(":")
        if device and state.strip() == "connected":
            devices.add(device.strip())
    return devices


class ResolverView(Protocol):
    """Reads and writes the machine's resolver configuration.

    Implementations must only ever be driven through DnsGuard, which
    owns the save-before-change discipline.
    """

    def is_root(self) -> bool:
        """True when this process may change resolver settings."""
        ...

    def resolv_conf_bytes(self) -> bytes:
        """The current contents of the resolver file (following any
        symlink, as a resolver reading it would see)."""
        ...

    def resolv_conf_symlink_target(self) -> Optional[str]:
        """The symlink target of /etc/resolv.conf, or None when it is
        a regular file (or missing)."""
        ...

    def systemd_resolved_active(self) -> bool:
        ...

    def network_manager_manages_default(self) -> bool:
        """True when NetworkManager is active AND manages the link
        carrying the default route (or generates the resolver file).
        An installed-but-idle NetworkManager does not count: what
        matters is whether it owns this machine's DNS."""
        ...

    def default_link(self) -> Optional[str]:
        """The interface carrying the default route, if any."""
        ...

    def link_dns(self, link: str) -> List[str]:
        """The DNS servers systemd-resolved currently uses for
        ``link`` (its configured-or-learned set — see the guard's
        notes on what may be recorded as an original)."""
        ...

    def set_link_dns(self, link: str, servers: List[str]) -> None:
        """``resolvectl dns <link> <servers...>``"""
        ...

    def revert_link(self, link: str) -> None:
        """``resolvectl revert <link>`` — drop the runtime per-link
        settings, returning the link to its configured/automatic
        state."""
        ...

    def write_resolv_conf(self, data: bytes) -> None:
        """Atomically replace the resolver file's contents. Only
        DnsGuard calls this, and only on the direct stack."""
        ...

    def service_active(self, unit: str) -> Optional[bool]:
        """systemd's word on a unit: True/False, or None when there
        is no systemd to ask on this machine."""
        ...


def _run(argv: List[str], timeout: float = 10.0) -> Optional[str]:
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return done.stdout


class RealSystemView:
    """The production ResolverView: real files, real tools.

    ``root_prefix`` exists so the view can be pointed at a scratch
    root in manual testing; production passes "".
    """

    def __init__(self, root_prefix: str = ""):
        self._resolv_conf = Path(root_prefix + str(RESOLV_CONF))

    # -- identity ---------------------------------------------------

    def is_root(self) -> bool:
        return os.geteuid() == 0

    # -- the resolver file -------------------------------------------

    def resolv_conf_bytes(self) -> bytes:
        try:
            return self._resolv_conf.read_bytes()
        except OSError:
            return b""

    def resolv_conf_symlink_target(self) -> Optional[str]:
        try:
            if self._resolv_conf.is_symlink():
                return os.readlink(self._resolv_conf)
        except OSError:
            pass
        return None

    def write_resolv_conf(self, data: bytes) -> None:
        write_atomically(self._resolv_conf, data)
        try:
            os.chmod(self._resolv_conf, 0o644)
        except OSError:
            pass

    # -- systemd / NetworkManager ------------------------------------

    def _is_active(self, unit: str) -> bool:
        out = _run(["systemctl", "is-active", unit])
        return out is not None and out.strip() == "active"

    def systemd_resolved_active(self) -> bool:
        return self._is_active("systemd-resolved")

    def service_active(self, unit: str) -> Optional[bool]:
        out = _run(["systemctl", "is-active", unit])
        if out is None:
            return None
        return out.strip() == "active"

    def network_manager_manages_default(self) -> bool:
        if not self._is_active("NetworkManager"):
            return False
        head = self.resolv_conf_bytes()[:512].lower()
        if b"networkmanager" in head:
            return True
        link = self.default_link()
        if link is None:
            return False
        out = _run(["nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"])
        if out is None:
            return False
        return link in parse_nm_connected_devices(out)

    # -- links and resolved -------------------------------------------

    def default_link(self) -> Optional[str]:
        out = _run(["ip", "-j", "route", "show", "default"])
        if out is not None:
            link = parse_default_link(out)
            if link:
                return link
        out = _run(["ip", "route", "show", "default"])
        if out:
            tokens = out.split()
            if "dev" in tokens:
                at = tokens.index("dev")
                if at + 1 < len(tokens):
                    return tokens[at + 1]
        return None

    def link_dns(self, link: str) -> List[str]:
        out = _run(["resolvectl", "dns", link])
        if out is None:
            return []
        return parse_resolvectl_dns(out)

    def set_link_dns(self, link: str, servers: List[str]) -> None:
        done = subprocess.run(
            ["resolvectl", "dns", link, *servers],
            capture_output=True, text=True, timeout=10,
        )
        if done.returncode != 0:
            raise OSError(
                f"resolvectl could not set DNS on {link}: "
                f"{done.stderr.strip() or done.stdout.strip()}"
            )

    def revert_link(self, link: str) -> None:
        done = subprocess.run(
            ["resolvectl", "revert", link],
            capture_output=True, text=True, timeout=10,
        )
        if done.returncode != 0:
            raise OSError(
                f"resolvectl could not revert {link}: "
                f"{done.stderr.strip() or done.stdout.strip()}"
            )
