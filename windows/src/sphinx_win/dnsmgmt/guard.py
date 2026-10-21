"""DnsGuard: the engage / disengage discipline around a DnsManager.

The rules, in order (the fleet's restore discipline — the machine
must never be left with broken DNS):

1. Elevation first. Without administrator rights, nothing is read
   for change and nothing is touched; the caller says so plainly.
2. The original settings are saved BEFORE any change, and the save
   is verified by reading it back. No verified save, no change.
3. An existing backup is never overwritten: if one is on disk, its
   recorded originals are the truth (a previous run may have died
   mid-engage; the loopback values now live must never be recorded
   as "original").
4. Every change is verified by reading the adapter back.
5. Disengage restores exactly what was recorded, verifies each
   adapter, and only then removes the backup. Anything that fails
   keeps the backup and is reported by name.
6. A backup on disk with live DNS *not* at loopback is a leftover
   (the earlier run restored by hand, or died in a strange place):
   it is surfaced as its own state so the user can restore or
   dismiss it — never silently treated as engaged.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..core.server import LOOPBACK_V4, LOOPBACK_V6
from ..core.store import write_atomically
from .base import FAMILY_V4, FAMILY_V6, AdapterDns, DnsManager, NotElevatedError

BACKUP_FILE_NAME = "dns-backup.json"
LOOPBACK_FOR_FAMILY = {FAMILY_V4: LOOPBACK_V4, FAMILY_V6: LOOPBACK_V6}


class DnsState(Enum):
    DISENGAGED = "disengaged"  # no backup; live DNS is the user's own
    ENGAGED = "engaged"  # backup on disk; live DNS points at the filter
    LEFTOVER = "leftover"  # backup on disk; live DNS no longer loopback
    UNKNOWN = "unknown"  # live DNS is loopback but no backup exists


@dataclass
class EngageResult:
    ok: bool
    message: str
    changed: List[AdapterDns] = field(default_factory=list)


@dataclass
class RestoreResult:
    ok: bool
    message: str
    failed: List[AdapterDns] = field(default_factory=list)


class DnsGuard:
    def __init__(self, manager: DnsManager, data_dir: Path):
        self._manager = manager
        self.backup_file = Path(data_dir) / BACKUP_FILE_NAME

    # --- Backup file ------------------------------------------------

    def load_backup(self) -> Optional[List[AdapterDns]]:
        try:
            raw = json.loads(self.backup_file.read_text(encoding="utf-8"))
            entries = raw["adapters"]
            return [AdapterDns.from_dict(e) for e in entries]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _save_backup_verified(self, adapters: List[AdapterDns]) -> bool:
        payload = {
            "version": 1,
            "saved_at_ms": int(time.time() * 1000),
            "adapters": [a.to_dict() for a in adapters],
        }
        write_atomically(
            self.backup_file, json.dumps(payload, indent=1).encode("utf-8")
        )
        # The save is verified by reading it back: a backup we cannot
        # read is not a backup, and without one nothing may change.
        loaded = self.load_backup()
        if loaded is None or len(loaded) != len(adapters):
            return False
        return all(
            got.interface_alias == want.interface_alias
            and got.family == want.family
            and got.servers == want.servers
            for got, want in zip(loaded, adapters)
        )

    def _delete_backup(self) -> None:
        try:
            self.backup_file.unlink(missing_ok=True)
        except OSError:
            pass

    # --- State detection ----------------------------------------------

    def _live_loopback_state(self, adapters: List[AdapterDns]) -> bool:
        """True when every given adapter/family currently points at
        the filter's loopback (exactly one server: the loopback)."""
        return all(
            self._manager.get_dns(a.interface_alias, a.family)
            == [LOOPBACK_FOR_FAMILY[a.family]]
            for a in adapters
        )

    def detect_state(self) -> DnsState:
        backup = self.load_backup()
        if backup is not None:
            if self._live_loopback_state(backup):
                return DnsState.ENGAGED
            return DnsState.LEFTOVER
        current = self._manager.active_adapters()
        pointed = [
            a
            for a in current
            if self._manager.get_dns(a.interface_alias, a.family)
            == [LOOPBACK_FOR_FAMILY[a.family]]
        ]
        if pointed and len(pointed) == len(current):
            # Loopback everywhere and no record of the originals:
            # Sphinx will not guess at settings it never saved.
            return DnsState.UNKNOWN
        return DnsState.DISENGAGED

    # --- Engage / disengage -------------------------------------------

    def engage(self) -> EngageResult:
        """Point the active adapters' DNS at the filter.

        Raises NotElevatedError before touching anything when the
        process lacks administrator rights."""
        if not self._manager.is_elevated():
            raise NotElevatedError(
                "Changing DNS settings needs administrator rights. "
                "Run Sphinx as administrator; nothing was changed."
            )

        existing = self.load_backup()
        if existing is not None:
            if self._live_loopback_state(existing):
                return EngageResult(True, "DNS already points at Sphinx.", [])
            # A leftover: the recorded originals stay the truth. Fall
            # through and re-engage against them — the backup on disk
            # is NOT replaced (rule 3).
            targets = existing
        else:
            targets = self._manager.active_adapters()
            if not targets:
                return EngageResult(
                    False, "No active network adapter was found.", []
                )
            if self._live_loopback_state(targets):
                return EngageResult(
                    False,
                    "DNS already points at a loopback resolver, but "
                    "Sphinx has no record of the previous settings, so "
                    "it will not take over settings it cannot restore. "
                    "Set DNS back to automatic (DHCP) in Windows "
                    "settings, then start Sphinx.",
                    [],
                )
            if not self._save_backup_verified(targets):
                return EngageResult(
                    False,
                    "Sphinx could not save your current DNS settings "
                    "verifiably, so it changed nothing.",
                    [],
                )

        changed: List[AdapterDns] = []
        for adapter in targets:
            loopback = LOOPBACK_FOR_FAMILY[adapter.family]
            try:
                self._manager.set_dns(adapter.interface_alias, adapter.family, [loopback])
            except Exception:
                self._rollback(changed, targets)
                return EngageResult(
                    False,
                    f"Setting DNS failed on {adapter.interface_alias} "
                    f"({adapter.family}); already-changed adapters were "
                    "restored from the saved settings.",
                    [],
                )
            if self._manager.get_dns(adapter.interface_alias, adapter.family) != [loopback]:
                self._rollback(changed + [adapter], targets)
                return EngageResult(
                    False,
                    f"DNS on {adapter.interface_alias} ({adapter.family}) "
                    "did not verify after the change; everything was "
                    "restored from the saved settings.",
                    [],
                )
            changed.append(adapter)
        return EngageResult(
            True,
            "DNS points at Sphinx on "
            + ", ".join(sorted({a.interface_alias for a in changed}))
            + ".",
            changed,
        )

    def _rollback(self, changed: List[AdapterDns], originals: List[AdapterDns]) -> None:
        by_key = {(a.interface_alias, a.family): a for a in originals}
        for adapter in changed:
            original = by_key.get((adapter.interface_alias, adapter.family))
            if original is None:
                continue
            try:
                self._manager.set_dns(
                    original.interface_alias, original.family, list(original.servers)
                )
            except Exception:
                pass  # best effort; the backup file remains for restore

    def disengage(self) -> RestoreResult:
        """Restore the recorded settings exactly, verify each, and
        only then remove the backup."""
        if not self._manager.is_elevated():
            raise NotElevatedError(
                "Restoring DNS settings needs administrator rights. "
                "Run Sphinx as administrator; nothing was changed."
            )
        backup = self.load_backup()
        if backup is None:
            return RestoreResult(True, "No saved DNS settings to restore.", [])
        failed: List[AdapterDns] = []
        for adapter in backup:
            try:
                self._manager.set_dns(
                    adapter.interface_alias, adapter.family, list(adapter.servers)
                )
                if self._manager.get_dns(
                    adapter.interface_alias, adapter.family
                ) != list(adapter.servers):
                    failed.append(adapter)
            except Exception:
                failed.append(adapter)
        if failed:
            names = ", ".join(
                f"{a.interface_alias} ({a.family})" for a in failed
            )
            return RestoreResult(
                False,
                f"DNS could not be verified as restored on: {names}. "
                "The saved settings were kept — try Restore again.",
                failed,
            )
        self._delete_backup()
        return RestoreResult(True, "Your previous DNS settings are restored.", [])

    def dismiss_leftover(self) -> bool:
        """The user confirms a leftover backup is no longer wanted
        (e.g. they fixed DNS by hand and checked it). Deletes the
        backup record only; changes no settings."""
        if self.load_backup() is None:
            return False
        self._delete_backup()
        return True
