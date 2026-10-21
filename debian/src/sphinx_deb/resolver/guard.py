"""DnsGuard: the engage / restore discipline around a ResolverView.

The rules, in order (the fleet's restore discipline — the machine
must never be left with broken DNS):

1. Root first. Without root, nothing is read for change and nothing
   is touched; the caller says so plainly.
2. The filter must prove it answers on a loopback before DNS is
   pointed at it — per family. A family is engaged only when its
   loopback was proven; the engagement is reported as the partial
   thing it is when only one family could be proven.
3. The original settings are saved BEFORE any change, and the save
   is verified by reading it back. No verified save, no change. An
   existing record is never overwritten: if one is on disk, its
   recorded originals are the truth (a previous run may have died
   mid-engage; the loopback values now live must never be recorded
   as "original"). A fresh save is refused outright when ANY current
   nameserver is already a loopback — those previous settings are
   unknowable, so there is nothing honest to record.
4. Every change is verified by reading the resolver back, and by a
   live question through the new path. Anything that fails is
   rolled back to the recorded originals; the record is kept (the
   machine is then a "leftover", offered for restore or dismissal).
5. Restore puts back exactly what was recorded, verifies it, and
   only then removes the record. Anything that fails keeps the
   record and is reported loudly — a failed restore never claims
   success.
6. A record on disk with live DNS *not* at the filter is a leftover;
   live DNS at the filter with no record is unknown. Both are their
   own states, surfaced for the user's decision — never silently
   treated as on, and never taken over.

Debian specifics, stated rather than hidden:

- Two stacks are engageable in Phase 1. The **direct** stack: a
  regular /etc/resolv.conf the machine's owner maintains (the guard
  rewrites it, keeping every non-nameserver line, and restores it
  byte-for-byte). The **resolved** stack: systemd-resolved in its
  standard stub setup (engage is a ``resolvectl`` runtime override
  on the default link; restore is ``resolvectl revert`` — the exact
  undo of the override, returning the link to whatever its
  configuration and DHCP provide; see debian/README.md for what
  that means for a hand-set resolvectl override).
- NetworkManager-managed machines and unrecognized resolver setups
  are **refused, plainly**: a tool that owns or regenerates the
  resolver state would fight any change, and guessing at restore
  values is how machines lose DNS.
- Intent (the recorded on/off decision) is written only at
  successful transitions.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Protocol

from ..core.server import LOOPBACK_V4, LOOPBACK_V6
from .systemview import (
    RESOLVED_STUB,
    ResolverView,
    is_loopback,
    nameservers_in,
    write_atomically,
)

BACKUP_FILE_NAME = "dns-backup.json"
INTENT_FILE_NAME = "state.json"

FAMILY_V4 = "IPv4"
FAMILY_V6 = "IPv6"
LOOPBACK_FOR_FAMILY = {FAMILY_V4: LOOPBACK_V4, FAMILY_V6: LOOPBACK_V6}
SPHINX_LOOPBACKS = frozenset({LOOPBACK_V4, LOOPBACK_V6})

STACK_DIRECT = "direct"
STACK_RESOLVED = "resolved"
STACK_NETWORKMANAGER = "networkmanager"
STACK_OTHER = "other"
ENGAGEABLE_STACKS = (STACK_DIRECT, STACK_RESOLVED)


class RightsRequiredError(RuntimeError):
    """Raised when a resolver change is attempted without root. The
    check happens before anything is touched: an unprivileged run
    changes nothing and says so plainly."""


class DnsState(Enum):
    DISENGAGED = "disengaged"  # no record; live DNS is the user's own
    ENGAGED = "engaged"  # record on disk; live DNS points at the filter
    LEFTOVER = "leftover"  # record on disk; live DNS no longer at the filter
    UNKNOWN = "unknown"  # live DNS is at the filter but no record exists


class Stack(Enum):
    DIRECT = STACK_DIRECT
    RESOLVED = STACK_RESOLVED
    NETWORKMANAGER = STACK_NETWORKMANAGER
    OTHER = STACK_OTHER


@dataclass
class EngageResult:
    ok: bool
    message: str
    engaged_loopbacks: List[str] = field(default_factory=list)


@dataclass
class RestoreResult:
    ok: bool
    message: str


class Proofer(Protocol):
    """How the guard learns the filter is alive, per loopback.

    The production proofer asks the running daemon (over its local
    control socket) to prove it answers, and questions the resolved
    stub directly for the end-to-end chain proof; tests script one.
    """

    def loopback_answers(self, address: str) -> bool:
        ...

    def stub_answers(self) -> bool:
        ...


# --- Stack + state detection ---------------------------------------


def detect_stack(view: ResolverView) -> Stack:
    """Which resolver stack owns this machine's DNS, from real reads.

    The answer is deliberately conservative: anything that is not
    positively one of the two engageable stacks comes back as a
    stack the guard refuses.
    """
    target = view.resolv_conf_symlink_target()
    data = view.resolv_conf_bytes()
    names = nameservers_in(data)
    if view.network_manager_manages_default():
        return Stack.NETWORKMANAGER
    if target is not None:
        if "systemd/resolve" in target:
            if view.systemd_resolved_active() and RESOLVED_STUB in names:
                return Stack.RESOLVED
            return Stack.OTHER
        return Stack.OTHER  # a symlink to something else entirely
    if not data:
        return Stack.OTHER  # no resolver file at all
    if view.systemd_resolved_active() and RESOLVED_STUB in names:
        # A regular file that nonetheless points at the stub: the
        # lever is still resolvectl, and the file stays untouched.
        return Stack.RESOLVED
    head = data[:1024].lower()
    for generator in (b"dhcpcd", b"resolvconf", b"openresolv", b"networkmanager"):
        if generator in head:
            # A tool generates this file; hand-writing it would be
            # overwritten, and restore could fight the generator.
            return Stack.OTHER
    return Stack.DIRECT


@dataclass
class BackupRecord:
    """The saved originals. Exactly what restore will put back."""

    stack: str
    engaged_loopbacks: List[str]
    # direct stack: the whole previous file, byte-for-byte.
    resolv_conf_b64: str = ""
    resolv_conf_sha256: str = ""
    # resolved stack: the link, and the servers it used beforehand
    # (kept as information; restore is resolvectl revert — see the
    # module notes).
    link: str = ""
    prior_servers: List[str] = field(default_factory=list)

    def original_resolv_conf(self) -> Optional[bytes]:
        try:
            raw = base64.b64decode(self.resolv_conf_b64.encode(), validate=True)
        except (ValueError, TypeError):
            return None
        if hashlib.sha256(raw).hexdigest() != self.resolv_conf_sha256:
            return None
        return raw

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "stack": self.stack,
            "engaged_loopbacks": list(self.engaged_loopbacks),
            "resolv_conf_b64": self.resolv_conf_b64,
            "resolv_conf_sha256": self.resolv_conf_sha256,
            "link": self.link,
            "prior_servers": list(self.prior_servers),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> Optional["BackupRecord"]:
        """Parse and validate a record. A record that claims a
        loopback as the original is corrupt by construction (engage
        refuses to record one), so it is refused here too."""
        try:
            if raw.get("version") != 1:
                return None
            stack = str(raw["stack"])
            loopbacks = [str(x) for x in raw["engaged_loopbacks"]]
            if stack not in ENGAGEABLE_STACKS:
                return None
            if not loopbacks or any(lb not in SPHINX_LOOPBACKS for lb in loopbacks):
                return None
            record = cls(
                stack=stack,
                engaged_loopbacks=loopbacks,
                resolv_conf_b64=str(raw.get("resolv_conf_b64", "")),
                resolv_conf_sha256=str(raw.get("resolv_conf_sha256", "")),
                link=str(raw.get("link", "")),
                prior_servers=[str(s) for s in raw.get("prior_servers", [])],
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
        if stack == STACK_DIRECT:
            original = record.original_resolv_conf()
            if original is None:
                return None
            recorded_names = nameservers_in(original)
            if recorded_names and all(is_loopback(n) for n in recorded_names):
                return None  # a loopback "original" — never legitimate
        if stack == STACK_RESOLVED:
            if not record.link:
                return None
            if record.prior_servers and all(
                is_loopback(s) for s in record.prior_servers
            ):
                return None
        return record


def compose_engaged_resolv_conf(original: bytes, loopbacks: List[str]) -> bytes:
    """The resolver file while Sphinx is on: the filter's loopbacks
    as the only nameservers, every other line of the original kept
    (search domains, options — the machine's own settings ride
    along). Restore never depends on this file; it puts back the
    recorded original bytes exactly."""
    kept: List[str] = []
    for line in original.decode("utf-8", "replace").splitlines():
        effective = line
        for marker in ("#", ";"):
            at = effective.find(marker)
            if at >= 0:
                effective = effective[:at]
        tokens = effective.split()
        if tokens and tokens[0] == "nameserver":
            continue  # replaced by the filter's loopbacks
        kept.append(line)
    out = [
        "# Sphinx is on. Name lookups go to the Sphinx filter on this machine.",
        "# Your previous settings are saved by Sphinx and come back exactly",
        "# when you turn Sphinx off:  sudo sphinx restore",
    ]
    out += [f"nameserver {lb}" for lb in loopbacks]
    out += [line for line in kept if line.strip()]
    return ("\n".join(out) + "\n").encode("utf-8")


class DnsGuard:
    def __init__(self, view: ResolverView, state_dir: Path):
        self._view = view
        self.state_dir = Path(state_dir)
        self.backup_file = self.state_dir / BACKUP_FILE_NAME
        self.intent_file = self.state_dir / INTENT_FILE_NAME

    # --- the record -------------------------------------------------

    def load_backup(self) -> Optional[BackupRecord]:
        try:
            raw = json.loads(self.backup_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(raw, dict):
            return None
        return BackupRecord.from_dict(raw)

    def backup_problem(self) -> Optional[str]:
        """A plain-language problem when a record file exists but
        cannot be read or trusted; None when there is no record or
        the record is sound. A record Sphinx cannot read is never
        overwritten and never silently ignored."""
        if not self.backup_file.exists():
            return None
        if self.load_backup() is None:
            return (
                "A saved DNS record exists but Sphinx cannot read or "
                "trust it, so nothing was changed and the record was "
                f"kept. It is at {self.backup_file} — it holds the "
                "settings from when Sphinx was turned on."
            )
        return None

    def _save_backup_verified(self, record: BackupRecord) -> bool:
        payload = dict(record.to_dict())
        payload["saved_at_ms"] = int(time.time() * 1000)
        write_atomically(
            self.backup_file, json.dumps(payload, indent=1).encode("utf-8")
        )
        # The save is verified by reading it back: a record we cannot
        # read is not a record, and without one nothing may change.
        loaded = self.load_backup()
        if loaded is None:
            return False
        return (
            loaded.stack == record.stack
            and loaded.engaged_loopbacks == record.engaged_loopbacks
            and loaded.resolv_conf_sha256 == record.resolv_conf_sha256
            and loaded.link == record.link
            and loaded.prior_servers == record.prior_servers
        )

    def _delete_backup(self) -> None:
        try:
            self.backup_file.unlink(missing_ok=True)
        except OSError:
            pass

    # --- intent -------------------------------------------------------

    def load_intent(self) -> Optional[dict]:
        try:
            raw = json.loads(self.intent_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return raw if isinstance(raw, dict) else None

    def _write_intent(self, engaged: bool, stack: str, loopbacks: List[str]) -> None:
        payload = {
            "version": 1,
            "engaged": engaged,
            "stack": stack,
            "loopbacks": list(loopbacks),
            "updated_at_ms": int(time.time() * 1000),
        }
        try:
            write_atomically(
                self.intent_file, json.dumps(payload, indent=1).encode("utf-8")
            )
        except OSError:
            pass  # intent is bookkeeping; the record is the truth

    # --- live-state reads ----------------------------------------------

    def _live_pointed(self, stack: Stack) -> List[str]:
        """The loopbacks live DNS currently points at (subset of the
        filter's own), from real reads."""
        if stack == Stack.DIRECT:
            names = nameservers_in(self._view.resolv_conf_bytes())
            if names and all(n in SPHINX_LOOPBACKS for n in names):
                return sorted(set(names))
        elif stack == Stack.RESOLVED:
            link = self._view.default_link()
            if link:
                servers = self._view.link_dns(link)
                if servers and all(s in SPHINX_LOOPBACKS for s in servers):
                    return sorted(set(servers))
        return []

    def _matches_record(self, record: BackupRecord) -> bool:
        """Live DNS sits where this record's engagement put it.

        Tolerant of a partial (re-)engagement, like the other
        editions: after a re-engage that could only prove one
        family, live points at a *subset* of the loopbacks the
        record names — that is still this record's engagement, not
        a leftover. The record on disk is never rewritten to say
        so; its originals are the truth and they are untouched.
        """
        recorded = set(record.engaged_loopbacks)
        if record.stack == STACK_DIRECT:
            live = set(nameservers_in(self._view.resolv_conf_bytes()))
        else:
            live = set(self._view.link_dns(record.link)) if record.link else set()
        return bool(live) and live <= recorded and live <= SPHINX_LOOPBACKS

    def detect_state(self) -> DnsState:
        if self.backup_problem() is not None:
            return DnsState.LEFTOVER  # a record exists; it waits for the user
        backup = self.load_backup()
        if backup is not None:
            return DnsState.ENGAGED if self._matches_record(backup) else DnsState.LEFTOVER
        stack = detect_stack(self._view)
        if stack in (Stack.DIRECT, Stack.RESOLVED) and self._live_pointed(stack):
            # Pointed at the filter with no record of the originals:
            # Sphinx will not guess at settings it never saved.
            return DnsState.UNKNOWN
        return DnsState.DISENGAGED

    # --- engage ---------------------------------------------------------

    def engage(self, proofer: Proofer) -> EngageResult:
        if not self._view.is_root():
            raise RightsRequiredError(
                "Changing DNS settings needs root. Run it with sudo: "
                "sudo sphinx engage — nothing was changed."
            )
        problem = self.backup_problem()
        if problem is not None:
            return EngageResult(False, problem, [])
        stack = detect_stack(self._view)
        if stack == Stack.NETWORKMANAGER:
            return EngageResult(
                False,
                "NetworkManager is in charge of this machine's DNS "
                "settings, and Sphinx Phase 1 does not take over from "
                "NetworkManager — it would fight any change and could "
                "not promise an exact restore. Nothing was changed.",
                [],
            )
        if stack not in (Stack.DIRECT, Stack.RESOLVED):
            return EngageResult(
                False,
                "This machine's resolver setup is not one Sphinx "
                "Phase 1 can safely take over (it is not a plain "
                "/etc/resolv.conf, and not systemd-resolved in its "
                "standard stub setup), so nothing was changed. "
                "Sphinx will not guess at settings it cannot restore "
                "exactly.",
                [],
            )
        state = self.detect_state()
        if state == DnsState.UNKNOWN:
            return EngageResult(
                False,
                "DNS already points at a resolver on this machine, "
                "but Sphinx has no saved record of the previous "
                "settings, so it will not take over settings it "
                "cannot restore. Put DNS back the way it was (or to "
                "automatic), then turn Sphinx on.",
                [],
            )
        if state == DnsState.ENGAGED:
            return EngageResult(True, "Sphinx is already on.", [])

        # The toll: the filter proves it answers — per family —
        # before anything is saved or pointed.
        proven: Dict[str, str] = {}
        for family, loopback in LOOPBACK_FOR_FAMILY.items():
            if proofer.loopback_answers(loopback):
                proven[family] = loopback
        if not proven:
            return EngageResult(
                False,
                "The Sphinx filter is not answering, so DNS was left "
                "unchanged — a machine is never pointed at a resolver "
                "that is not answering. Start the service first: "
                "sudo systemctl start sphinx",
                [],
            )
        engaged_loopbacks = [proven[f] for f in (FAMILY_V4, FAMILY_V6) if f in proven]

        existing = self.load_backup()
        if existing is not None:
            # A leftover: re-engage against the recorded originals.
            # The record on disk stays the truth — never re-saved.
            if existing.stack != stack.value:
                return EngageResult(
                    False,
                    "The saved DNS record is from a different resolver "
                    "setup than this machine has now, so Sphinx will "
                    "not re-engage against it. Restore it (sudo "
                    "sphinx restore) or dismiss it (sudo sphinx "
                    "dismiss) first — nothing was changed.",
                    [],
                )
            record = existing
            record.engaged_loopbacks = engaged_loopbacks
        else:
            record = self._gather_originals(stack, engaged_loopbacks)
            if isinstance(record, EngageResult):
                return record
            if not self._save_backup_verified(record):
                return EngageResult(
                    False,
                    "Sphinx could not save your current DNS settings "
                    "verifiably, so it changed nothing.",
                    [],
                )

        try:
            self._apply_point(stack, record)
        except Exception as exc:
            self._rollback(record)
            return EngageResult(
                False,
                f"Pointing DNS at Sphinx failed ({exc}); your "
                "previous settings were put back from the saved record.",
                [],
            )
        if not self._verify_pointed(stack, record):
            self._rollback(record)
            return EngageResult(
                False,
                "DNS did not verify after the change, so your "
                "previous settings were put back from the saved "
                "record. The record was kept — sphinx status shows "
                "the state.",
                [],
            )
        if not self._post_point_proof(stack, proofer, engaged_loopbacks):
            self._rollback(record)
            return EngageResult(
                False,
                "DNS was pointed at Sphinx but the filter did not "
                "answer through the new path, so your previous "
                "settings were put back from the saved record.",
                [],
            )

        self._write_intent(True, stack.value, engaged_loopbacks)
        message = "Sphinx is on: DNS points at the filter on this machine."
        if len(engaged_loopbacks) == 1:
            missing = FAMILY_V6 if engaged_loopbacks == [LOOPBACK_V4] else FAMILY_V4
            message += (
                f" {missing} DNS was left unchanged — the filter is "
                f"not answering on that family's loopback."
            )
        if existing is not None:
            message += " (Re-engaged against the settings saved earlier.)"
        return EngageResult(True, message, engaged_loopbacks)

    def _gather_originals(self, stack: Stack, engaged_loopbacks: List[str]):
        """Build the record of the machine's current settings, or an
        EngageResult refusing — a loopback can never be recorded as
        an original."""
        if stack == Stack.DIRECT:
            data = self._view.resolv_conf_bytes()
            names = nameservers_in(data)
            looped = [n for n in names if is_loopback(n)]
            if looped:
                return EngageResult(
                    False,
                    "DNS already points at a resolver on this machine "
                    f"({', '.join(sorted(set(looped)))}), but Sphinx "
                    "has no record of the previous settings, so it "
                    "will not take over settings it cannot restore. "
                    "Set DNS back to your usual resolver (or "
                    "automatic) first, then turn Sphinx on.",
                    [],
                )
            return BackupRecord(
                stack=STACK_DIRECT,
                engaged_loopbacks=engaged_loopbacks,
                resolv_conf_b64=base64.b64encode(data).decode(),
                resolv_conf_sha256=hashlib.sha256(data).hexdigest(),
            )
        link = self._view.default_link()
        if not link:
            return EngageResult(
                False,
                "No network connection with a default route was "
                "found, so there is nothing to point at Sphinx.",
                [],
            )
        prior = self._view.link_dns(link)
        if any(is_loopback(s) for s in prior):
            return EngageResult(
                False,
                "The connection's DNS already includes a resolver on "
                "this machine, but Sphinx has no record of the "
                "previous settings, so it will not take over settings "
                "it cannot restore. Remove that resolver first, then "
                "turn Sphinx on.",
                [],
            )
        return BackupRecord(
            stack=STACK_RESOLVED,
            engaged_loopbacks=engaged_loopbacks,
            link=link,
            prior_servers=prior,
        )

    def _apply_point(self, stack: Stack, record: BackupRecord) -> None:
        if record.stack == STACK_DIRECT:
            original = record.original_resolv_conf()
            if original is None:
                raise OSError("the saved record could not be read back")
            self._view.write_resolv_conf(
                compose_engaged_resolv_conf(original, record.engaged_loopbacks)
            )
        else:
            self._view.set_link_dns(record.link, record.engaged_loopbacks)

    def _verify_pointed(self, stack: Stack, record: BackupRecord) -> bool:
        if record.stack == STACK_DIRECT:
            names = nameservers_in(self._view.resolv_conf_bytes())
            return sorted(set(names)) == sorted(set(record.engaged_loopbacks))
        servers = self._view.link_dns(record.link)
        return sorted(set(servers)) == sorted(set(record.engaged_loopbacks))

    def _post_point_proof(
        self, stack: Stack, proofer: Proofer, engaged_loopbacks: List[str]
    ) -> bool:
        if stack == Stack.RESOLVED:
            # Through the stub: the whole chain (stub -> resolved ->
            # Sphinx) must answer.
            return proofer.stub_answers()
        return all(proofer.loopback_answers(lb) for lb in engaged_loopbacks)

    def _rollback(self, record: BackupRecord) -> None:
        """Best effort: put the recorded originals back. The record
        itself stays on disk — if this failed too, it is the only
        way back, and status will show the leftover."""
        try:
            if record.stack == STACK_DIRECT:
                original = record.original_resolv_conf()
                if original is not None:
                    self._view.write_resolv_conf(original)
            else:
                self._view.revert_link(record.link)
        except Exception:
            pass

    # --- restore -------------------------------------------------------

    def disengage(self) -> RestoreResult:
        if not self._view.is_root():
            raise RightsRequiredError(
                "Restoring DNS settings needs root. Run it with sudo: "
                "sudo sphinx restore — nothing was changed."
            )
        problem = self.backup_problem()
        if problem is not None:
            return RestoreResult(False, problem)
        record = self.load_backup()
        if record is None:
            if self.detect_state() == DnsState.UNKNOWN:
                return RestoreResult(
                    False,
                    "DNS points at a resolver on this machine, but "
                    "Sphinx has no saved record of the previous "
                    "settings, so there is nothing it can honestly "
                    "restore. Set DNS back by hand (or to automatic) "
                    "in your network settings.",
                )
            return RestoreResult(True, "No saved DNS settings to restore.")
        try:
            if record.stack == STACK_DIRECT:
                original = record.original_resolv_conf()
                if original is None:
                    return RestoreResult(
                        False,
                        "The saved record could not be read back, so "
                        "nothing was changed and the record was kept.",
                    )
                self._view.write_resolv_conf(original)
                if self._view.resolv_conf_bytes() != original:
                    return RestoreResult(
                        False,
                        "DNS was written back but did not verify as "
                        "your previous settings. The saved record was "
                        "kept — try sudo sphinx restore again.",
                    )
                note = ""
            else:
                self._view.revert_link(record.link)
                servers = self._view.link_dns(record.link)
                still = [s for s in servers if s in SPHINX_LOOPBACKS]
                if still:
                    return RestoreResult(
                        False,
                        "DNS on this connection still points at "
                        "Sphinx after the restore attempt. The saved "
                        "record was kept — try sudo sphinx restore "
                        "again.",
                    )
                note = ""
                if sorted(servers) != sorted(record.prior_servers):
                    note = (
                        " The connection's DNS servers differ from "
                        "when Sphinx was turned on — they come from "
                        "the network (DHCP), which may have renewed "
                        "since; the restore itself is exact: Sphinx's "
                        "override is gone."
                    )
        except Exception as exc:
            return RestoreResult(
                False,
                f"Restoring DNS failed ({exc}). The saved record was "
                "kept — try sudo sphinx restore again.",
            )
        self._delete_backup()
        self._write_intent(False, record.stack, [])
        return RestoreResult(
            True, "Your previous DNS settings are restored." + note
        )

    def dismiss_leftover(self) -> RestoreResult:
        """The user confirms a leftover record is no longer wanted
        (e.g. they fixed DNS by hand and checked it). Deletes the
        record only; changes no settings."""
        if not self._view.is_root():
            raise RightsRequiredError(
                "Dismissing the saved record needs root. Run it with "
                "sudo: sudo sphinx dismiss — nothing was changed."
            )
        if self.load_backup() is None and not self.backup_file.exists():
            return RestoreResult(True, "There is no saved DNS record.")
        if self.detect_state() == DnsState.ENGAGED:
            return RestoreResult(
                False,
                "Sphinx is on — turn it off first (sudo sphinx "
                "restore); the record is what makes turning it off "
                "exact.",
            )
        self._delete_backup()
        self._write_intent(False, "", [])
        return RestoreResult(
            True,
            "The saved DNS record is dismissed. No settings were changed.",
        )
