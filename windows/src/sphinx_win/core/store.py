"""Where Sphinx keeps its lists on the machine, and how the working
set is chosen — a port of the Android edition's ``lists/ListStore.kt``
(the list parts, and — since Windows Phase 3 — its profiles: the
profile store behavior mirrors the Android store's, audit fixes
included).

All storage is under one app data directory chosen by the app shell.
Nothing here leaves the device.

Which blocklist is active (FILTER-SPEC, "List updates"):
  - If downloaded lists are on disk and together pass the sanity
    gate, they are the blocklist.
  - Otherwise the list bundled with the app is the blocklist. The
    bundled list is never modified by updates, so there is always a
    known-good list to fall back to.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Collection, List, Optional

from .blocklist import Allowlist, Blocklist, FilterLists, normalize_entry, parse_entries
from .profiles import Profile, ProfileSet, RuleState, is_valid_profile_name
from .validation import DEFAULT_SOURCES, ListSource, is_acceptable_url, parse_and_validate
from . import validation as _validation

BUNDLED_LIST_NAME = "bundled-blocklist.txt"


def write_atomically(target: Path, data: bytes) -> None:
    """Write ``data`` to ``target`` so the file is never left torn:
    write a temp file, then rename it over the target. If the rename
    ever refuses, stage the copy under a second name and rename
    *that* — copying straight over the target is not an option,
    because a crash mid-copy would leave half a file behind (and a
    half-written list can still pass the sanity gate as a silently
    weaker list). If even the staged rename fails, the old file stays
    and the temps are cleaned up.
    """
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
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def _file_name_for(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return digest[:16] + ".txt"


@dataclass(frozen=True)
class StoreStatus:
    active_domains: int
    using_downloaded: bool
    last_updated_ms: int


class Store:
    """List storage rooted at one data directory.

    Layout:
      <dir>/lists/<sha256(url)[:16]>.txt   downloaded list copies
      <dir>/allowlist.txt                  the user's allowlist
      <dir>/custom-block.txt               the user's own block entries
      <dir>/profiles.txt                   named profiles of the two
                                           rule files above (Phase 3)
      <dir>/state.json                     sources, last update, settings
    """

    def __init__(self, data_dir: Path, bundled_list_path: Optional[Path] = None):
        self.data_dir = Path(data_dir)
        self.lists_dir = self.data_dir / "lists"
        self.lists_dir.mkdir(parents=True, exist_ok=True)
        self.allowlist_file = self.data_dir / "allowlist.txt"
        self.custom_block_file = self.data_dir / "custom-block.txt"
        self.profiles_file = self.data_dir / "profiles.txt"
        self.state_file = self.data_dir / "state.json"
        if bundled_list_path is None:
            bundled_list_path = Path(__file__).resolve().parent.parent / "data" / BUNDLED_LIST_NAME
        self.bundled_list_path = Path(bundled_list_path)
        self._state = self._load_state()

    # --- Scalar state (state.json) ---------------------------------

    def _load_state(self) -> dict:
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            return raw if isinstance(raw, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_state(self) -> None:
        write_atomically(
            self.state_file,
            json.dumps(self._state, indent=1, sort_keys=True).encode("utf-8"),
        )

    def _get(self, key, default=None):
        return self._state.get(key, default)

    def _set(self, key, value) -> None:
        self._state[key] = value
        self._save_state()

    # --- Sources -----------------------------------------------------

    def sources(self) -> List[ListSource]:
        raw = self._get("sources")
        if not isinstance(raw, list):
            return list(DEFAULT_SOURCES)
        parsed = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            source = ListSource(str(item.get("name", "")), str(item.get("url", "")).strip())
            if is_acceptable_url(source.url):
                parsed.append(source)
        return parsed if parsed else list(DEFAULT_SOURCES)

    def save_sources(self, sources: List[ListSource]) -> None:
        self._set(
            "sources",
            [{"name": s.name, "url": s.url} for s in sources],
        )
        self._prune_orphan_files(sources)

    # --- Downloaded list files ---------------------------------------

    def file_for(self, source: ListSource) -> Path:
        return self.lists_dir / _file_name_for(source.url)

    def saved_file(self, source: ListSource) -> Optional[Path]:
        f = self.file_for(source)
        return f if f.is_file() else None

    def write_downloaded(self, source: ListSource, data: bytes) -> None:
        """Replace ``source``'s downloaded list, via temp + rename, so
        a crash mid-write can never leave a torn list behind."""
        write_atomically(self.file_for(source), data)

    def last_updated_ms(self) -> int:
        return int(self._get("last_updated_ms", 0) or 0)

    def record_update(self, total_domains: int, when_ms: int) -> None:
        self._state["downloaded_count"] = total_domains
        self._state["last_updated_ms"] = when_ms
        self._save_state()

    # --- Loading -------------------------------------------------------

    def load_bundled_blocklist(self) -> Blocklist:
        lines = self.bundled_list_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return Blocklist.from_lines(lines)

    def load_downloaded_blocklist(self) -> Optional[Blocklist]:
        """The union of every downloaded list on disk that individually
        passes the sanity gate — or None when there is no valid
        downloaded list, in which case the bundled list rules."""
        union: Optional[set] = None
        for source in self.sources():
            f = self.saved_file(source)
            if f is None:
                continue
            parsed = parse_and_validate(
                f.read_text(encoding="utf-8", errors="replace").splitlines()
            )
            if parsed is None:
                continue
            if union is None:
                union = set()
            union.update(parsed.domains)
        if union is None:
            return None
        combined = Blocklist(union)
        return combined if _validation.is_acceptable(combined) else None

    def load_effective_lists(self) -> FilterLists:
        """The lists the filter should run with right now: the active
        blocklist (downloaded, or bundled) with the user's own custom
        block entries unioned in; the allowlist still wins over both."""
        base = self.load_downloaded_blocklist() or self.load_bundled_blocklist()
        custom = self._custom_block_domain_set()
        blocklist = Blocklist(base.domains | custom) if custom else base
        return FilterLists(blocklist, self.load_allowlist())

    def status(self) -> StoreStatus:
        downloaded = self.load_downloaded_blocklist()
        if downloaded is not None:
            return StoreStatus(downloaded.size, True, self.last_updated_ms())
        return StoreStatus(self.load_bundled_blocklist().size, False, self.last_updated_ms())

    # --- Allowlist ------------------------------------------------------

    def load_allowlist(self) -> Allowlist:
        if not self.allowlist_file.is_file():
            return Allowlist([])
        return Allowlist.from_lines(
            self.allowlist_file.read_text(encoding="utf-8", errors="replace").splitlines()
        )

    def allowlist_entries(self) -> List[str]:
        """The user's allowlist entries, normalized and sorted."""
        if not self.allowlist_file.is_file():
            return []
        return sorted(
            parse_entries(
                self.allowlist_file.read_text(encoding="utf-8", errors="replace").splitlines()
            )
        )

    def save_allowlist(self, entries: Collection[str], *, sync_profile: bool = True) -> None:
        # Entry validation, not mere normalization: an entry the
        # loader would drop (single label, reserved name) must not be
        # stored as if it were in force.
        normalized = sorted({n for n in (normalize_entry(e) for e in entries) if n})
        text = "".join(n + "\n" for n in normalized)
        write_atomically(self.allowlist_file, text.encode("utf-8"))
        if sync_profile:
            self._sync_active_profile()

    # --- Custom block entries -------------------------------------------

    def _custom_block_domain_set(self) -> set:
        if not self.custom_block_file.is_file():
            return set()
        return parse_entries(
            self.custom_block_file.read_text(encoding="utf-8", errors="replace").splitlines()
        )

    def custom_block_entries(self) -> List[str]:
        """The user's custom block entries, normalized and sorted.
        Entries enter ONLY through the parser's front door
        (parse_entries / normalize_entry), so what is stored is
        exactly what the matcher honors."""
        return sorted(self._custom_block_domain_set())

    def save_custom_block_entries(
        self, entries: Collection[str], *, sync_profile: bool = True
    ) -> None:
        normalized = sorted({n for n in (normalize_entry(e) for e in entries) if n})
        text = "".join(n + "\n" for n in normalized)
        write_atomically(self.custom_block_file, text.encode("utf-8"))
        if sync_profile:
            self._sync_active_profile()

    # --- Profiles (Windows Phase 3) -----------------------------------
    #
    # A port of the Android store's profile behavior
    # (lists/ListStore.kt, Phase 4 there) — including the two
    # disciplines its audit pinned: live edits write through to the
    # active profile, and a switch's own writes never do (see
    # switch_profile).

    def load_profile_set(self) -> ProfileSet:
        """The stored profiles, or an empty set when none were ever
        saved. A malformed profiles file degrades to the profiles
        that parse — never to a wiped live ruleset, because profiles
        and live state are different files, and the live state
        changes only through switch_profile."""
        if not self.profiles_file.is_file():
            return ProfileSet()
        return ProfileSet.parse(
            self.profiles_file.read_text(encoding="utf-8", errors="replace").splitlines()
        )

    def _save_profile_set(self, profile_set: ProfileSet) -> None:
        text = "".join(line + "\n" for line in profile_set.serialize_lines())
        write_atomically(self.profiles_file, text.encode("utf-8"))

    def snapshot_live_state(self) -> RuleState:
        """The live rule state, read back from the live stores —
        what a profile snapshot is taken of."""
        return RuleState(
            allowlist_entries=self.allowlist_entries(),
            custom_block_entries=self.custom_block_entries(),
        )

    def create_profile(self, name: str) -> Optional[ProfileSet]:
        """Save the live rule state as a new profile called ``name``
        and make it the active profile. Returns the updated set, or
        None when the name is unusable or already taken."""
        clean = name.strip()
        if not is_valid_profile_name(clean):
            return None
        profile_set = self.load_profile_set()
        if profile_set.profile(clean) is not None:
            return None
        updated = profile_set.with_profile(
            Profile(clean, self.snapshot_live_state())
        ).with_active(clean)
        self._save_profile_set(updated)
        return updated

    def switch_profile(self, name: str) -> bool:
        """Make the profile called ``name`` the live rule state.
        Its snapshot is only *read*, never modified, by a switch —
        and the snapshot itself is never where the state lands
        first: the live stores are written (without the
        write-through sync), then the active marker is set from a
        fresh read of the profiles file. That order is the Android
        Phase 4 audit's fix: if a switch's live writes ran the
        edit sync, each would write the *incoming* state into the
        *outgoing* profile's snapshot on disk, and a crash anywhere
        mid-switch would leave the outgoing profile silently
        replaced by the incoming one. Returns False when no such
        profile exists (nothing changes then).

        Applying the switch to a *running* filter is the caller's
        step: the controller's reload_lists(), the ordinary reload
        path — the switch is not in force until that runs (a switch
        that changed files but not the running filter's lists
        would be the half-applied state FILTER-SPEC forbids)."""
        profile_set = self.load_profile_set()
        profile = profile_set.profile(name)
        if profile is None:
            return False
        self._write_live_state(profile.state)
        self._save_profile_set(self.load_profile_set().with_active(profile.name))
        return True

    def delete_profile(self, name: str) -> bool:
        """Remove the profile called ``name``. The live rule state
        is untouched; if the removed profile was active, the active
        marker clears with it — the rules simply stop being under
        a profile. Returns False when no such profile exists."""
        profile_set = self.load_profile_set()
        if profile_set.profile(name) is None:
            return False
        self._save_profile_set(profile_set.without_profile(name))
        return True

    def _write_live_state(self, state: RuleState) -> None:
        """Write a profile snapshot into the live stores, without
        the write-through sync — see switch_profile for why a
        switch must never sync."""
        self.save_allowlist(state.allowlist_entries, sync_profile=False)
        self.save_custom_block_entries(state.custom_block_entries, sync_profile=False)

    def _sync_active_profile(self) -> None:
        """Write the live rule state through to the active profile,
        if there is one — the profile is the configuration, so an
        edit made under it belongs to it. Called after every live
        rule save; writes only the profiles file, so it cannot
        recurse."""
        profile_set = self.load_profile_set()
        active = profile_set.active_profile
        if active is None:
            return
        self._save_profile_set(
            profile_set.with_profile(Profile(active.name, self.snapshot_live_state()))
        )

    # --- Hosting settings (Windows Phase 2) ----------------------------

    def protection_intent(self) -> bool:
        """The recorded on/off intent: True when protection was on
        the last time Sphinx's state changed hands cleanly. The
        controller records it at every successful start, stop, and
        leftover restore/dismissal — the same intent discipline the
        Android edition's boot auto-start honors — and the tray host
        reads it at sign-in to decide whether protection should
        resume. Default False: a machine Sphinx has never run on has
        no intent to resume anything."""
        return bool(self._get("protection_intent", False))

    def set_protection_intent(self, on: bool) -> None:
        self._set("protection_intent", bool(on))

    def autostart_enabled(self) -> bool:
        """The user's recorded opt-in to starting Sphinx at sign-in.
        This is the *record* of the choice; the machine's truth is
        the per-user Run registry value, which the app shell reads
        and reconciles against this on every start (the shell's
        checkbox shows the registry's actual state)."""
        return bool(self._get("autostart_enabled", False))

    def set_autostart_enabled(self, enabled: bool) -> None:
        self._set("autostart_enabled", bool(enabled))

    # --- Query log setting ------------------------------------------------

    def query_log_enabled(self) -> bool:
        """The query log is ON by default: it is how a user can see
        what Sphinx questioned, it never leaves the device, and it
        can be turned off here at any time. (Stated in the README.)"""
        return bool(self._get("query_log_enabled", True))

    def set_query_log_enabled(self, enabled: bool) -> None:
        self._set("query_log_enabled", bool(enabled))

    # --- Internals ----------------------------------------------------------

    def _prune_orphan_files(self, current: List[ListSource]) -> None:
        keep = {_file_name_for(s.url) for s in current}
        for f in self.lists_dir.iterdir():
            if f.is_file() and f.name not in keep:
                try:
                    f.unlink()
                except OSError:
                    pass
