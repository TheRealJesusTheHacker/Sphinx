"""Where Sphinx keeps its lists and the user's own rules on the
machine, and how the working set is chosen — a port of the Android
edition's ``lists/ListStore.kt`` (the list parts, and its profiles:
the profile store behavior mirrors the Android store's, audit fixes
included), adapted to the Debian edition's separations.

All storage is under one data directory chosen by the shell — on
Debian, /var/lib/sphinx. Nothing here leaves the device. The store
holds *rules and lists*, never query history: the query log is the
engine's, in memory only, and no path from it leads here.

Which blocklist is active (FILTER-SPEC, "List updates"):
  - If downloaded lists are on disk and together pass the sanity
    gate, they are the blocklist.
  - Otherwise the list bundled with the package is the blocklist.
    The bundled list is never modified by updates, so there is
    always a known-good list to fall back to — an update can never
    leave the filter listless.

Who writes, who reads (the Phase 1 audit's model): the ``sphinx``
command, as root, is the only writer; the daemon — the
unprivileged ``sphinx`` user — only reads. Construction therefore
creates nothing on disk: directories appear on the write paths
(write_atomically makes parents), so the daemon can hold a Store
over a read-only view of the state directory without failing.
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
from .validation import (
    DEFAULT_SOURCES,
    ListSource,
    is_acceptable,
    is_acceptable_url,
    parse_and_validate,
)

#: The store's scalar state (sources, last update). NOT "state.json":
#: that name belongs to the engage guard's intent record in the same
#: directory — two stores, two files, neither overwrites the other.
STORE_STATE_NAME = "store.json"


def _fsync_file(path: Path) -> None:
    """Flush one file's contents to stable storage."""
    with open(path, "r+b") as f:
        f.flush()
        os.fsync(f.fileno())


def _fsync_dir(path: Path) -> None:
    """Flush a directory entry to stable storage."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_atomically(target: Path, data: bytes) -> None:
    """Write ``data`` to ``target`` so the file is never left torn:
    write a temp file, fsync it, then rename it over the target
    (and fsync the containing directory after) — without the
    fsyncs the rename can reach the disk before the data does, and
    the "atomic" write is not power-loss-durable (Sweep #3, W-4,
    fixed on Windows; the same fix landed here in Sweep #4 when
    the Debian port was found still carrying the pre-W-4 helper).
    If the rename ever refuses, stage the copy under a second name
    and rename *that* — copying straight over the target is not an
    option, because a crash mid-copy would leave half a file behind
    (and a half-written list can still pass the sanity gate as a
    silently weaker list). If even the staged rename fails, the
    old file stays, the temps are cleaned up, and the failure is
    RAISED: a save that never happened must never be reported as
    success. (The fleet's store discipline — the resolver's
    systemview carries the same helper for its files.)
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.name + ".tmp")
    with open(temp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    # The mode is set explicitly, never left to the writer's umask:
    # the only writer is the command running as root, and the only
    # reader that matters is the daemon running as the unprivileged
    # sphinx user. A restrictive root umask (027 is a common
    # hardening default) would otherwise leave every store file
    # 0640 root:root — the CLI would happily write rules the daemon
    # cannot read, and the filter would be blind to them (Debian
    # Phase 2 audit). Store files hold rules and lists, never
    # secrets or query data, so 0644 is the right mode, and the
    # state directory itself is 0755 for the same reason (see
    # packaging/postinst).
    try:
        os.chmod(temp, 0o644)
        os.chmod(target.parent, 0o755)
    except OSError:
        pass
    try:
        os.replace(temp, target)
        _fsync_dir(target.parent)
        return
    except OSError:
        pass
    swap = target.with_name(target.name + ".swap")
    try:
        shutil.copyfile(temp, swap)
        try:
            os.chmod(swap, 0o644)  # copyfile does not carry the mode
        except OSError:
            pass
        _fsync_file(swap)
        os.replace(swap, target)
    except OSError as e:
        try:
            swap.unlink(missing_ok=True)
        except OSError:
            pass
        raise OSError(
            f"Sphinx could not replace {target.name} — the previous "
            "file was left unchanged."
        ) from e
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
    _fsync_dir(target.parent)


def _file_name_for(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return digest[:16] + ".txt"


@dataclass(frozen=True)
class StoreStatus:
    active_domains: int
    using_downloaded: bool
    last_updated_ms: int


@dataclass(frozen=True)
class LiveState:
    """One whole working set, loaded in a single pass: the lists
    the filter runs with, plus the facts status reports about them.
    The daemon reloads this as one unit when the store's files
    change, so a running filter never sees a half-swapped set."""

    lists: FilterLists
    base_domains: int
    using_downloaded: bool
    last_updated_ms: int


class Store:
    """List + rule storage rooted at one data directory.

    Layout:
      <dir>/lists/<sha256(url)[:16]>.txt   downloaded list copies
      <dir>/allowlist.txt                  the user's allowlist
      <dir>/custom-block.txt               the user's own block entries
      <dir>/profiles.txt                   named profiles of the two
                                           rule files above
      <dir>/store.json                     sources, last update

    The guard's files (dns-backup.json, state.json) live in the
    same directory and are not the store's business.
    """

    def __init__(self, data_dir: Path, bundled_list_path: Path):
        self.data_dir = Path(data_dir)
        self.lists_dir = self.data_dir / "lists"
        self.allowlist_file = self.data_dir / "allowlist.txt"
        self.custom_block_file = self.data_dir / "custom-block.txt"
        self.profiles_file = self.data_dir / "profiles.txt"
        self.state_file = self.data_dir / STORE_STATE_NAME
        self.bundled_list_path = Path(bundled_list_path)
        self._state = self._load_state()

    # --- Scalar state (store.json) ---------------------------------

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
            source = ListSource(
                str(item.get("name", "")), str(item.get("url", "")).strip()
            )
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
        lines = self.bundled_list_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
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
        return combined if is_acceptable(combined) else None

    def load_base_blocklist(self) -> tuple:
        """The blocklist before the user's own entries are unioned
        in, and whether it is the downloaded set (True) or the
        bundled floor (False)."""
        downloaded = self.load_downloaded_blocklist()
        if downloaded is not None:
            return downloaded, True
        return self.load_bundled_blocklist(), False

    def load_effective_lists(self) -> FilterLists:
        """The lists the filter should run with right now."""
        return self.load_live().lists

    def load_live(self) -> LiveState:
        """The whole working set in one pass: the active blocklist
        (downloaded, or bundled) with the user's own custom block
        entries unioned in; the allowlist still wins over both."""
        base, using_downloaded = self.load_base_blocklist()
        custom = self._custom_block_domain_set()
        blocklist = Blocklist(base.domains | custom) if custom else base
        return LiveState(
            lists=FilterLists(blocklist, self.load_allowlist()),
            base_domains=base.size,
            using_downloaded=using_downloaded,
            last_updated_ms=self.last_updated_ms(),
        )

    def status(self) -> StoreStatus:
        base, using_downloaded = self.load_base_blocklist()
        return StoreStatus(base.size, using_downloaded, self.last_updated_ms())

    def watched_files(self) -> List[Path]:
        """Every file whose change can change the working set — the
        daemon watches these (by mtime + size) to reload without a
        restart. Profiles are absent on purpose: a switch lands in
        the live rule files, and those are what is watched."""
        files = [self.bundled_list_path, self.allowlist_file, self.custom_block_file]
        files.extend(self.file_for(source) for source in self.sources())
        return files

    # --- Allowlist ------------------------------------------------------

    def load_allowlist(self) -> Allowlist:
        if not self.allowlist_file.is_file():
            return Allowlist([])
        return Allowlist.from_lines(
            self.allowlist_file.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        )

    def allowlist_entries(self) -> List[str]:
        """The user's allowlist entries, normalized and sorted."""
        if not self.allowlist_file.is_file():
            return []
        return sorted(
            parse_entries(
                self.allowlist_file.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            )
        )

    def save_allowlist(
        self, entries: Collection[str], *, sync_profile: bool = True
    ) -> None:
        # Entry validation, not mere normalization: an entry the
        # loader would drop (single label, reserved name) must not be
        # stored as if it were in force. (The command line refuses
        # such entries with an explanation before it ever gets here;
        # this is the same rail at the store's own door.)
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
            self.custom_block_file.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
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

    # --- Profiles ------------------------------------------------------
    #
    # The Android store's profile behavior (lists/ListStore.kt,
    # Phase 4 there) — including the two disciplines its audit
    # pinned: live edits write through to the active profile, and a
    # switch's own writes never do (see switch_profile).

    def load_profile_set(self) -> ProfileSet:
        """The stored profiles, or an empty set when none were ever
        saved. A malformed profiles file degrades to the profiles
        that parse — never to a wiped live ruleset, because profiles
        and live state are different files, and the live state
        changes only through switch_profile."""
        if not self.profiles_file.is_file():
            return ProfileSet()
        return ProfileSet.parse(
            self.profiles_file.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
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

        Applying the switch to a *running* filter is the daemon's
        side of the bargain: it watches the live rule files and
        reloads the whole state when they change — the switch is
        in force from the next question the filter answers."""
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

    # --- Internals ----------------------------------------------------------

    def _prune_orphan_files(self, current: List[ListSource]) -> None:
        keep = {_file_name_for(s.url) for s in current}
        if not self.lists_dir.is_dir():
            return
        for f in self.lists_dir.iterdir():
            if f.is_file() and f.name not in keep:
                try:
                    f.unlink()
                except OSError:
                    pass
