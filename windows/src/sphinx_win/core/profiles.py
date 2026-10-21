"""Named profiles of the user's own rule state — FILTER-SPEC,
"Profiles". A port of the Android edition's pure core
(``core/Profiles.kt``), so every edition runs the same mechanism:

A profile captures exactly the user's own choices. On Windows
there are no per-app rules (they ride on Android's per-app VPN
routing), so a Windows profile is the allowlist plus the user's
custom block entries. What a profile never captures, on any
edition: the blocklists themselves and their sources — every
profile questions with the same lists, so switching profiles
cannot change which lists are in force, and a list update never
disturbs a profile.

The mechanism's rules (FILTER-SPEC, and the Android Phase 4
audit's hard lessons):

- Switching is a copy, applied by the ordinary reload path. The
  snapshot itself is only read by a switch, never modified.
- The active profile does not drift: while a profile is active,
  edits to the live rule state are written through to it by the
  store, so what a profile says is always what it does.
- Profiles degrade; they never destroy. Entries are normalized
  through the parser's rails and storage is atomic (the store's
  job). A malformed profile file degrades to the profiles that
  parse — worst case, none — and never to a wiped live ruleset:
  profiles and live state are different stores, and the live
  state changes only when the user explicitly switches.
- Deleting a profile deletes only the snapshot. The live rules
  stay as they are; if the deleted profile was active, the rules
  simply stop being under a profile.

Pure Python — no platform APIs — so the whole model is testable
anywhere.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from .blocklist import normalize_entry, parse_entries

MAX_PROFILE_NAME = 40


def is_valid_profile_name(name: Optional[str]) -> bool:
    """A profile name: short, printable, no format-breaking
    characters (a tab or newline would corrupt the line format).
    Anything else — spaces, punctuation, emoji — is the user's
    business."""
    if name is None:
        return False
    trimmed = name.strip()
    if not trimmed or len(trimmed) > MAX_PROFILE_NAME:
        return False
    return all(unicodedata.category(c) != "Cc" for c in trimmed)


class RuleState:
    """One snapshot of the user's own rule state: the allowlist
    and the custom block entries, normalized through the parser's
    front door (:func:`normalize_entry`) at construction, so a
    stored state always does what it appears to do."""

    def __init__(
        self,
        allowlist_entries: Iterable[str] = (),
        custom_block_entries: Iterable[str] = (),
    ):
        self.allowlist_entries = frozenset(
            n for n in (normalize_entry(e) for e in allowlist_entries) if n
        )
        self.custom_block_entries = frozenset(
            n for n in (normalize_entry(e) for e in custom_block_entries) if n
        )

    @property
    def is_empty(self) -> bool:
        return not self.allowlist_entries and not self.custom_block_entries

    def serialize_lines(self) -> List[str]:
        """The storage lines for this state — sorted, so the file
        on disk is stable and diff-friendly."""
        return [f"allow\t{e}" for e in sorted(self.allowlist_entries)] + [
            f"custom\t{e}" for e in sorted(self.custom_block_entries)
        ]

    @classmethod
    def parse(cls, lines: Iterable[str]) -> "RuleState":
        """Parse one state's lines (the shape serialize_lines
        writes). Defensive, like every parser in this core:
        unknown verbs and unusable entries are skipped, never
        half-applied. (The Android edition's state also carries
        per-app rule lines — ``block`` / ``exclude``; the Windows
        edition has no per-app rules, so those verbs are simply
        not part of its state and are ignored here.)"""
        allow_raw: List[str] = []
        custom_raw: List[str] = []
        for line in lines:
            tab = line.find("\t")
            if tab <= 0:
                continue
            verb = line[:tab].strip().lower()
            value = line[tab + 1 :]
            if verb == "allow":
                allow_raw.append(value)
            elif verb == "custom":
                custom_raw.append(value)
        return cls(
            allowlist_entries=parse_entries(allow_raw),
            custom_block_entries=parse_entries(custom_raw),
        )

    def __eq__(self, other):
        return (
            isinstance(other, RuleState)
            and self.allowlist_entries == other.allowlist_entries
            and self.custom_block_entries == other.custom_block_entries
        )

    def __hash__(self):
        return hash((self.allowlist_entries, self.custom_block_entries))

    def __repr__(self):
        return (
            f"RuleState(allowlist={sorted(self.allowlist_entries)}, "
            f"custom={sorted(self.custom_block_entries)})"
        )


@dataclass(frozen=True)
class Profile:
    name: str
    state: RuleState


class ProfileSet:
    """The user's named profiles plus which one is active.

    The profiles are snapshots held in one store; the *live* rule
    state (the store files the filter actually reads) is separate.
    Switching profiles copies a snapshot into the live state and
    applies it through the ordinary reload path. Edits to the live
    state while a profile is active are written through to that
    profile by the store, so the active profile always describes
    the rules in force — a profile is the configuration, not a
    museum copy that silently drifts from it.

    Storage shape (one directive per line, tab-separated)::

        active<TAB>Home
        profile<TAB>Home
        allow<TAB>example.com
        custom<TAB>ads.example.net
        profile<TAB>Quiet
        ...

    Parsing is defensive: a malformed file degrades to the
    profiles that do parse — and, worst case, to no profiles at
    all. It can never degrade to a wiped live ruleset, because
    profiles and live state are different stores and the live
    state is only ever overwritten by an explicit switch.
    """

    def __init__(
        self,
        profiles: Sequence[Profile] = (),
        active_name: Optional[str] = None,
    ):
        seen = set()
        kept: List[Profile] = []
        for profile in profiles:
            name = profile.name.strip()
            if not is_valid_profile_name(name):
                continue
            if name in seen:
                continue
            seen.add(name)
            kept.append(Profile(name, profile.state))
        self.profiles: tuple = tuple(kept)
        candidate = active_name.strip() if active_name else None
        self.active_name: Optional[str] = (
            candidate if candidate and any(p.name == candidate for p in kept) else None
        )

    @property
    def is_empty(self) -> bool:
        return not self.profiles

    def profile(self, name: Optional[str]) -> Optional[Profile]:
        """The profile called ``name``, or None."""
        if name is None:
            return None
        target = name.strip()
        for p in self.profiles:
            if p.name == target:
                return p
        return None

    @property
    def active_profile(self) -> Optional[Profile]:
        """The active profile, or None when the live rules are not
        under any profile."""
        return self.profile(self.active_name) if self.active_name else None

    def with_profile(self, profile: Profile) -> "ProfileSet":
        """A copy with ``profile`` added, or replacing the
        same-named profile in place (its position in the list is
        kept). An unusable name changes nothing. Does not touch
        which profile is active."""
        name = profile.name.strip()
        if not is_valid_profile_name(name):
            return self
        replacement = Profile(name, profile.state)
        next_profiles = list(self.profiles)
        for i, existing in enumerate(next_profiles):
            if existing.name == name:
                next_profiles[i] = replacement
                break
        else:
            next_profiles.append(replacement)
        return ProfileSet(next_profiles, self.active_name)

    def without_profile(self, name: str) -> "ProfileSet":
        """A copy without the profile called ``name``. Removing
        the active profile clears the active marker — the live
        rules themselves are untouched; they simply stop being
        "under" a profile."""
        target = name.strip()
        if all(p.name != target for p in self.profiles):
            return self
        return ProfileSet(
            [p for p in self.profiles if p.name != target],
            None if self.active_name == target else self.active_name,
        )

    def with_active(self, name: Optional[str]) -> "ProfileSet":
        """A copy with a different active profile. ``name`` must
        name an existing profile, or be None to clear the marker;
        anything else changes nothing."""
        if name is None:
            return ProfileSet(self.profiles, None)
        target = name.strip()
        if all(p.name != target for p in self.profiles):
            return self
        return ProfileSet(self.profiles, target)

    def serialize_lines(self) -> List[str]:
        """The storage lines for this set — the active marker
        first, then each profile's section."""
        lines: List[str] = []
        if self.active_name is not None:
            lines.append(f"active\t{self.active_name}")
        for profile in self.profiles:
            lines.append(f"profile\t{profile.name}")
            lines.extend(profile.state.serialize_lines())
        return lines

    @classmethod
    def parse(cls, lines: Iterable[str]) -> "ProfileSet":
        """Parse a stored profile file. Sections open at
        ``profile<TAB>name``; state lines belong to the section
        above them; lines outside a section, sections with an
        unusable name, and later sections reusing a name are all
        ignored (first profile of a name wins). The last valid
        ``active<TAB>name`` line is the candidate marker — the
        constructor keeps it only if that profile exists."""
        active_candidate: Optional[str] = None
        found: List[Profile] = []
        seen = set()
        current_name: Optional[str] = None
        current_lines: List[str] = []

        def close_section() -> None:
            nonlocal current_name, current_lines
            if current_name is None:
                return
            found.append(Profile(current_name, RuleState.parse(current_lines)))
            current_name = None
            current_lines = []

        for line in lines:
            tab = line.find("\t")
            if tab <= 0:
                continue
            verb = line[:tab].strip().lower()
            value = line[tab + 1 :].strip()
            if verb == "active":
                if is_valid_profile_name(value):
                    active_candidate = value
            elif verb == "profile":
                close_section()
                if is_valid_profile_name(value) and value not in seen:
                    seen.add(value)
                    current_name = value
            elif verb in ("allow", "custom"):
                if current_name is not None:
                    current_lines.append(line)
            # Unknown directives are ignored, never fatal.
        close_section()
        return cls(found, active_candidate)

    def __eq__(self, other):
        return (
            isinstance(other, ProfileSet)
            and self.profiles == other.profiles
            and self.active_name == other.active_name
        )

    def __hash__(self):
        return hash((self.profiles, self.active_name))

    def __repr__(self):
        names = [p.name for p in self.profiles]
        return f"ProfileSet(profiles={names}, active={self.active_name})"
