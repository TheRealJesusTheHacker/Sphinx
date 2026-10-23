"""Where tunnel profiles live, and the tunnel session record.

Two stores, both under the state directory, both following the
fleet's store discipline — and stricter than the rule store's,
because these files hold private keys:

- **Profiles** live in their own directory,
  ``<state>/tunnel-profiles/``, mode ``0700`` (root-only), one
  file per profile, mode ``0600``. A profile file *is* the
  config text the user imported or Sphinx rendered — the same
  lossless interchange format as import/export, so what is on
  disk is exactly what export prints.
- **The session record** (``<state>/tunnel-state.json``) is the
  tunnel guard's bookkeeping: mode, profile, intent, the pinned
  endpoint, and the pre-tunnel facts restore needs. It holds no
  traffic data and no key material (TUNNEL-SPEC, "Logging
  honesty").

Degrade, never destroy: a profile file that no longer parses is
reported and left exactly where it is — never overwritten, never
deleted by a read. A bad import is refused before anything is
written, and every write is atomic (temp file, fsync, rename),
so no profile is ever half-written.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .tunnel import TunnelProfile, TunnelRefusal, parse_config

PROFILES_DIR_NAME = "tunnel-profiles"
SESSION_FILE_NAME = "tunnel-state.json"

_SLUG_RUNS = re.compile(r"[^a-z0-9]+")


def slug_for(name: str) -> str:
    """A filesystem-safe slug for a profile name. Names are labels
    only; two names that slug the same are told apart by the store
    refusing the second rather than overwriting the first."""
    slug = _SLUG_RUNS.sub("-", name.strip().lower()).strip("-")
    return slug or "profile"


def _fsync_dir(path: Path) -> None:
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


def write_secret_atomically(target: Path, data: bytes) -> None:
    """Atomic replace with the tunnel store's modes: the directory
    is root-only (0700) and the file is 0600, set explicitly on the
    temp file before the rename — never left to the umask, because
    these bytes hold a private key. Same durability shape as the
    fleet's other atomic writers (fsync the file, rename, fsync
    the directory; a failed staged rename leaves the old file and
    raises)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target.parent, 0o700)
    except OSError:
        pass
    temp = target.with_name(target.name + ".tmp")
    with open(temp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(temp, 0o600)
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
            os.chmod(swap, 0o600)
        except OSError:
            pass
        with open(swap, "r+b") as f:
            f.flush()
            os.fsync(f.fileno())
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


@dataclass
class StoredProfile:
    profile: TunnelProfile
    path: Path


@dataclass
class ProfileProblem:
    """A profile file that exists but cannot be used — reported,
    never silently dropped, and the file is left untouched."""

    path: Path
    reason: str


class TunnelStore:
    """Profile storage rooted at the state directory. Construction
    creates nothing; directories appear on the write paths only,
    so read-only holders (status, the daemon) never fail on a
    machine that has no profiles yet."""

    def __init__(self, state_dir: Path):
        self.state_dir = Path(state_dir)
        self.profiles_dir = self.state_dir / PROFILES_DIR_NAME
        self.session_file = self.state_dir / SESSION_FILE_NAME

    # --- profiles -------------------------------------------------

    def _path_for(self, name: str) -> Path:
        return self.profiles_dir / (slug_for(name) + ".conf")

    def list_profiles(self) -> List[StoredProfile]:
        out: List[StoredProfile] = []
        for stored in self._scan():
            if isinstance(stored, StoredProfile):
                out.append(stored)
        return sorted(out, key=lambda s: (s.profile.name or "").lower())

    def problems(self) -> List[ProfileProblem]:
        return [s for s in self._scan() if isinstance(s, ProfileProblem)]

    def _scan(self) -> list:
        if not self.profiles_dir.is_dir():
            return []
        found: list = []
        for path in sorted(self.profiles_dir.glob("*.conf")):
            try:
                text = path.read_text(encoding="utf-8", errors="strict")
                profile = parse_config(text)
            except (OSError, UnicodeDecodeError, TunnelRefusal) as exc:
                reason = getattr(exc, "reason", None) or str(exc)
                found.append(ProfileProblem(path=path, reason=str(reason)))
                continue
            if profile.name is None:
                # A profile imported without a Sphinx name comment
                # is named by its file (TUNNEL-SPEC: name from the
                # file name when no comment is present).
                profile.set_name(path.stem)
            found.append(StoredProfile(profile=profile, path=path))
        return found

    def get(self, name: str) -> Optional[StoredProfile]:
        for stored in self.list_profiles():
            if stored.profile.name == name:
                return stored
        # An OpenVPN record's text cannot carry a Sphinx name
        # comment (its export must stay byte-lossless), so its
        # stored name is its file's slug — a name typed with
        # different case still finds it.
        for stored in self.list_profiles():
            if (stored.profile.name or "").lower() == name.lower():
                return stored
        return None

    def save(self, profile: TunnelProfile) -> StoredProfile:
        """Store a profile under its name. Refuses (ValueError) a
        nameless profile or one whose name is already taken — an
        import never overwrites an existing profile silently."""
        if not profile.name:
            raise ValueError("the profile has no name yet")
        target = self._path_for(profile.name)
        existing = self.get(profile.name)
        if existing is not None and existing.path != target:
            raise ValueError(f"a profile called '{profile.name}' already exists")
        if target.is_file() and existing is None:
            raise ValueError(f"a profile called '{profile.name}' already exists")
        write_secret_atomically(target, profile.export_text().encode("utf-8"))
        return StoredProfile(profile=profile, path=target)

    def remove(self, name: str) -> bool:
        stored = self.get(name)
        if stored is None:
            return False
        try:
            stored.path.unlink()
        except OSError:
            return False
        return True

    # --- the session record ----------------------------------------

    def load_session(self) -> Optional[dict]:
        try:
            raw = json.loads(self.session_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return raw if isinstance(raw, dict) else None

    def save_session(self, record: dict) -> None:
        write_secret_atomically(
            self.session_file,
            json.dumps(record, indent=1, sort_keys=True).encode("utf-8"),
        )

    def clear_session(self) -> None:
        try:
            self.session_file.unlink(missing_ok=True)
        except OSError:
            pass
