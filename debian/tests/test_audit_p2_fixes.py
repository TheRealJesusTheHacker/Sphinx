"""Regression pins for the Debian Phase 2 audit's two fixes.

1. Store and guard files carry an explicit mode (0644), never the
   writer's umask: the writer is the root CLI, the reader that
   matters is the unprivileged daemon (and unprivileged status).
   Under a restrictive root umask (027), umask-made files landed
   0640 root:root and the daemon could not read its own rules.
2. The daemon's watched-file signature includes inode + ctime, so
   a same-size edit with its mtime set back is still a change.
   (mtime + size alone collided; ctime cannot be set back, and
   the store's temp-and-rename writes always change the inode.)
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from sphinx_deb.core.store import Store
from sphinx_deb.core.updater import ListUpdater
from sphinx_deb.daemon import LiveLists
from sphinx_deb.resolver.guard import DnsGuard

from conftest import CANONICAL_LIST, FakeProofer, FakeView


@pytest.fixture
def restrictive_umask():
    old = os.umask(0o027)
    try:
        yield
    finally:
        os.umask(old)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_store_files_are_readable_regardless_of_umask(tmp_path, restrictive_umask):
    store = Store(tmp_path, CANONICAL_LIST)
    store.save_allowlist(["a.example.com"])
    store.save_custom_block_entries(["b.example.com"])
    store.create_profile("Home")
    ListUpdater(
        store,
        download_fn=lambda url: (
            "\n".join(f"d{i}.example.com" for i in range(1200)) + "\n"
        ).encode(),
    ).update_all(1)
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert written, "the store should have written files"
    for path in written:
        assert _mode(path) == 0o644, f"{path.name} landed as {oct(_mode(path))}"
    lists_dir = tmp_path / "lists"
    assert _mode(lists_dir) == 0o755


def test_guard_files_are_readable_regardless_of_umask(tmp_path, restrictive_umask):
    guard = DnsGuard(FakeView(), tmp_path)
    result = guard.engage(FakeProofer())
    assert result.ok
    assert _mode(tmp_path / "dns-backup.json") == 0o644
    assert _mode(tmp_path / "state.json") == 0o644


def test_watcher_detects_same_size_edit_with_mtime_set_back(tmp_path):
    store = Store(tmp_path, CANONICAL_LIST)
    live = LiveLists(store)
    store.save_allowlist(["aaaa.example.com"])
    assert live.current().lists.allowlist.covers("aaaa.example.com")
    target = tmp_path / "allowlist.txt"
    before = target.stat()
    store.save_allowlist(["bbbb.example.com"])  # same size, via rename
    # Forge the one thing a tool can forge: the mtime, back to the
    # previous value. Size is identical too. The edit must still
    # be seen — inode and ctime cannot be forged back.
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    current = live.current()
    assert current.lists.allowlist.covers("bbbb.example.com")
    assert not current.lists.allowlist.covers("aaaa.example.com")
