"""The store (Phase 2): which list is in force, the rule files,
and the scalar state — including the separation from the guard's
files in the same directory (the guard's intent owns state.json;
the store's own scalars live in store.json, and neither store nor
guard may overwrite the other's)."""
import json

from sphinx_deb.core.store import Store
from sphinx_deb.core.validation import DEFAULT_SOURCES


def _lines(count, start=0, fmt="0.0.0.0 ads{}.example.com"):
    return [fmt.format(i) for i in range(start, start + count)]


def _bundled(tmp_path, count=1500):
    bundled = tmp_path / "bundled.txt"
    bundled.write_text("\n".join(_lines(count)) + "\n")
    return bundled


def _store(tmp_path, bundled_count=1500):
    return Store(tmp_path / "state", _bundled(tmp_path, bundled_count))


def test_bundled_is_the_floor_until_a_download_lands(tmp_path):
    store = _store(tmp_path)
    status = store.status()
    assert status.using_downloaded is False
    assert status.active_domains == 1500
    assert status.last_updated_ms == 0
    lists = store.load_effective_lists()
    assert lists.is_blocked("ads0.example.com")
    assert lists.is_blocked("deep.ads42.example.com")  # subdomain rule
    assert not lists.is_blocked("example.com")


def test_default_sources_are_the_two_spec_sources(tmp_path):
    store = _store(tmp_path)
    assert store.sources() == list(DEFAULT_SOURCES)
    urls = [s.url for s in store.sources()]
    assert all(u.startswith("https://") for u in urls)
    assert any("StevenBlack" in u for u in urls)
    assert any("hagezi" in u for u in urls)


def test_downloaded_lists_take_over_and_union_uniquely(tmp_path):
    store = _store(tmp_path)
    first, second = store.sources()
    # Overlapping sets: the union counts a shared domain once.
    store.write_downloaded(first, ("\n".join(_lines(1200)) + "\n").encode())
    store.write_downloaded(
        second, ("\n".join(_lines(1200, start=600, fmt="0.0.0.0 ads{}.example.com")) + "\n").encode()
    )
    store.record_update(1800, 123456789)
    status = store.status()
    assert status.using_downloaded is True
    assert status.active_domains == 1800
    assert status.last_updated_ms == 123456789


def test_a_downloaded_file_that_fails_the_gate_is_ignored(tmp_path):
    store = _store(tmp_path)
    first, second = store.sources()
    # One valid file, one torn one (parses below the gate): the torn
    # one is ignored, and the remaining valid set still rules.
    store.write_downloaded(first, ("\n".join(_lines(1200)) + "\n").encode())
    store.write_downloaded(second, b"0.0.0.0 only.example.com\n")
    store.record_update(1200, 5)
    assert store.status().using_downloaded is True
    # Both torn: the bundled floor holds — never listless.
    store.write_downloaded(first, b"garbage\n")
    assert store.status().using_downloaded is False
    assert store.load_effective_lists().is_blocked("ads0.example.com")


def test_scalar_state_is_store_json_and_the_guards_files_are_untouched(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    guard_intent = state / "state.json"
    guard_intent.write_text('{"version": 1, "engaged": true}')
    store = Store(state, _bundled(tmp_path))
    store.record_update(2000, 42)
    # The store wrote its own file; the guard's intent is byte-intact.
    assert (state / "store.json").is_file()
    assert guard_intent.read_text() == '{"version": 1, "engaged": true}'
    raw = json.loads((state / "store.json").read_text())
    assert raw["last_updated_ms"] == 42 and raw["downloaded_count"] == 2000
    # And the store never *reads* the guard's file as its own state.
    assert store.last_updated_ms() == 42


def test_construction_creates_nothing_on_disk(tmp_path):
    # The daemon constructs a Store as an unprivileged user over a
    # read-only view of the state directory: construction must not
    # write (no eager mkdir), or the daemon could not start under
    # its own sandboxing.
    store = Store(tmp_path / "absent", _bundled(tmp_path))
    assert not (tmp_path / "absent").exists()
    assert store.allowlist_entries() == []
    assert store.custom_block_entries() == []


def test_rule_files_round_trip_through_the_rails(tmp_path):
    store = _store(tmp_path)
    store.save_allowlist(["Example.COM.", "*.ok.example.org", "com", "localhost", "1.2.3.4"])
    # Only entries the loader would honor are stored: normalized,
    # railed (no single labels, no reserved names, no IP literals).
    assert store.allowlist_entries() == ["example.com", "ok.example.org"]
    store.save_custom_block_entries(["tracker.example.net", "junk entry", "UP.example.io"])
    assert store.custom_block_entries() == ["tracker.example.net", "up.example.io"]


def test_custom_entries_union_in_and_allowlist_still_wins(tmp_path):
    store = _store(tmp_path)
    store.save_custom_block_entries(["mine.example.net"])
    lists = store.load_effective_lists()
    assert lists.is_blocked("mine.example.net")
    store.save_allowlist(["mine.example.net"])
    lists = store.load_effective_lists()
    assert not lists.is_blocked("mine.example.net")


def test_watched_files_cover_everything_that_changes_the_set(tmp_path):
    store = _store(tmp_path)
    watched = {str(p) for p in store.watched_files()}
    assert str(store.bundled_list_path) in watched
    assert str(store.allowlist_file) in watched
    assert str(store.custom_block_file) in watched
    for source in store.sources():
        assert str(store.file_for(source)) in watched


def test_store_atomic_write_is_fsynced_and_raises_on_final_failure(tmp_path, monkeypatch):
    # Sweep #4 (W-4 parity): the Debian store's write_atomically
    # carried the pre-W-4 helper — no fsync, and a failed staged
    # rename was swallowed, so a save that never landed could be
    # reported as success by every caller above it.
    import os

    import pytest

    from sphinx_deb.core.store import write_atomically

    fsynced = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: fsynced.append(fd) or real_fsync(fd))
    target = tmp_path / "f.txt"
    write_atomically(target, b"durable")
    assert target.read_bytes() == b"durable"
    assert fsynced  # temp file (and directory) flushed before/after rename
    monkeypatch.undo()

    target.write_bytes(b"old")

    def always_refuse(src, dst):
        raise OSError("injected replace refusal")

    monkeypatch.setattr(os, "replace", always_refuse)
    with pytest.raises(OSError):
        write_atomically(target, b"never-lands")
    assert target.read_bytes() == b"old"  # the old file stays
    assert not (tmp_path / "f.txt.tmp").exists()
    assert not (tmp_path / "f.txt.swap").exists()
