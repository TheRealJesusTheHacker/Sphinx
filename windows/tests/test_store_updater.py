"""Store + updater discipline: atomic writes, the sanity gate, the
atomic swap, kept copies, and the audited 'a failed update changes
nothing' rule."""
import pytest

from sphinx_win.core.store import Store, write_atomically
from sphinx_win.core.updater import ListUpdater
from sphinx_win.core.validation import ListSource

SOURCE_A = ListSource("A", "https://a.example/hosts")
SOURCE_B = ListSource("B", "https://b.example/hosts")


def list_text(tag, count):
    return "\n".join(f"0.0.0.0 {tag}{i}.ads.example.com" for i in range(count))


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "data", bundled_list_path=tmp_path / "bundled.txt")
    (tmp_path / "bundled.txt").write_text(list_text("bundled", 1500))
    # write bundled AFTER Store creation is fine: it is read lazily.
    s.save_sources([SOURCE_A, SOURCE_B])
    return s


def downloads(mapping):
    def fn(url):
        value = mapping.get(url)
        return value.encode() if isinstance(value, str) else value

    return fn


class TestAtomicWrite:
    def test_replaces_content_and_leaves_no_temp(self, tmp_path):
        target = tmp_path / "f.txt"
        target.write_bytes(b"old")
        write_atomically(target, b"new-content")
        assert target.read_bytes() == b"new-content"
        assert not (tmp_path / "f.txt.tmp").exists()

    def test_temp_file_is_fsynced_before_replace(self, tmp_path, monkeypatch):
        # W-4: without an fsync the "atomic" write is not
        # power-loss-durable — the rename can reach disk before
        # the data does.
        import os

        fsynced = []
        real_fsync = os.fsync
        monkeypatch.setattr(
            os, "fsync", lambda fd: fsynced.append(fd) or real_fsync(fd)
        )
        target = tmp_path / "f.txt"
        write_atomically(target, b"durable")
        assert target.read_bytes() == b"durable"
        assert fsynced  # the temp file (and directory, where allowed)

    def test_first_replace_refusal_falls_back_to_the_swap(self, tmp_path, monkeypatch):
        import os

        target = tmp_path / "f.txt"
        target.write_bytes(b"old")
        real_replace = os.replace
        calls = []

        def flaky(src, dst):
            calls.append((src, dst))
            if len(calls) == 1:
                raise OSError("injected first-replace refusal")
            return real_replace(src, dst)

        monkeypatch.setattr(os, "replace", flaky)
        write_atomically(target, b"via-swap")
        assert target.read_bytes() == b"via-swap"
        assert len(calls) == 2  # direct rename, then the staged swap
        assert not (tmp_path / "f.txt.tmp").exists()
        assert not (tmp_path / "f.txt.swap").exists()

    def test_final_replace_failure_raises_and_keeps_the_old_file(
        self, tmp_path, monkeypatch
    ):
        # W-4: when even the staged rename fails, the write must
        # say so — reporting a success that never happened leaves
        # callers trusting state that is not on disk.
        import os

        target = tmp_path / "f.txt"
        target.write_bytes(b"old")

        def always_refuse(src, dst):
            raise OSError("injected replace refusal")

        monkeypatch.setattr(os, "replace", always_refuse)
        with pytest.raises(OSError):
            write_atomically(target, b"never-lands")
        assert target.read_bytes() == b"old"  # the old file stays
        assert not (tmp_path / "f.txt.tmp").exists()
        assert not (tmp_path / "f.txt.swap").exists()


class TestUpdater:
    def test_happy_path_both_sources(self, store):
        updater = ListUpdater(
            store,
            download_fn=downloads(
                {SOURCE_A.url: list_text("a", 1200), SOURCE_B.url: list_text("b", 1300)}
            ),
        )
        result = updater.update_all(now_ms=12345)
        assert result.success
        assert result.total_domains == 2500
        assert store.last_updated_ms() == 12345
        assert store.load_downloaded_blocklist().size == 2500

    def test_gate_failure_writes_nothing(self, store):
        updater = ListUpdater(
            store,
            download_fn=downloads({SOURCE_A.url: list_text("a", 10),
                                   SOURCE_B.url: list_text("b", 10)}),
        )
        result = updater.update_all(now_ms=999)
        assert not result.success
        assert store.last_updated_ms() == 0
        assert store.load_downloaded_blocklist() is None
        assert store.saved_file(SOURCE_A) is None

    def test_failed_source_keeps_previous_copy(self, store):
        good = ListUpdater(
            store,
            download_fn=downloads({SOURCE_A.url: list_text("a", 2000),
                                   SOURCE_B.url: list_text("b", 2000)}),
        )
        assert good.update_all(now_ms=1).success
        a_file_before = store.saved_file(SOURCE_A).read_bytes()

        flaky = ListUpdater(
            store,
            download_fn=downloads({SOURCE_A.url: None,
                                   SOURCE_B.url: list_text("b2", 2100)}),
        )
        result = flaky.update_all(now_ms=2)
        assert result.success
        outcomes = {o.source.name: o for o in result.outcomes}
        assert not outcomes["A"].refreshed
        assert outcomes["A"].domains == 2000  # the kept copy
        assert store.saved_file(SOURCE_A).read_bytes() == a_file_before
        combined = store.load_downloaded_blocklist()
        assert combined.is_blocked("a7.ads.example.com")  # kept
        assert combined.is_blocked("b27.ads.example.com")  # fresh

    def test_all_sources_failed_is_a_failed_update(self, store):
        # Even when the gate would pass on copies already on disk, an
        # update that downloaded nothing changes nothing — including
        # the recorded last-updated time (Android Phase 2 audit).
        good = ListUpdater(
            store,
            download_fn=downloads({SOURCE_A.url: list_text("a", 2000),
                                   SOURCE_B.url: list_text("b", 2000)}),
        )
        assert good.update_all(now_ms=111).success

        dead = ListUpdater(store, download_fn=downloads({}))
        result = dead.update_all(now_ms=222)
        assert not result.success
        assert store.last_updated_ms() == 111

    def test_error_page_download_keeps_working_list(self, store):
        updater = ListUpdater(
            store,
            download_fn=downloads({SOURCE_A.url: "<html>404 Not Found</html>",
                                   SOURCE_B.url: list_text("b", 3000)}),
        )
        result = updater.update_all(now_ms=5)
        assert result.success  # B alone passes the combined gate
        outcomes = {o.source.name: o for o in result.outcomes}
        assert not outcomes["A"].refreshed


class TestStoreLists:
    def test_bundled_fallback_until_downloads_exist(self, store):
        lists = store.load_effective_lists()
        assert lists.blocklist.size == 1500
        assert store.status().using_downloaded is False

    def test_downloaded_take_over_from_bundled(self, store):
        ListUpdater(
            store,
            download_fn=downloads({SOURCE_A.url: list_text("a", 1500),
                                   SOURCE_B.url: list_text("b", 1500)}),
        ).update_all(now_ms=1)
        status = store.status()
        assert status.using_downloaded is True
        assert status.active_domains == 3000

    def test_custom_entries_union_and_survive_updates(self, store):
        store.save_custom_block_entries(["mybank-ads.example.com", "com"])
        # "com" is refused by the entry rails, at entry time.
        assert store.custom_block_entries() == ["mybank-ads.example.com"]
        lists = store.load_effective_lists()
        assert lists.is_blocked("mybank-ads.example.com")
        assert lists.is_blocked("sub.mybank-ads.example.com")

    def test_allowlist_wins_over_custom_and_list(self, store):
        store.save_custom_block_entries(["ads.example.com"])
        store.save_allowlist(["ads.example.com"])
        assert not store.load_effective_lists().is_blocked("ads.example.com")

    def test_allowlist_save_enforces_rails(self, store):
        store.save_allowlist(["good.example.com", "localhost", "net"])
        assert store.allowlist_entries() == ["good.example.com"]

    def test_sources_round_trip_and_prune(self, store, tmp_path):
        ListUpdater(
            store,
            download_fn=downloads({SOURCE_A.url: list_text("a", 1500),
                                   SOURCE_B.url: list_text("b", 1500)}),
        ).update_all(now_ms=1)
        assert store.saved_file(SOURCE_B) is not None
        store.save_sources([SOURCE_A])
        assert [s.name for s in store.sources()] == ["A"]
        # B's downloaded file is pruned as an orphan.
        assert store.saved_file(SOURCE_B) is None

    def test_default_sources_when_none_saved(self, tmp_path):
        fresh = Store(tmp_path / "fresh")
        names = [s.name for s in fresh.sources()]
        assert any("StevenBlack" in n for n in names)
        assert any("HaGeZi" in n for n in names)
