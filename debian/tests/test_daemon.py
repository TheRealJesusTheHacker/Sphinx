"""The daemon's configuration discipline: spec defaults, honest
overrides, and the hard rule that an upstream on this machine is
refused (it would loop questions back into a local resolver).

Plus (Phase 2) the daemon's live view of the store: rule edits,
profile switches, and list updates land in the running filter —
proven at the engine's decision point, without a restart."""
import pytest

from sphinx_deb.core.dnswire import build_query
from sphinx_deb.core.server import FilterEngine
from sphinx_deb.core.store import Store
from sphinx_deb.daemon import ConfigError, DaemonConfig, LiveLists


def _write(tmp_path, text):
    conf = tmp_path / "sphinx.conf"
    conf.write_text(text)
    return conf


def test_defaults_when_no_config_file(tmp_path):
    config = DaemonConfig.load(tmp_path / "missing.conf")
    assert config.upstreams == ["1.1.1.1", "9.9.9.9"]
    assert config.log_queries is True


def test_custom_upstream_and_fallback(tmp_path):
    config = DaemonConfig.load(
        _write(tmp_path, "upstream = 192.168.1.1\nfallback = 192.168.1.2\n")
    )
    assert config.upstreams == ["192.168.1.1", "192.168.1.2"]


def test_primary_only_drops_the_default_fallback(tmp_path):
    config = DaemonConfig.load(_write(tmp_path, "upstream = 192.168.1.1\n"))
    assert config.upstreams == ["192.168.1.1"]


def test_loopback_upstreams_are_refused(tmp_path):
    for bad in ("127.0.0.1", "127.0.0.53", "::1"):
        with pytest.raises(ConfigError):
            DaemonConfig.load(_write(tmp_path, f"upstream = {bad}\n"))


def test_non_address_upstream_is_refused(tmp_path):
    with pytest.raises(ConfigError):
        DaemonConfig.load(_write(tmp_path, "upstream = dns.example.com\n"))


def test_query_log_can_be_turned_off(tmp_path):
    config = DaemonConfig.load(_write(tmp_path, "query_log = off\n"))
    assert config.log_queries is False


# --- LiveLists: the running filter sees store edits --------------------


def _live(tmp_path):
    bundled = tmp_path / "bundled.txt"
    lines = ["0.0.0.0 ads{}.example.com".format(i) for i in range(1500)]
    lines.append("0.0.0.0 ads.example.com")
    bundled.write_text("\n".join(lines) + "\n")
    store = Store(tmp_path / "state", bundled)
    return store, LiveLists(store)


def _engine(live):
    return FilterEngine(
        lists_provider=live.get, forwarder=lambda data: b"FORWARDED"
    )


def test_rule_edits_change_live_decisions_without_a_restart(tmp_path):
    store, live = _live(tmp_path)
    engine = _engine(live)
    query = build_query("tracker.example.net")
    # Not blocked anywhere yet: the question is let through.
    assert engine.handle_query(query) == b"FORWARDED"
    # A custom block entry lands — and the very next decision flips.
    store.save_custom_block_entries(["tracker.example.net"])
    assert engine.handle_query(query) is not None
    assert engine.handle_query(query) != b"FORWARDED"
    # An allowlist edit flips a bundled block the other way.
    ads = build_query("ads.example.com")
    assert engine.handle_query(ads) != b"FORWARDED"
    store.save_allowlist(["ads.example.com"])
    assert engine.handle_query(ads) == b"FORWARDED"


def test_a_profile_switch_changes_live_decisions(tmp_path):
    store, live = _live(tmp_path)
    engine = _engine(live)
    store.save_custom_block_entries(["home.example.net"])
    store.create_profile("Home")
    # Build the second profile without the write-through sync
    # touching Home's snapshot (the same sync-off write the
    # store's own switch machinery uses).
    store.save_custom_block_entries(["other.example.net"], sync_profile=False)
    store.create_profile("Other")
    home_q = build_query("home.example.net")
    other_q = build_query("other.example.net")
    assert engine.handle_query(other_q) != b"FORWARDED"
    assert engine.handle_query(home_q) == b"FORWARDED"
    store.switch_profile("Home")
    assert engine.handle_query(home_q) != b"FORWARDED"
    assert engine.handle_query(other_q) == b"FORWARDED"


def test_a_list_update_changes_live_decisions(tmp_path):
    store, live = _live(tmp_path)
    engine = _engine(live)
    fresh_q = build_query("fresh.example.org")
    assert engine.handle_query(fresh_q) == b"FORWARDED"
    first, second = store.sources()
    body = ("\n".join("0.0.0.0 dl{}.example.com".format(i) for i in range(1200)) + "\n").encode()
    store.write_downloaded(first, body)
    store.write_downloaded(second, body.replace(b"dl", b"dl2"))
    store.record_update(2400, 99)
    assert live.current().using_downloaded is True
    assert engine.handle_query(build_query("dl0.example.com")) != b"FORWARDED"


def test_a_failed_reload_keeps_the_last_good_lists(tmp_path):
    store, live = _live(tmp_path)
    assert live.current().lists.is_blocked("ads.example.com")
    # The bundled list becomes unreadable mid-run (a directory
    # where the file was): the reload fails, the last good set
    # keeps serving, and nothing crashes.
    store.bundled_list_path.unlink()
    store.bundled_list_path.mkdir()
    state = live.current()
    assert state.lists.is_blocked("ads.example.com")


def test_the_first_load_failure_propagates(tmp_path):
    store = Store(tmp_path / "state", tmp_path / "missing-bundled.txt")
    live = LiveLists(store)
    with pytest.raises(OSError):
        live.current()
