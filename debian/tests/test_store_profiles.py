"""Profiles at the store level — the disciplines the other
editions' audits pinned, carried here exactly:

- live edits write through to the active profile;
- a switch NEVER writes through (sync off) and sets the active
  marker from a fresh read, so the outgoing profile's snapshot
  survives a switch byte-intact — the Android Phase 4 audit's
  corruption scenario, designed out;
- a switch changes the live rules and nothing else: never the
  lists, never the sources, never the last-updated record —
  a profile switch is not a disguised list change;
- deleting a profile deletes only the snapshot.
"""
from sphinx_deb.core.store import Store


def _store(tmp_path):
    bundled = tmp_path / "bundled.txt"
    bundled.write_text("0.0.0.0 bundled.example.com\n")
    return Store(tmp_path / "state", bundled)


def _profile_section(store, name):
    """The raw stored lines of one profile's section, for
    byte-level comparison across a switch."""
    lines = store.profiles_file.read_text().splitlines()
    section, inside = [], False
    for line in lines:
        verb, _, value = line.partition("\t")
        if verb == "profile":
            inside = value == name
            if inside:
                section.append(line)
            continue
        if inside:
            section.append(line)
    return section


def test_create_snapshots_the_live_rules_and_activates(tmp_path):
    store = _store(tmp_path)
    store.save_allowlist(["a.example.com"])
    store.save_custom_block_entries(["b.example.net"])
    created = store.create_profile("Home")
    assert created is not None and created.active_name == "Home"
    home = created.profile("Home")
    assert home.state.allowlist_entries == frozenset({"a.example.com"})
    assert home.state.custom_block_entries == frozenset({"b.example.net"})


def test_create_refuses_duplicate_and_unusable_names(tmp_path):
    store = _store(tmp_path)
    assert store.create_profile("Home") is not None
    assert store.create_profile("Home") is None
    assert store.create_profile("bad\tname") is None
    assert store.create_profile("   ") is None


def test_live_edits_write_through_to_the_active_profile(tmp_path):
    store = _store(tmp_path)
    store.create_profile("Home")
    store.save_allowlist(["new.example.com"])
    store.save_custom_block_entries(["mine.example.net"])
    home = store.load_profile_set().profile("Home")
    assert home.state.allowlist_entries == frozenset({"new.example.com"})
    assert home.state.custom_block_entries == frozenset({"mine.example.net"})


def test_no_write_through_without_an_active_profile(tmp_path):
    store = _store(tmp_path)
    store.create_profile("Home")
    store.delete_profile("Home")  # no longer active — or present
    store.save_allowlist(["a.example.com"])
    assert store.load_profile_set().is_empty


def _two_profiles(store):
    """'Home' = allow home.example.com; 'Other' = allow
    other.example.com + block x.example.net. The second profile's
    state is staged with the sync off — while a profile is active,
    ordinary edits belong to it (write-through), so staging a
    *different* state uses the same sync-off write the store's
    switch machinery itself uses."""
    store.save_allowlist(["home.example.com"])
    store.create_profile("Home")
    store.save_allowlist(["other.example.com"], sync_profile=False)
    store.save_custom_block_entries(["x.example.net"], sync_profile=False)
    store.create_profile("Other")


def test_switch_applies_the_snapshot_to_the_live_rules(tmp_path):
    store = _store(tmp_path)
    _two_profiles(store)
    assert store.switch_profile("Home") is True
    assert store.allowlist_entries() == ["home.example.com"]
    assert store.custom_block_entries() == []
    assert store.load_profile_set().active_name == "Home"


def test_switch_leaves_both_snapshots_byte_intact(tmp_path):
    store = _store(tmp_path)
    _two_profiles(store)
    home_before = _profile_section(store, "Home")
    other_before = _profile_section(store, "Other")
    assert store.switch_profile("Home") is True
    assert _profile_section(store, "Home") == home_before
    assert _profile_section(store, "Other") == other_before
    assert store.switch_profile("Other") is True
    assert _profile_section(store, "Home") == home_before
    assert _profile_section(store, "Other") == other_before


def test_switch_to_a_missing_profile_changes_nothing(tmp_path):
    store = _store(tmp_path)
    store.save_allowlist(["a.example.com"])
    assert store.switch_profile("Ghost") is False
    assert store.allowlist_entries() == ["a.example.com"]
    assert not store.profiles_file.exists()


def test_switch_never_touches_lists_sources_or_update_record(tmp_path):
    store = _store(tmp_path)
    first, _second = store.sources()
    store.write_downloaded(first, b"0.0.0.0 dl.example.com\n")
    store.record_update(1, 4242)
    lists_before = store.file_for(first).read_bytes()
    store.create_profile("Home")
    assert store.switch_profile("Home") is True
    assert store.file_for(first).read_bytes() == lists_before
    assert store.last_updated_ms() == 4242
    assert store.sources()  # unchanged (still the defaults + nothing lost)


def test_delete_removes_only_the_snapshot(tmp_path):
    store = _store(tmp_path)
    store.save_allowlist(["a.example.com"])
    store.create_profile("Home")
    assert store.delete_profile("Home") is True
    assert store.allowlist_entries() == ["a.example.com"]  # live rules stay
    assert store.load_profile_set().active_name is None  # marker cleared
    assert store.delete_profile("Home") is False


def test_a_malformed_profiles_file_degrades_and_never_wipes_live_rules(tmp_path):
    store = _store(tmp_path)
    store.save_allowlist(["a.example.com"])
    store.data_dir.mkdir(parents=True, exist_ok=True)
    store.profiles_file.write_text("garbage\x00nonsense\nprofile\t\n")
    assert store.load_profile_set().is_empty
    assert store.allowlist_entries() == ["a.example.com"]
