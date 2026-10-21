"""Profiles at the store: creation, write-through, switching, and
deletion — including the Android Phase 4 audit's switch-integrity
scenario (a switch must never write the incoming state into the
outgoing profile's snapshot), and a controller pass proving a
switch plus the ordinary reload applies ALL state to the filter.

The flow these tests walk is the model's own: creating a profile
makes it active, so the rules you edit next belong to it; creating
a second profile snapshots the current rules, and from there the
two can diverge.
"""
import pytest

from sphinx_win.app.controller import SphinxController
from sphinx_win.core.store import Store
from sphinx_win.dnsmgmt.base import AdapterDns
from sphinx_win.dnsmgmt.fake import FakeDnsManager

from dnsutil import build_query

ADAPTERS = [
    AdapterDns("Wi-Fi", "IPv4", ["192.168.1.1"]),
    AdapterDns("Wi-Fi", "IPv6", []),
]


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "data")


def make_two_profiles(store):
    """Live rules [a] under profile A; live rules [b] under B
    (active). Returns nothing; asserts belong to the caller."""
    store.save_custom_block_entries(["a.example.com"])
    assert store.create_profile("A") is not None
    assert store.create_profile("B") is not None
    store.save_custom_block_entries(["b.example.com"])  # writes through to B


def test_create_profile_snapshots_live_state_and_activates(store):
    store.save_allowlist(["bank.example.com"])
    store.save_custom_block_entries(["ads.example.net"])
    created = store.create_profile("Home")
    assert created is not None
    assert created.active_name == "Home"
    home = created.profile("Home")
    assert home.state.allowlist_entries == {"bank.example.com"}
    assert home.state.custom_block_entries == {"ads.example.net"}
    # And it survives a fresh read from disk.
    assert store.load_profile_set() == created


def test_create_profile_refuses_duplicates_and_bad_names(store):
    assert store.create_profile("Home") is not None
    assert store.create_profile("Home") is None
    assert store.create_profile("   ") is None
    assert store.create_profile("bad\tname") is None
    assert [p.name for p in store.load_profile_set().profiles] == ["Home"]


def test_live_edits_write_through_to_the_active_profile(store):
    store.create_profile("Home")
    store.save_allowlist(["bank.example.com"])
    store.save_custom_block_entries(["ads.example.net"])
    home = store.load_profile_set().profile("Home")
    assert home.state.allowlist_entries == {"bank.example.com"}
    assert home.state.custom_block_entries == {"ads.example.net"}


def test_live_edits_without_an_active_profile_touch_no_profiles(store):
    store.save_allowlist(["bank.example.com"])
    store.save_custom_block_entries(["ads.example.net"])
    assert store.load_profile_set().is_empty
    assert not store.profiles_file.exists()


def test_switch_applies_the_snapshot_and_never_rewrites_the_outgoing(store):
    make_two_profiles(store)
    before = store.load_profile_set()
    assert before.active_name == "B"
    assert before.profile("A").state.custom_block_entries == {"a.example.com"}
    assert before.profile("B").state.custom_block_entries == {"b.example.com"}

    assert store.switch_profile("A") is True

    # Live state is A's now...
    assert store.custom_block_entries() == ["a.example.com"]
    # ...the marker moved...
    after = store.load_profile_set()
    assert after.active_name == "A"
    # ...and both snapshots are byte-for-byte the states they held
    # before the switch — the outgoing profile (B) was only read.
    assert after.profiles == before.profiles


def test_switch_to_a_missing_profile_changes_nothing(store):
    make_two_profiles(store)
    live_before = store.custom_block_entries()
    set_before = store.load_profile_set()
    assert store.switch_profile("Ghost") is False
    assert store.custom_block_entries() == live_before
    assert store.load_profile_set() == set_before


def test_delete_profile_keeps_live_rules_and_clears_the_marker(store):
    make_two_profiles(store)
    assert store.delete_profile("B") is True  # B was active
    profile_set = store.load_profile_set()
    assert profile_set.active_name is None
    assert [p.name for p in profile_set.profiles] == ["A"]
    # The live rules stay exactly as they were.
    assert store.custom_block_entries() == ["b.example.com"]
    assert store.delete_profile("B") is False


def test_malformed_profiles_file_degrades_and_never_touches_live(store):
    store.save_allowlist(["bank.example.com"])
    store.profiles_file.write_text(
        "garbage with no tabs\n\x00\x01 binary junk\nprofile\t\n",
        encoding="utf-8",
    )
    assert store.load_profile_set().is_empty
    assert store.switch_profile("Anything") is False
    assert store.allowlist_entries() == ["bank.example.com"]


class FakeServer:
    def __init__(self, engine):
        self.engine = engine
        self.started = False

    def start(self):
        self.started = True
        return [("127.0.0.1", 53), ("::1", 53)]

    def answers_on(self, address, timeout=2.0):
        return True

    def stop(self):
        self.started = False


def test_switch_plus_reload_applies_all_state_to_the_filter(tmp_path):
    """The whole point of the phase's switch discipline: after
    store.switch_profile + controller.reload_lists (the window's
    switch path), the running filter's decisions are the new
    profile's — allowlist and custom entries alike."""
    store = Store(tmp_path / "data")
    manager = FakeDnsManager(ADAPTERS, elevated=True)
    controller = SphinxController(
        store, manager, tmp_path / "data", server_factory=FakeServer
    )

    # Profile A: blocks a.example.com via a custom entry.
    # Profile B: allowlists it instead (and blocks nothing custom).
    store.save_custom_block_entries(["a.example.com"])
    assert store.create_profile("A") is not None
    assert store.create_profile("B") is not None
    store.save_custom_block_entries([])
    store.save_allowlist(["a.example.com"])  # write-through: B's state

    assert store.switch_profile("A") is True
    controller.reload_lists()
    lists = controller._current_lists()
    assert lists.is_blocked("a.example.com") is True
    # The engine itself sinkholes it (no upstream involved).
    response = controller.engine.handle_query(build_query("a.example.com"))
    assert response is not None
    assert response[-4:] == b"\x00\x00\x00\x00"

    assert store.switch_profile("B") is True
    controller.reload_lists()
    lists = controller._current_lists()
    assert lists.is_blocked("a.example.com") is False
