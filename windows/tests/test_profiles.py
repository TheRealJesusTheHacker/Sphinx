"""Profiles: the named rule-state model (core/profiles.py).

A mirror of the Android edition's ProfilesTest cases, minus the
per-app rules the Windows edition doesn't have: round-trip,
garbage tolerance, first-wins duplicates, the parser's rails on
stored entries, replace/delete/active semantics, and the name
rules. The store-level disciplines (write-through, switch
integrity) live in test_store_profiles.py.
"""
from sphinx_win.core.profiles import (
    Profile,
    ProfileSet,
    RuleState,
    is_valid_profile_name,
)


def home_state():
    return RuleState(
        allowlist_entries=["example.com", "news.example.org"],
        custom_block_entries=["ads.example.net"],
    )


def kids_state():
    return RuleState(
        allowlist_entries=["school.example.edu"],
        custom_block_entries=["social.example.com", "games.example.com"],
    )


def test_round_trip_preserves_profiles_states_and_active():
    profile_set = ProfileSet(
        [Profile("Home", home_state()), Profile("Kids", kids_state())],
        active_name="Kids",
    )
    parsed = ProfileSet.parse(profile_set.serialize_lines())
    assert parsed == profile_set
    assert parsed.active_name == "Kids"
    assert parsed.profile("Kids").state == kids_state()
    assert parsed.profile("Home").state == home_state()


def test_empty_set_round_trips():
    profile_set = ProfileSet()
    assert profile_set.is_empty
    assert profile_set.active_name is None
    assert ProfileSet.parse(profile_set.serialize_lines()) == profile_set
    assert ProfileSet.parse([]) == profile_set


def test_parse_ignores_garbage_unknown_verbs_and_orphan_lines():
    parsed = ProfileSet.parse(
        [
            "this line has no tab",
            "frobnicate\twhatever",
            "allow\torphan.example.com",  # outside any section
            "profile\tHome",
            "mystery\tline",
            "",
            "allow\texample.com",
            "custom\tads.example.net",
        ]
    )
    assert len(parsed.profiles) == 1
    home = parsed.profile("Home")
    assert home.state.allowlist_entries == {"example.com"}
    assert home.state.custom_block_entries == {"ads.example.net"}


def test_duplicate_profile_names_first_wins():
    parsed = ProfileSet.parse(
        [
            "profile\tHome",
            "allow\tfirst.example.com",
            "profile\tHome",
            "allow\tsecond.example.com",
        ]
    )
    assert len(parsed.profiles) == 1
    assert parsed.profile("Home").state.allowlist_entries == {"first.example.com"}


def test_active_pointing_at_missing_profile_is_dropped():
    parsed = ProfileSet.parse(
        [
            "active\tGhost",
            "profile\tHome",
            "allow\texample.com",
        ]
    )
    assert parsed.active_name is None
    assert parsed.active_profile is None


def test_entries_pass_through_the_parser_rails():
    # Junk offered as entries must be dropped by the same rails
    # the list parser applies: no single labels (they would block
    # a whole TLD), no reserved names, no IP literals.
    state = RuleState(
        allowlist_entries=["com", "localhost", "EXAMPLE.com.", "ok.example.org"],
        custom_block_entries=["*.wild.example.net", "127.0.0.1"],
    )
    assert state.allowlist_entries == {"example.com", "ok.example.org"}
    assert state.custom_block_entries == {"wild.example.net"}


def test_with_profile_adds_replaces_in_place_and_refuses_bad_names():
    profile_set = ProfileSet()
    profile_set = profile_set.with_profile(Profile("Home", home_state()))
    profile_set = profile_set.with_profile(Profile("Kids", kids_state()))
    assert [p.name for p in profile_set.profiles] == ["Home", "Kids"]

    # Replacing keeps the position and swaps the state.
    changed = RuleState(
        allowlist_entries=set(kids_state().allowlist_entries) | {"extra.example.com"},
        custom_block_entries=kids_state().custom_block_entries,
    )
    profile_set = profile_set.with_profile(Profile("Kids", changed))
    assert [p.name for p in profile_set.profiles] == ["Home", "Kids"]
    assert profile_set.profile("Kids").state == changed

    # An unusable name changes nothing.
    assert profile_set.with_profile(Profile("  ", home_state())) == profile_set
    assert profile_set.with_profile(Profile("bad\tname", home_state())) == profile_set


def test_without_profile_clears_active_only_when_it_was_the_active_one():
    profile_set = ProfileSet(
        [Profile("Home", home_state()), Profile("Kids", kids_state())],
        active_name="Home",
    )
    profile_set = profile_set.without_profile("Kids")
    assert profile_set.active_name == "Home"
    assert [p.name for p in profile_set.profiles] == ["Home"]

    profile_set = profile_set.without_profile("Home")
    assert profile_set.is_empty
    assert profile_set.active_name is None

    # Removing a name that isn't there is a no-op.
    other = ProfileSet([Profile("Home", home_state())], "Home")
    assert other.without_profile("Nope") == other


def test_with_active_requires_an_existing_profile():
    profile_set = ProfileSet([Profile("Home", home_state())])
    assert profile_set.with_active("Home").active_name == "Home"
    assert profile_set.with_active("Ghost") == profile_set
    assert profile_set.with_active("Home").with_active(None).active_name is None


def test_profile_name_validation():
    assert is_valid_profile_name("Home")
    assert is_valid_profile_name("Kids' stuff 2")
    assert not is_valid_profile_name(None)
    assert not is_valid_profile_name("")
    assert not is_valid_profile_name("   ")
    assert not is_valid_profile_name("x" * 41)
    assert is_valid_profile_name("x" * 40)
    assert not is_valid_profile_name("has\ttab")
    assert not is_valid_profile_name("has\nnewline")


def test_section_with_invalid_name_is_skipped_entirely():
    parsed = ProfileSet.parse(
        [
            "profile\t",
            "allow\tlost.example.com",
            "profile\tKept",
            "allow\tkept.example.com",
        ]
    )
    assert [p.name for p in parsed.profiles] == ["Kept"]
    assert parsed.profile("Kept").state.allowlist_entries == {"kept.example.com"}


def test_constructor_dedupes_and_filters_like_the_parser():
    profile_set = ProfileSet(
        [
            Profile("Home", home_state()),
            Profile("Home", kids_state()),
            Profile("bad\tname", home_state()),
        ],
        active_name="Ghost",
    )
    assert [p.name for p in profile_set.profiles] == ["Home"]
    assert profile_set.profile("Home").state == home_state()
    assert profile_set.active_name is None
