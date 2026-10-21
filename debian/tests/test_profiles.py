"""The profile model (FILTER-SPEC, "Profiles"): a pure port of the
shared mechanism — snapshots of the user's own rules only, parsing
that degrades instead of destroying, and name/entry discipline
identical to the other editions."""
from sphinx_deb.core.profiles import Profile, ProfileSet, RuleState, is_valid_profile_name


def test_round_trip_preserves_profiles_states_and_active():
    original = ProfileSet(
        [
            Profile("Home", RuleState(["example.com"], ["ads.example.net"])),
            Profile("Quiet", RuleState([], ["tracker.example.org"])),
        ],
        active_name="Home",
    )
    parsed = ProfileSet.parse(original.serialize_lines())
    assert parsed == original
    assert parsed.active_name == "Home"


def test_empty_set_round_trips():
    assert ProfileSet.parse(ProfileSet().serialize_lines()).is_empty


def test_parse_ignores_garbage_unknown_verbs_and_orphan_lines():
    lines = [
        "this is not a directive",
        "allow\torphan.example.com",  # outside any section: ignored
        "frobnicate\twhatever",
        "profile\tHome",
        "allow\texample.com",
        "mystery\tline.example.com",
        "custom\tads.example.net",
    ]
    parsed = ProfileSet.parse(lines)
    home = parsed.profile("Home")
    assert home is not None
    assert home.state.allowlist_entries == frozenset({"example.com"})
    assert home.state.custom_block_entries == frozenset({"ads.example.net"})


def test_duplicate_profile_names_first_wins():
    lines = [
        "profile\tHome",
        "allow\tfirst.example.com",
        "profile\tHome",
        "allow\tsecond.example.com",
    ]
    parsed = ProfileSet.parse(lines)
    assert len(parsed.profiles) == 1
    assert parsed.profile("Home").state.allowlist_entries == frozenset({"first.example.com"})


def test_active_pointing_at_a_missing_profile_is_dropped():
    parsed = ProfileSet.parse(["active\tGhost", "profile\tHome", "allow\texample.com"])
    assert parsed.active_name is None
    assert parsed.profile("Home") is not None


def test_entries_pass_through_the_parser_rails():
    state = RuleState(
        ["Example.COM.", "com", "localhost", "1.2.3.4", "ok.example.org"],
        ["*.wild.example.net", "single"],
    )
    assert state.allowlist_entries == frozenset({"example.com", "ok.example.org"})
    assert state.custom_block_entries == frozenset({"wild.example.net"})


def test_with_profile_adds_replaces_in_place_and_refuses_bad_names():
    base = ProfileSet([Profile("Home", RuleState(["a.example.com"]))])
    added = base.with_profile(Profile("Work", RuleState(["b.example.com"])))
    assert [p.name for p in added.profiles] == ["Home", "Work"]
    replaced = added.with_profile(Profile("Home", RuleState(["c.example.com"])))
    assert [p.name for p in replaced.profiles] == ["Home", "Work"]  # position kept
    assert replaced.profile("Home").state.allowlist_entries == frozenset({"c.example.com"})
    assert base.with_profile(Profile("bad\tname", RuleState())) is base


def test_without_profile_clears_active_only_when_it_was_active():
    base = ProfileSet(
        [Profile("Home", RuleState()), Profile("Work", RuleState())],
        active_name="Home",
    )
    assert base.without_profile("Work").active_name == "Home"
    gone = base.without_profile("Home")
    assert gone.active_name is None
    assert gone.profile("Home") is None
    assert base.without_profile("Ghost") is base


def test_with_active_requires_an_existing_profile():
    base = ProfileSet([Profile("Home", RuleState())])
    assert base.with_active("Home").active_name == "Home"
    assert base.with_active("Ghost").active_name is None
    assert base.with_active(None).active_name is None


def test_profile_name_validation():
    assert is_valid_profile_name("Home")
    assert is_valid_profile_name("  padded name  ")
    assert is_valid_profile_name("x" * 40)
    assert not is_valid_profile_name("")
    assert not is_valid_profile_name("   ")
    assert not is_valid_profile_name("x" * 41)
    assert not is_valid_profile_name("tab\tname")
    assert not is_valid_profile_name(None)


def test_section_with_an_invalid_name_is_skipped_entirely():
    lines = ["profile\tbad\tname", "allow\tlost.example.com", "profile\tGood", "allow\tkept.example.com"]
    parsed = ProfileSet.parse(lines)
    assert [p.name for p in parsed.profiles] == ["Good"]
    assert parsed.profile("Good").state.allowlist_entries == frozenset({"kept.example.com"})
