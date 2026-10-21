"""The command line (Phase 2): rule editing, profiles, and the
update command — driven through main() with the state directory
and the list pointed at temp files, and root simulated, so the
suite never touches the host's real state. The guard commands'
own suite is test_guard.py; here the guard appears only as
status's resumption reconciliation, over the conftest fakes."""
import pytest

from conftest import FakeProofer, stub_resolved_view
from sphinx_deb import cli
from sphinx_deb.core.store import Store
from sphinx_deb.core.updater import ListUpdater as RealListUpdater
from sphinx_deb.core.validation import DEFAULT_SOURCES
from sphinx_deb.resolver.guard import DnsGuard


def _body(count, start=0):
    return ("\n".join("0.0.0.0 ads{}.example.com".format(i) for i in range(start, start + count)) + "\n").encode()


@pytest.fixture
def env(tmp_path, monkeypatch):
    state = tmp_path / "state"
    bundled = tmp_path / "bundled.txt"
    bundled.write_bytes(_body(1500))
    monkeypatch.setenv("SPHINX_STATE_DIR", str(state))
    monkeypatch.setenv("SPHINX_LIST", str(bundled))
    monkeypatch.setenv("SPHINX_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("SPHINX_CONF", str(tmp_path / "missing.conf"))
    monkeypatch.setattr(cli, "_is_root", lambda: True)
    return state, bundled


def _store(env):
    state, bundled = env
    return Store(state, bundled)


# --- allow / block -------------------------------------------------------


def test_allow_add_list_remove_round_trip(env, capsys):
    assert cli.main(["allow", "add", "Example.COM."]) == 0
    assert _store(env).allowlist_entries() == ["example.com"]
    assert cli.main(["allow", "list"]) == 0
    assert "example.com" in capsys.readouterr().out
    assert cli.main(["allow", "add", "example.com"]) == 0
    assert "already" in capsys.readouterr().out
    assert cli.main(["allow", "remove", "example.com"]) == 0
    assert _store(env).allowlist_entries() == []
    assert cli.main(["allow", "remove", "example.com"]) == 0
    assert "is not on" in capsys.readouterr().out


def test_block_add_and_list(env, capsys):
    assert cli.main(["block", "add", "tracker.example.net"]) == 0
    assert _store(env).custom_block_entries() == ["tracker.example.net"]
    assert cli.main(["block", "list"]) == 0
    assert "tracker.example.net" in capsys.readouterr().out


@pytest.mark.parametrize(
    "bad", ["localhost", "com", "1.2.3.4", "not a domain", "", "*.com"]
)
def test_unusable_entries_are_refused_plainly(env, capsys, bad):
    assert cli.main(["allow", "add", bad]) == cli.EXIT_REFUSED
    assert "cannot be an entry" in capsys.readouterr().out
    assert _store(env).allowlist_entries() == []


def test_rule_edits_need_root_but_listing_does_not(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_is_root", lambda: False)
    assert cli.main(["allow", "add", "example.com"]) == cli.EXIT_REFUSED
    assert "sudo" in capsys.readouterr().out
    assert _store(env).allowlist_entries() == []
    assert cli.main(["allow", "list"]) == 0


def test_bare_rule_and_profile_commands_say_what_to_do(env, capsys):
    assert cli.main(["allow"]) == cli.EXIT_REFUSED
    assert cli.main(["profile"]) == cli.EXIT_REFUSED
    out = capsys.readouterr().out
    assert "sphinx allow list" in out and "sphinx profile list" in out


# --- profiles --------------------------------------------------------------


def test_profile_flow(env, capsys):
    assert cli.main(["allow", "add", "home.example.com"]) == 0
    assert cli.main(["profile", "save", "Home"]) == 0
    capsys.readouterr()
    assert cli.main(["profile", "list"]) == 0
    out = capsys.readouterr().out
    assert "Home" in out and "under the profile 'Home'" in out
    # Change the live rules, then switch back: the snapshot rules.
    assert cli.main(["allow", "remove", "home.example.com"]) == 0
    assert _store(env).allowlist_entries() == []
    assert cli.main(["profile", "use", "Home"]) == 0
    # (the remove wrote through to Home first — it was active — so
    # Home now holds the empty allowlist too; write-through is the
    # spec's rule, proven at the store level in test_store_profiles)
    assert cli.main(["profile", "delete", "Home"]) == 0
    assert cli.main(["profile", "use", "Home"]) == cli.EXIT_REFUSED
    assert cli.main(["profile", "save", "Home"]) == 0  # name free again


def test_profile_save_duplicate_and_bad_name(env, capsys):
    assert cli.main(["profile", "save", "Home"]) == 0
    assert cli.main(["profile", "save", "Home"]) == cli.EXIT_REFUSED
    assert "already exists" in capsys.readouterr().out
    assert cli.main(["profile", "save", "x" * 41]) == cli.EXIT_REFUSED


def test_profile_commands_need_root_except_list(env, monkeypatch):
    monkeypatch.setattr(cli, "_is_root", lambda: False)
    assert cli.main(["profile", "save", "Home"]) == cli.EXIT_REFUSED
    assert cli.main(["profile", "list"]) == 0


# --- update ------------------------------------------------------------------


def _fake_updater_factory(bodies):
    def factory(store):
        return RealListUpdater(store, download_fn=lambda url: bodies.get(url))

    return factory


def test_update_success_reports_and_records(env, monkeypatch, capsys):
    first, second = DEFAULT_SOURCES
    bodies = {first.url: _body(1200), second.url: _body(1200, start=1200)}
    monkeypatch.setattr(cli, "ListUpdater", _fake_updater_factory(bodies))
    assert cli.main(["update"]) == 0
    out = capsys.readouterr().out
    assert "Lists updated: 2,400 domains" in out
    store = _store(env)
    assert store.status().using_downloaded is True
    assert store.last_updated_ms() > 0


def test_update_failure_changes_nothing_and_says_so(env, monkeypatch, capsys):
    first, second = DEFAULT_SOURCES
    bodies = {first.url: _body(1200), second.url: None}
    monkeypatch.setattr(cli, "ListUpdater", _fake_updater_factory(bodies))
    assert cli.main(["update"]) == cli.EXIT_REFUSED
    out = capsys.readouterr().out
    assert "nothing was changed" in out and "FAILED" in out
    store = _store(env)
    assert store.status().using_downloaded is False
    assert store.last_updated_ms() == 0


def test_update_needs_root(env, monkeypatch):
    monkeypatch.setattr(cli, "_is_root", lambda: False)
    built = []
    monkeypatch.setattr(cli, "ListUpdater", lambda store: built.append(store))
    assert cli.main(["update"]) == cli.EXIT_REFUSED
    assert built == []  # the updater was never even constructed


# --- status: the resumption reconciliation -----------------------------------


def test_status_reconciles_a_leftover_with_intent_on(env, monkeypatch, capsys):
    state, _bundled = env
    view = stub_resolved_view()
    guard = DnsGuard(view, state)
    assert guard.engage(FakeProofer()).ok
    # Reboot: the runtime override is gone; record + intent remain.
    view.links["eth0"] = ["192.168.1.1"]
    monkeypatch.setattr(cli, "RealSystemView", lambda: view)
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "Recorded decision: on" in out
    assert "was on when this machine's network changed" in out
    assert "sudo sphinx engage" in out


def test_status_does_not_offer_resumption_when_intent_is_off(env, monkeypatch, capsys):
    state, _bundled = env
    view = stub_resolved_view()
    guard = DnsGuard(view, state)
    assert guard.engage(FakeProofer()).ok
    assert guard.disengage().ok
    # A leftover whose intent is off (record re-created by hand is
    # not needed: disengage retired it) — plain disengaged status,
    # no resumption offer.
    monkeypatch.setattr(cli, "RealSystemView", lambda: view)
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "was on when this machine's network changed" not in out
