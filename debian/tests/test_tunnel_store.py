"""The tunnel profile store: root-only, 0600, atomic, and
degrade-never-destroy (TUNNEL-SPEC profile storage)."""
import os
import stat

from sphinx_deb.core.tunnel import parse_config
from sphinx_deb.core.tunnelstore import TunnelStore

WG = (
    "# Sphinx profile: Home Server\n"
    "[Interface]\n"
    "PrivateKey = hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=\n"
    "Address = 10.8.0.2/32\n"
    "DNS = 10.8.0.1\n"
    "\n"
    "[Peer]\n"
    "PublicKey = q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=\n"
    "Endpoint = vpn.example.com:51820\n"
    "AllowedIPs = 0.0.0.0/0\n"
)


def test_profiles_live_root_only_at_0600(tmp_path):
    store = TunnelStore(tmp_path)
    stored = store.save(parse_config(WG))
    assert stat.S_IMODE(os.stat(store.profiles_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(stored.path).st_mode) == 0o600
    # The private key is in the file (it is the profile); nothing
    # else in the state dir carries it.
    assert "PrivateKey" in stored.path.read_text()
    assert not list(tmp_path.glob("*.tmp"))


def test_save_get_list_remove_round_trip(tmp_path):
    store = TunnelStore(tmp_path)
    store.save(parse_config(WG))
    got = store.get("Home Server")
    assert got is not None
    assert got.profile.export_text() == WG
    assert [s.profile.name for s in store.list_profiles()] == ["Home Server"]
    assert store.remove("Home Server") is True
    assert store.get("Home Server") is None
    assert store.remove("Home Server") is False


def test_a_broken_profile_file_degrades_and_is_never_destroyed(tmp_path):
    store = TunnelStore(tmp_path)
    store.save(parse_config(WG))
    broken = store.profiles_dir / "broken.conf"
    broken.write_text("this is not a config at all\n")
    before = broken.read_bytes()
    names = [s.profile.name for s in store.list_profiles()]
    assert names == ["Home Server"]  # the good profile is untouched
    problems = store.problems()
    assert len(problems) == 1 and problems[0].path == broken
    assert broken.read_bytes() == before  # left exactly as it was


def test_session_record_round_trip_and_clear(tmp_path):
    store = TunnelStore(tmp_path)
    assert store.load_session() is None
    record = {"version": 1, "state": "engaged", "profile": "Home Server", "intent": True}
    store.save_session(record)
    assert store.load_session() == record
    assert stat.S_IMODE(os.stat(store.session_file).st_mode) == 0o600
    store.clear_session()
    assert store.load_session() is None


def test_unnamed_profile_is_named_by_its_file(tmp_path):
    store = TunnelStore(tmp_path)
    store.profiles_dir.mkdir(parents=True)
    (store.profiles_dir / "provider-export.conf").write_text(
        WG.replace("# Sphinx profile: Home Server\n", "")
    )
    got = store.get("provider-export")
    assert got is not None and got.profile.name == "provider-export"
