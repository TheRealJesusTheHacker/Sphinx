"""The profile store and the tunnel state record: atomic writes,
corrupt records refused loudly with the file left untouched, the
empty-start truth, and the parallel-record rule — the DNS backup
file is never the tunnel's to touch."""
import json

import pytest

from sphinx_win.core.tunnel import TunnelRefusal
from sphinx_win.core.tunnelstore import (
    TunnelState,
    TunnelStore,
    TunnelStoreError,
)

WG = (
    "# Sphinx profile: Home Server\n[Interface]\n"
    "PrivateKey = hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=\n"
    "Address = 10.8.0.2/32\nDNS = 10.8.0.1\n\n[Peer]\n"
    "PublicKey = q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=\n"
    "Endpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
)
BAD = "[Interface]\nPrivateKey = too-short\n"


@pytest.fixture()
def store(tmp_path):
    return TunnelStore(tmp_path / "data")


class TestProfiles:
    def test_starts_empty(self, store):
        assert store.load_profiles() == []
        assert store.profile_names() == []

    def test_import_round_trip_and_export(self, store):
        profile = store.import_text(WG)
        assert profile.name == "Home Server"
        assert store.profile_names() == ["Home Server"]
        assert store.export_text("Home Server") == WG
        loaded = store.get_profile("Home Server")
        assert loaded.server_public_key == (
            "q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU="
        )

    def test_bad_import_refused_and_store_untouched(self, store):
        store.import_text(WG)
        before = store.profiles_file.read_bytes()
        with pytest.raises(TunnelRefusal) as refused:
            store.import_text(BAD, name="Bad")
        assert refused.value.reason == "invalid-key"
        assert store.profiles_file.read_bytes() == before
        assert store.profile_names() == ["Home Server"]

    def test_duplicate_name_refused(self, store):
        store.import_text(WG)
        with pytest.raises(TunnelRefusal):
            store.import_text(WG)

    def test_delete(self, store):
        store.import_text(WG)
        assert store.delete_profile("Home Server") is True
        assert store.profile_names() == []
        assert store.delete_profile("Home Server") is False

    def test_corrupt_profiles_file_refused_loudly_and_kept(self, store, tmp_path):
        store.data_dir.mkdir(parents=True, exist_ok=True)
        store.profiles_file.write_text("{not json", encoding="utf-8")
        with pytest.raises(TunnelStoreError):
            store.load_profiles()
        # Left exactly as found — never silently "repaired" to empty.
        assert store.profiles_file.read_text(encoding="utf-8") == "{not json"

    def test_stored_profile_that_no_longer_parses_refuses_loudly(self, store):
        store.data_dir.mkdir(parents=True, exist_ok=True)
        store.profiles_file.write_text(
            json.dumps(
                {"version": 1, "profiles": [{"name": "Bad", "config_text": BAD}]}
            ),
            encoding="utf-8",
        )
        with pytest.raises(TunnelStoreError):
            store.load_profiles()


class TestStateRecord:
    def test_round_trip(self, store):
        state = TunnelState(
            profile_name="Home Server",
            mode_before_vpn="blocker",
            with_blocker=True,
            intent=True,
            pinned_endpoint="203.0.113.7:51820",
            dns_originals=[
                {
                    "interface_alias": "Wi-Fi",
                    "family": "IPv4",
                    "servers": ["192.168.1.1"],
                }
            ],
            dns_applied=["10.8.0.1"],
        )
        store.save_state(state)
        assert store.load_state().to_dict() == state.to_dict()
        store.clear_state()
        assert store.load_state() is None

    def test_missing_state_is_none_not_an_error(self, store):
        assert store.load_state() is None

    def test_corrupt_state_refused_loudly_and_kept(self, store):
        store.data_dir.mkdir(parents=True, exist_ok=True)
        store.state_file.write_text("[1, 2", encoding="utf-8")
        with pytest.raises(TunnelStoreError):
            store.load_state()
        assert store.state_file.read_text(encoding="utf-8") == "[1, 2"

    def test_state_without_profile_name_refused(self, store):
        store.data_dir.mkdir(parents=True, exist_ok=True)
        store.state_file.write_text(
            json.dumps({"version": 1, "intent": True}), encoding="utf-8"
        )
        with pytest.raises(TunnelStoreError):
            store.load_state()

    def test_state_record_is_not_the_dns_backup(self, store, tmp_path):
        # The parallel-record rule: writing tunnel state creates
        # tunnel-state.json and NOT dns-backup.json.
        store.save_state(TunnelState(profile_name="Home Server", intent=True))
        assert store.state_file.is_file()
        assert not (store.data_dir / "dns-backup.json").exists()
