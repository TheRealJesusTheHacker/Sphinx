"""The production OpenVPN manager's pure parts, testable
anywhere: the executable search's honest absence, Sphinx's
controlled command line, and the log parsers that turn the
client's own words into establishment proof and the pushed DNS
set. Actually supervising a client on a real Windows machine
with OpenVPN installed is a named release gate."""
from pathlib import Path

from sphinx_win.tunnelmgmt import openvpn_windows_impl as oi


class TestDiscovery:
    def test_missing_client_is_the_honest_state(self, monkeypatch):
        monkeypatch.setenv("SPHINX_OPENVPN_EXE", "/nonexistent/openvpn.exe")
        monkeypatch.setattr(oi.shutil, "which", lambda name: None)
        monkeypatch.setattr(oi, "_PROGRAM_FILES_CANDIDATES", ())
        manager = oi.WindowsOpenVpnManager()
        ok, reason = manager.availability()
        assert not ok
        assert "OpenVPN isn't installed" in reason
        assert "openvpn.net" in reason
        assert manager.status().adapter_up is False
        assert manager.pushed_dns() == []
        assert manager.process_id is None

    def test_status_without_a_child_is_down_not_connected(self):
        manager = oi.WindowsOpenVpnManager(exe_path=Path("/nonexistent/x"))
        status = manager.status()
        assert status.adapter_up is False
        assert status.exited_unexpectedly is False


class TestCommandLine:
    def test_every_flag_is_sphinxs_own(self, tmp_path):
        command = oi.build_command(
            Path("openvpn.exe"), tmp_path / "c.ovpn", 49321,
            tmp_path / "c.log",
        )
        assert command[0] == "openvpn.exe"
        assert "--config" in command
        # Scripts are forbidden at the client's own level, on top
        # of the sanitizer: even a surviving directive cannot run.
        i = command.index("--script-security")
        assert command[i + 1] == "0"
        # The management endpoint is Sphinx's, on loopback.
        i = command.index("--management")
        assert command[i + 1] == "127.0.0.1"
        assert command[i + 2] == "49321"


class TestLogProofs:
    def test_pushed_dns_parsed_in_order_deduplicated(self):
        log = (
            "PUSH: Received control message: 'PUSH_REPLY,"
            "dhcp-option DNS 10.8.0.53,dhcp-option DNS 10.8.0.54,"
            "redirect-gateway def1'\n"
            "dhcp-option DNS 10.8.0.53\n"
        )
        assert oi.parse_pushed_dns(log) == ["10.8.0.53", "10.8.0.54"]
        assert oi.parse_pushed_dns("") == []

    def test_establishment_proof_is_the_clients_own_words(self):
        assert oi.log_proves_established(
            "...\nInitialization Sequence Completed\n"
        )
        assert not oi.log_proves_established("AUTH: Received message")
