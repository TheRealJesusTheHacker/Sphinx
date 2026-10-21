"""The daemon's configuration discipline: spec defaults, honest
overrides, and the hard rule that an upstream on this machine is
refused (it would loop questions back into a local resolver)."""
import pytest

from sphinx_deb.daemon import ConfigError, DaemonConfig


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
