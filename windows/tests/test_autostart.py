"""Start-at-sign-in policy (app/autostart.py): one Run value, an
honest definition of "enabled", idempotent sync — proven against a
dict-backed registry stand-in."""
from sphinx_win.app.autostart import (
    RUN_VALUE_NAME,
    AutostartManager,
    autostart_command,
)


class DictRegistry:
    def __init__(self):
        self.values = {}

    def get_value(self, name):
        return self.values.get(name)

    def set_value(self, name, value):
        self.values[name] = value

    def delete_value(self, name):
        self.values.pop(name, None)


COMMAND = '"C:\\Apps\\Sphinx.exe" --autostart'


def manager(registry):
    return AutostartManager(registry, command=COMMAND)


class TestAutostartManager:
    def test_enable_disable_round_trip(self):
        registry = DictRegistry()
        m = manager(registry)
        assert not m.is_enabled()
        m.enable()
        assert registry.values[RUN_VALUE_NAME] == COMMAND
        assert m.is_enabled()
        m.disable()
        assert not m.is_enabled()
        m.disable()  # idempotent
        assert not m.is_enabled()

    def test_a_value_pointing_elsewhere_is_not_enabled(self):
        registry = DictRegistry()
        registry.values[RUN_VALUE_NAME] = '"C:\\Old\\Sphinx.exe" --autostart'
        m = manager(registry)
        assert not m.is_enabled()  # a stale path is not this build's start

    def test_sync_rewrites_a_stale_value(self):
        registry = DictRegistry()
        registry.values[RUN_VALUE_NAME] = '"C:\\Old\\Sphinx.exe" --autostart'
        m = manager(registry)
        assert m.sync(True) is True
        assert registry.values[RUN_VALUE_NAME] == COMMAND

    def test_sync_off_removes_and_reports_truthfully(self):
        registry = DictRegistry()
        m = manager(registry)
        m.enable()
        assert m.sync(False) is False
        assert RUN_VALUE_NAME not in registry.values
        assert m.sync(False) is False  # already off: still off, no error

    def test_default_command_is_the_current_launch(self):
        command = autostart_command()
        assert "--autostart" in command
        assert "sphinx_win.app.main" in command or "Sphinx" in command
