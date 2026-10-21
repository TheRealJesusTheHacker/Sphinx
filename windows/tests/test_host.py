"""The tray host's startup discipline (app/host.py): the decision
table over real DNS state, recorded intent, launch kind, and
elevation — pure logic, proven without a desktop."""
import sys

import pytest

from sphinx_win.app.host import (
    LaunchOptions,
    StartupAction,
    instance_name,
    parse_launch_args,
    plan_startup,
    relaunch_args,
    relaunch_command,
    relaunch_elevated,
)
from sphinx_win.dnsmgmt.guard import DnsState


def plan(state, **kw):
    defaults = dict(
        intent_on=False, autostart_launch=False,
        elevated_attempted=False, elevated=True,
    )
    defaults.update(kw)
    return plan_startup(state, **defaults)


class TestPlanTable:
    def test_unknown_is_never_taken_over(self):
        for kw in ({}, {"intent_on": True, "autostart_launch": True}):
            p = plan(DnsState.UNKNOWN, **kw)
            assert p.action is StartupAction.SURFACE_UNKNOWN
            assert not p.may_auto_elevate

    def test_leftover_waits_for_the_user(self):
        p = plan(DnsState.LEFTOVER, intent_on=True, autostart_launch=True)
        assert p.action is StartupAction.SURFACE_LEFTOVER
        assert not p.may_auto_elevate

    def test_engaged_resumes_when_elevated(self):
        p = plan(DnsState.ENGAGED)
        assert p.action is StartupAction.RESUME

    def test_engaged_unelevated_needs_admin(self):
        p = plan(DnsState.ENGAGED, elevated=False, autostart_launch=True)
        assert p.action is StartupAction.NEEDS_ADMIN
        assert p.may_auto_elevate  # sign-in launch, no attempt yet

    def test_engaged_unelevated_manual_launch_waits(self):
        p = plan(DnsState.ENGAGED, elevated=False)
        assert p.action is StartupAction.NEEDS_ADMIN
        assert not p.may_auto_elevate  # by hand: no surprise prompt

    def test_no_second_elevation_attempt(self):
        p = plan(
            DnsState.ENGAGED, elevated=False, autostart_launch=True,
            elevated_attempted=True,
        )
        assert p.action is StartupAction.NEEDS_ADMIN
        assert not p.may_auto_elevate

    def test_disengaged_autostart_with_intent_engages(self):
        p = plan(DnsState.DISENGAGED, intent_on=True, autostart_launch=True)
        assert p.action is StartupAction.ENGAGE

    def test_disengaged_autostart_with_intent_unelevated(self):
        p = plan(
            DnsState.DISENGAGED, intent_on=True, autostart_launch=True,
            elevated=False,
        )
        assert p.action is StartupAction.NEEDS_ADMIN
        assert p.may_auto_elevate

    def test_disengaged_manual_launch_never_auto_engages(self):
        p = plan(DnsState.DISENGAGED, intent_on=True)
        assert p.action is StartupAction.IDLE

    def test_disengaged_no_intent_is_idle(self):
        p = plan(DnsState.DISENGAGED, autostart_launch=True)
        assert p.action is StartupAction.IDLE


class TestLaunchArgs:
    def test_parse(self):
        opts = parse_launch_args(["--autostart", "-platform", "x"])
        assert opts.autostart and not opts.restore_dns
        assert parse_launch_args(["--restore-dns"]).restore_dns
        assert parse_launch_args([]) == LaunchOptions()

    def test_relaunch_args_keep_the_launch_and_mark_the_attempt(self):
        args = relaunch_args(LaunchOptions(autostart=True))
        assert "--autostart" in args and "--elevated-attempted" in args
        args = relaunch_args(LaunchOptions())
        assert args == ["--elevated-attempted"]

    def test_relaunch_command_reproduces_the_launch_shape(self):
        program, params = relaunch_command(["--autostart"])
        assert program == sys.executable
        if not getattr(sys, "frozen", False):
            assert "-m sphinx_win.app.main" in params
        assert "--autostart" in params

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows would prompt")
    def test_relaunch_elevated_is_false_off_windows(self):
        assert relaunch_elevated(["--autostart"]) is False


class TestInstanceName:
    def test_one_host_per_user(self):
        assert instance_name("skyler") == "Sphinx-skyler"
        assert instance_name("a b\\c") == "Sphinx-a-b-c"
        assert instance_name("") == "Sphinx-user"
