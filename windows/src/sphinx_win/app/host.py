"""The tray host's startup discipline — pure decisions, no Qt.

Phase 2 hosts the filter in a tray-resident process (see
windows/README.md for why that shape). When the host process
starts, exactly one thing must be decided: what, if anything, to
do about protection — and that decision is a table over facts,
kept here where it can be tested without a desktop:

- the machine's real DNS state, read through the guard
  (``DnsState`` — never the desired state);
- the recorded protection intent (the controller writes it at
  every successful start/stop; it is the Android edition's intent
  discipline, mirrored);
- whether this launch came from sign-in autostart or by hand;
- whether this process has administrator rights.

The table:

- UNKNOWN (DNS is loopback, no record): never take over settings
  Sphinx cannot restore. Surface it; do nothing automatic.
- LEFTOVER (a record exists, DNS is not engaged): surface it for
  the user's own Restore / Dismiss decision. Never auto-engage
  over a leftover and never silently re-point DNS at sign-in.
- ENGAGED (DNS still points at the filter, with a record): the
  machine was left mid-engagement — almost always a reboot while
  protection was on. Nothing is listening yet, so DNS is pointed
  at a dead resolver until the host serves again: resume through
  the normal start path, which re-proves the loopbacks and
  re-engages *against the existing record* (engage never re-saves
  over a record). Resuming needs admin; without it, the answer is
  NEEDS_ADMIN, not a half-start — starting the server alone would
  leave the machine's settings unverified and the state unowned.
- DISENGAGED + intent on + autostart launch: resume protection
  fresh (the user opted into sign-in start, and protection was on
  when they last left it). Needs admin (NEEDS_ADMIN without it).
- DISENGAGED otherwise: idle. A manual launch never engages on
  its own; intent alone, without the autostart launch, changes
  nothing automatically.

Elevation: a per-user sign-in program cannot silently elevate —
Windows does not allow it, and Sphinx does not pretend otherwise.
When an *autostart* launch lands on NEEDS_ADMIN and no elevation
has been attempted yet, the shell may ask once, via the standard
UAC prompt (a "runas" relaunch of this same command); the plan
flags that with ``may_auto_elevate``. The relaunched instance
carries ``--elevated-attempted`` so a declined or failed prompt is
never retried in a loop: the host then waits in the tray, stating
plainly that protection needs administrator rights to resume, with
a manual "Restart as administrator" action.
"""
from __future__ import annotations

import getpass
import sys
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Sequence

from ..dnsmgmt.guard import DnsState
from .autostart import AUTOSTART_FLAG


def instance_name(username: Optional[str] = None) -> str:
    """The single-instance channel name: one host per user, so two
    users on one machine never block each other's Sphinx, and one
    user's second launch always finds their own host."""
    user = username if username is not None else getpass.getuser()
    safe = "".join(c if c.isalnum() else "-" for c in user) or "user"
    return f"Sphinx-{safe}"

ELEVATED_ATTEMPTED_FLAG = "--elevated-attempted"
RESTORE_DNS_FLAG = "--restore-dns"
RESTORE_VPN_FLAG = "--restore-vpn"


@dataclass(frozen=True)
class LaunchOptions:
    autostart: bool = False
    elevated_attempted: bool = False
    restore_dns: bool = False
    restore_vpn: bool = False


def parse_launch_args(argv: Sequence[str]) -> LaunchOptions:
    """Scan raw argv for the host's own flags. A manual scan, not
    argparse: the frozen exe also receives Qt's arguments, which a
    strict parser would reject — unknown arguments are ignored."""
    args = set(argv)
    return LaunchOptions(
        autostart=AUTOSTART_FLAG in args,
        elevated_attempted=ELEVATED_ATTEMPTED_FLAG in args,
        restore_dns=RESTORE_DNS_FLAG in args,
        restore_vpn=RESTORE_VPN_FLAG in args,
    )


class StartupAction(Enum):
    IDLE = "idle"  # nothing automatic; the tray reports off
    ENGAGE = "engage"  # start protection fresh via the normal path
    RESUME = "resume"  # re-serve an engagement the machine still shows
    NEEDS_ADMIN = "needs_admin"  # protection should resume, rights are missing
    SURFACE_LEFTOVER = "surface_leftover"  # user's Restore/Dismiss call
    SURFACE_UNKNOWN = "surface_unknown"  # loopback DNS, no record: warn only


@dataclass(frozen=True)
class StartupPlan:
    action: StartupAction
    reason: str
    #: For NEEDS_ADMIN from an autostart launch with no attempt yet:
    #: the shell may put up the one UAC prompt before settling.
    may_auto_elevate: bool = False


def plan_startup(
    state: DnsState,
    *,
    intent_on: bool,
    autostart_launch: bool,
    elevated_attempted: bool,
    elevated: bool,
) -> StartupPlan:
    if state is DnsState.UNKNOWN:
        return StartupPlan(
            StartupAction.SURFACE_UNKNOWN,
            "DNS points at a loopback resolver Sphinx has no record "
            "of; Sphinx will not take over settings it cannot restore.",
        )
    if state is DnsState.LEFTOVER:
        return StartupPlan(
            StartupAction.SURFACE_LEFTOVER,
            "Saved DNS settings from an earlier run are waiting for "
            "the user's Restore or Dismiss.",
        )
    if state is DnsState.ENGAGED:
        if elevated:
            return StartupPlan(
                StartupAction.RESUME,
                "DNS still points at Sphinx from before this start; "
                "resuming the filter against the saved settings.",
            )
        return StartupPlan(
            StartupAction.NEEDS_ADMIN,
            "DNS still points at Sphinx from before this start, but "
            "resuming (or restoring) needs administrator rights.",
            may_auto_elevate=autostart_launch and not elevated_attempted,
        )
    # DISENGAGED: the only automatic start is the sign-in resume of
    # a protection the user left on and opted to restart.
    if intent_on and autostart_launch:
        if elevated:
            return StartupPlan(
                StartupAction.ENGAGE,
                "Protection was on and start-at-sign-in is enabled; "
                "resuming protection.",
            )
        return StartupPlan(
            StartupAction.NEEDS_ADMIN,
            "Protection was on and start-at-sign-in is enabled, but "
            "turning DNS over to Sphinx needs administrator rights.",
            may_auto_elevate=not elevated_attempted,
        )
    return StartupPlan(
        StartupAction.IDLE,
        "Protection is off; nothing to resume.",
    )


def relaunch_args(launch: LaunchOptions) -> List[str]:
    """Arguments for the elevated relaunch of this process: the
    same launch, plus the attempted marker that prevents loops."""
    args: List[str] = []
    if launch.autostart:
        args.append(AUTOSTART_FLAG)
    args.append(ELEVATED_ATTEMPTED_FLAG)
    return args


def relaunch_command(args: Sequence[str]):
    """The (program, parameters) pair that reproduces this launch:
    the frozen exe stands alone; a from-source launch needs its
    ``-m sphinx_win.app.main`` to start the same program."""
    if getattr(sys, "frozen", False):
        prefix: List[str] = []
    else:
        prefix = ["-m", "sphinx_win.app.main"]
    params = " ".join(
        f'"{a}"' if " " in a else a for a in [*prefix, *args]
    )
    return sys.executable, params


def relaunch_elevated(args: Sequence[str]) -> bool:
    """Ask Windows to relaunch this program elevated (the UAC
    prompt) with ``args``. True when the elevated process was
    launched; False when the user declined, the OS refused, or
    this is not Windows. The caller exits its own instance on True
    so exactly one host owns the machine."""
    if sys.platform != "win32":
        return False
    import ctypes

    program, params = relaunch_command(args)
    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", program, params, None, 1  # SW_SHOWNORMAL
        )
    except Exception:
        return False
    return result > 32  # ShellExecuteW returns >32 on success
