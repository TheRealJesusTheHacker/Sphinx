"""Sanitization of OpenVPN configs Sphinx did not write
(TUNNEL-SPEC, Phase 2 — the security-critical rule).

A server config — a provider's file, and above all a row from the
VPN Gate public feed — is a stranger's text. OpenVPN configs can
do far more than describe a tunnel: several directives make the
client RUN programs or scripts, move its working state around,
or hand control to a management socket. A config Sphinx connects
must therefore never reach ``openvpn.exe`` as written. Sphinx
sanitizes its own working copy before the client ever sees it:

- Every directive that runs, loads, or persists code — or hands
  the client to something that could — is REMOVED, by name, from
  the copy Sphinx runs. The stored profile is never edited: the
  lossless record stays exactly what the user imported; the
  sanitized text is a per-connect working copy.
- ``auth-user-pass`` is removed ONLY when it names a file (the
  bare form, which asks the user interactively, stays): what is
  stripped is the pointer at a file on the user's machine.
- Removals are never silent. The result carries the removed
  directive names, in order, and the caller surfaces them in the
  connect output and the session status. A sanitization with
  removals reads, in the UI, as exactly what happened: "Sphinx
  removed these lines from the server's config before
  connecting: …".
- Sphinx runs the client with its OWN controlled flags (see
  tunnelmgmt's OpenVPN implementation: its own management
  endpoint, ``--script-security 0``). Stranger text gets no say
  in how the client process itself behaves.

Inline blocks (``<ca>`` … ``</ca>`` and friends) are data, not
directives: their contents pass through untouched, even when a
line inside a block starts with a dangerous word.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

#: Directives removed unconditionally, by name. Each one either
#: executes something (up/down/route-up/route-pre-down run shell
#: commands; plugin loads a library; learn-address runs a script;
#: tls-verify runs a command), hands the client away (management
#: opens a control socket; iproute replaces the route helper),
#: changes where the client runs or persists state (cd, chroot,
#: daemon, writepid, status, log, log-append), or arms the
#: mechanism the others need (script-security). The test suite
#: pins this list so it can only change on purpose.
DANGEROUS_DIRECTIVES = (
    "up",
    "down",
    "route-up",
    "route-pre-down",
    "plugin",
    "script-security",
    "management",
    "iproute",
    "tls-verify",
    "cd",
    "chroot",
    "daemon",
    "writepid",
    "status",
    "log",
    "log-append",
    "learn-address",
    "client-connect",
    "client-disconnect",
    "auth-token-user",  # server-side token naming; never a client need
)

#: Directives removed only in a dangerous form: ``auth-user-pass``
#: with an argument reads credentials from a file on the user's
#: machine; the bare directive (an interactive prompt) is the
#: user's own choice and stays.
FILE_ARGUMENT_DIRECTIVES = ("auth-user-pass",)

#: Management sub-directives (management-hold, management-forget,
#: …) ride the same control socket; the whole family goes.
_MANAGEMENT_PREFIX = "management"


@dataclass
class SanitizedConfig:
    """The working copy plus the honest record of what changed."""

    text: str
    #: (directive name) for each removed line, in file order.
    removed: List[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.removed)

    def removal_summary(self) -> str:
        """The sentence the UI shows — no silent edits, ever."""
        if not self.removed:
            return (
                "Sphinx checked the server's config before "
                "connecting: nothing in it had to be removed."
            )
        names = ", ".join(self.removed)
        return (
            "Sphinx removed these lines from the server's config "
            f"before connecting, because a config must not run "
            f"anything on your machine: {names}. The saved profile "
            "itself was not edited."
        )


def _directive_of(line: str) -> Tuple[str, List[str]]:
    """The (directive, args) of one config line. A leading ``--``
    (command-line style sometimes pasted into files) is accepted;
    comments and blanks have no directive."""
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", ";")):
        return "", []
    if stripped.startswith("--"):
        stripped = stripped[2:]
    parts = stripped.split()
    if not parts:
        return "", []
    return parts[0].lower(), parts[1:]


def is_dangerous(directive: str, args: List[str]) -> bool:
    if not directive:
        return False
    if directive in DANGEROUS_DIRECTIVES:
        return True
    if directive.startswith(_MANAGEMENT_PREFIX):
        # management itself and every management-* sub-directive.
        return True
    if directive in FILE_ARGUMENT_DIRECTIVES:
        return len(args) >= 1
    return False


def sanitize_openvpn_config(text: str) -> SanitizedConfig:
    """Return the sanitized working copy of ``text``.

    Pure and total: any text goes in, a runnable-without-code-
    execution copy comes out, and every removal is named in the
    result. The input is never mutated (strings are immutable,
    but the point stands for the stored profile: this function
    is the ONLY transformation, and it makes a new text)."""
    out_lines: List[str] = []
    removed: List[str] = []
    in_block = False
    for line in text.split("\n"):
        stripped = line.strip()
        if in_block:
            out_lines.append(line)
            if stripped.startswith("</") and stripped.endswith(">"):
                in_block = False
            continue
        if (
            stripped.startswith("<")
            and stripped.endswith(">")
            and not stripped.startswith("</")
            and not stripped.startswith("<connection")
        ):
            # An inline data block (<ca>, <cert>, <key>, <tls-auth>,
            # …): its body is data, passed through untouched.
            in_block = True
            out_lines.append(line)
            continue
        directive, args = _directive_of(line)
        if is_dangerous(directive, args):
            removed.append(directive)
            continue
        out_lines.append(line)
    return SanitizedConfig(text="\n".join(out_lines), removed=removed)
