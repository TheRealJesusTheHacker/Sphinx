# Sphinx — Windows edition (SPHINX.EXE)

The Windows edition of Sphinx: the same filtering brain as every
edition (the shared rules in [../docs/FILTER-SPEC.md](../docs/FILTER-SPEC.md)),
running as a local DNS filter on this machine.

**Status: Phase 3 — profiles parity and the Sphinx palette,
landed.** Phase 1's filter, list engine, system-DNS engagement
with its restore discipline, and plain functional window exist
and passed an independent audit (see
[../docs/AUDITS.md](../docs/AUDITS.md)). Phase 2 hosts all of it in
a system-tray process so the filter no longer needs the window open,
adds an opt-in start-at-sign-in under the recorded-intent
discipline, and ships an installer alongside the portable edition.
Phase 3 adds profiles at parity with the Android edition — named
snapshots of your allowlist and your own block entries — and
restyles the window and tray in Sphinx's own palette (basalt,
sandstone, bronze-gold). What does *not* exist yet: a background
Windows *service* (Phase 2's host is a tray process — the section
below says why, plainly). This edition first shipped as **v0.3.0 in
Sphinx v1.0.0 (2026-10-23)**; the current release is **v0.3.1
in Sphinx v1.0.1 (2026-10-23)**, carrying the W-1–W-7
restore-discipline fixes and the R-17 installer branding. Both
releases passed the release gate in the roadmap (independent
audit → fix → re-audit, CI builds on the released commit,
published checksums verified by re-download). The real-machine
install → engage → uninstall pass named in the release notes
is still owed — v1.0.1 states that just as plainly, and this
README won't pretend otherwise.

## How it works

- Sphinx listens for DNS queries on the loopback addresses —
  **127.0.0.1 and ::1**, port 53. (Both families: Windows consults
  IPv6 DNS servers in parallel with IPv4 ones, so an IPv4-only
  listener would leave a bypass lane open.)
- When you turn it on, Sphinx points the DNS settings of the
  adapters that carry your connections (up, with a default route)
  at those loopbacks — per family, and only where the filter has
  first proved it answers: if it cannot listen on a family's
  loopback, that family's DNS is left exactly as it was and the
  result says so. Blocked names get the spec's sinkhole answer
  (0.0.0.0 / ::, TTL 60); allowed queries are forwarded unchanged
  along the spec's upstream chain — 1.1.1.1, then 9.9.9.9, then
  this machine's own DNS servers, captured when Sphinx was turned
  on, as the chain's floor — under the spec's answer-validation
  rules: connected socket, matching ID, response bit, a 3-second
  deadline per resolver, truncated answers completed over TCP.
  The floor is what keeps an allowed name answerable on a network
  where the public resolvers cannot be reached (an ISP that
  intercepts outside DNS, a filtered port 53, a captive portal):
  the chain degrades toward the network's own resolution, never
  toward silence, and the resolver that last answered is tried
  first on the next question.
- Everything runs on this machine. There is no Sphinx server, no
  account, and the query log never leaves memory.

## The restore discipline (read this — it's the point)

Changing a machine's DNS can break its networking, so Sphinx treats
the original settings the way Charon treats its restore point:

1. **Administrator rights are required** to change DNS. Without
   them, Sphinx says so plainly and changes nothing.
2. Before anything changes, the current settings of every adapter
   it will touch are **saved to `dns-backup.json` in the data
   folder — and read back to prove the save is real.** No verified
   save, no change. What gets saved is your *configured* settings,
   read from the configuration itself: "automatic (DHCP)" is
   recorded as automatic — never as a snapshot of whatever
   addresses DHCP happened to hand out, which a restore would
   otherwise pin in place as if you had set them by hand.
3. An existing backup is **never overwritten**: if one is on disk,
   its recorded settings are the truth, so a loopback address can
   never be recorded as an "original."
4. Every change is verified by reading the adapter back. A failure
   midway rolls back the adapters already changed.
5. Turning Sphinx off (or closing its window) restores the recorded
   settings **exactly** — including "automatic (DHCP)" where that
   was the original state — verifies each one, and only then
   deletes the backup. If a restore can't be verified, the filter
   stays running (a working resolver beats a dead one) and the
   window says what failed.
6. If Sphinx starts and finds a backup whose settings are no longer
   in force (a crash, a hand edit), that is shown as its own state —
   with Restore and Dismiss offered — never silently treated as
   "on," and DNS that points at a loopback Sphinx has no record of
   is never taken over, because it could not be restored honestly.

Before DNS is pointed at the filter, the filter must prove it
answers on each loopback it bound; before that proof, nothing about
the machine's DNS changes.

## The tray host, start-at-sign-in, and the installer (Phase 2)

**The host is a tray process, not a Windows service — on purpose.**
One process owns the window, the tray icon, the filter, and the
DNS engagement, so the saved-settings record the discipline above
depends on has exactly one owner, in one session, under the
user's own account; nothing about it has to cross a process
boundary. A separate service would split that ownership (a SYSTEM
service holding state the per-user UI must somehow share) for the
one benefit of prompting-free elevation — and the cost of that
benefit is stated below rather than hidden. Closing the window
sends it to the tray and stops *nothing*; the tray menu shows the
real status (read from the machine, not assumed), opens the
window, turns the filter on or off, and its **Quit** is what stops
Sphinx — running the same verified stop as Phase 1's close did (a
failed restore refuses the quit, in the tray as at the window).
Starting Sphinx a second time doesn't start a rival host: it asks
the running one to show its window. On a desktop with no system
tray, the window is the app again and Phase 1's close discipline
applies unchanged.

**Start-at-sign-in** uses the standard per-user Run entry — the
same one value whether the installer's option or the app's own
"Start Sphinx when I sign in" checkbox wrote it (off by default;
the checkbox always shows the value actually in the registry). A
sign-in start resumes protection only under the recorded-intent
discipline the Android edition uses: Sphinx records your intent at
every successful turn-on, turn-off, and leftover resolution, and
at sign-in it resumes only if protection was on — passing the same
prove-it-answers-first engagement as a manual start. If the
machine is found still engaged (a restart while protection was
on), the host resumes against the *existing* saved record; a
leftover or an unrecognized loopback DNS is surfaced for your own
decision, never handled silently.

The one friction, stated plainly: resuming means changing DNS,
which needs administrator rights, and a program that starts at
sign-in cannot silently grant itself those rights. So on a sign-in
start that needs to resume, Sphinx asks once, through the standard
Windows prompt. Approve it and protection is back; decline it and
Sphinx waits in the tray, off, saying exactly that — with a
"Restart as administrator" action in the window and the tray menu
whenever you want it.

**The installer** (`SphinxSetup.exe`, built by CI from
`packaging/Sphinx.iss`) installs the same one-file exe the
portable edition carries — the two editions behave identically;
the installer just adds the Start-menu entry, the optional sign-in
option, and an uninstaller. Uninstalling is part of the restore
discipline: before removing anything, the uninstaller runs
`Sphinx.exe --restore-dns`, which puts back the saved settings and
retires the record only when the restore verifies; **if the
restore cannot be verified, the uninstall stops and explains,
rather than leave the machine pointing at a filter that no longer
exists.** The sign-in entry is removed; your data folder
(lists, entries, settings) is left in place — removing the app
must not quietly delete your data. Stated ceiling: the installer
is compiled and its script pinned by tests in CI, but an
install → engage → uninstall pass on a real machine has not
happened yet — v1.0.0 shipped with that pass named in its
release notes as still owed, alongside the other real-Windows
proofs, and this README won't pretend otherwise.

## Profiles (Phase 3)

The same profile mechanism as the Android edition
([../docs/FILTER-SPEC.md](../docs/FILTER-SPEC.md), "Profiles"),
over the rule state Windows has: a profile captures **your
allowlist and your own block entries** under a name. The
blocklists and their sources are *not* part of a profile — every
profile questions with the same lists, so switching profiles can
never become a disguised list change, and a list update never
disturbs a profile. The disciplines are the audited ones: while
a profile is active, edits in the two editors are written
through to it, so it never silently drifts from the rules in
force; switching writes the saved state into the live stores
and applies it whole to the running filter, leaving the profile
you switched *from* exactly as it was; deleting a profile
removes only the saved copy — the rules in force stay as they
are — and a damaged profiles file degrades to the profiles that
still read, never to wiped rules.

## The Sphinx palette

Sphinx's identity, on every edition and surface: **basalt black,
sandstone, bronze-gold** — the stone guardian in the desert. The
values live in `src/sphinx_win/app/theme.py` (with every text
pairing held at WCAG 4.5:1 or better by the test suite) and are
recorded here so the Android polish and any future Toolkit card
inherit the same identity:

- Basalt black `#0f0d0a` (window), weathered stone `#171310`
  (panels), raised stone `#211a12` (inputs, buttons)
- Sandstone text `#ece0c6`, worn sandstone `#b3a284` (secondary)
- Bronze-gold `#cf9a3e` (the accent), polished bronze `#eac987`
  (bright detail), aged bronze `#6e521f` (primary actions)
- Danger red `#e5534b` — the fleet's standard value, for the
  states that genuinely need you, and nothing else

No purple: that exception belongs to Beerus alone. The tray icon
follows the machine's real state in the palette — dulled bronze
while off, bronze-gold while on, red when something needs your
decision (saved settings waiting, or DNS no longer pointing at a
running filter).

## Lists

The same brain-data as the Android edition: the bundled StevenBlack
unified list (**71,491 domains**, the identical file), the same two
default sources, the same gates — HTTPS only, every redirect hop
vetted, a download must parse to at least 1,000 domains, the
combined replacement set must pass the same gate, swaps are atomic,
a failed update changes nothing, and updates happen **only when you
tap the button**. The allowlist always wins; your own block entries
live in their own file where list updates never touch them.

## Running from source

```
cd windows
pip install -r requirements.txt
python -m sphinx_win.app.main        # with src/ on PYTHONPATH
```

(Set `PYTHONPATH=src`, or `pip install -e` style usage — the test
suite's `tests/conftest.py` shows the path setup.) Tests:
`pip install -r requirements-dev.txt`, then `python -m pytest`.

Data directory: `%LOCALAPPDATA%\Sphinx` for an installed/frozen
build; a `portable.txt` beside a frozen exe switches to `.\data`
next to the exe (the portable edition); `SPHINX_DATA_DIR` overrides
both; from source, `~/.sphinx`.

## Building

`packaging/build-portable.ps1` produces `dist\Sphinx.exe` (one
file), `dist\SphinxPortable.zip`, and — when Inno Setup is
installed — `dist\SphinxSetup.exe` (from `packaging/Sphinx.iss`),
with `dist\SHA256SUMS.txt` over all of them. The GitHub Actions
workflow `.github/workflows/sphinx-windows.yml` runs the tests and
all three builds on windows-latest for every change under
`windows/` — that workflow is the edition's build gate.

## Honest limits, Windows edition

- Same-domain ads (YouTube / YouTube Music) cannot be blocked at
  the DNS layer — the spec's standing honesty rule, unchanged.
- Apps that do their own encrypted DNS (DNS-over-HTTPS inside the
  app) never ask the system resolver, so Sphinx never sees those
  queries — same as every edition.
- Phase 1 filters the adapters that carry a default route at the
  moment you turn it on. Switching networks (a new Wi-Fi, a VPN
  client connecting later) after that can put new adapters outside
  the engagement; turning Sphinx off and on re-engages against the
  adapters then in force. The status line always shows the real
  state.
- Resuming protection after a restart needs one approval of the
  standard administrator prompt when Sphinx starts at sign-in (see
  the Phase 2 section above). Declining it leaves protection off —
  never silently half-on — until you start Sphinx as administrator.
- Per-app rules remain an Android-edition feature (they ride on
  Android's per-app VPN routing). Profiles (Phase 3) cover the
  rule state Windows has — the allowlist and your own entries.
