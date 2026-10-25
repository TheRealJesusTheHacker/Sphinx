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
restore-discipline fixes and the R-17 installer branding.
**Landed on `main` after v1.0.1, not yet in a release: VPN
mode Phases 1–2** ([../docs/TUNNEL-SPEC.md](../docs/TUNNEL-SPEC.md)) —
WireGuard server profiles, the four-mode model, and the kill
switch (Phase 1), plus OpenVPN connections through the user's
own installed OpenVPN program and the VPN Gate public-nodes
directory (Phase 2), in the "VPN mode" section below. Both
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
  to 1.1.1.1 (fallback 9.9.9.9) under the spec's answer-validation
  rules — connected socket, matching ID, response bit, a 3-second
  deadline per resolver — with truncated answers completed over TCP.
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

## VPN mode (TUNNEL-SPEC Phases 1–2 — WireGuard + OpenVPN)

The shared tunnel spec ([../docs/TUNNEL-SPEC.md](../docs/TUNNEL-SPEC.md))
adds a real VPN mode beside the blocker. The four modes, as the
window and tray state them: **Off**, **Blocker only** (the
behavior above, untouched), **VPN only**, and **VPN + Blocker**.

> In VPN mode, your traffic passes through the server you choose —
> that's how a VPN works. Sphinx ships no servers of its own in
> your list; a profile is a server you added or one your provider
> gave you.

- **The server list starts empty.** No bundled servers, no sample
  locations, no mock entries — ever. The picker's first-run state
  is an honest "No servers yet — add one from a config file or
  paste a config your provider gave you." Servers are added by
  importing a standard WireGuard `.conf` or an OpenVPN `.ovpn`
  (both connect — WireGuard since Phase 1, OpenVPN since
  Phase 2, below). The separate "Public volunteer servers"
  directory is not part of this list: it lives in its own
  section of the window, is fetched only when you open it, and
  is covered under its own heading below.
  Import validates against the shared corpus
  (`docs/tunnel-corpus.json`, which the test suite reads
  directly): bad keys, an endpoint with no port, bad CIDRs, and a
  missing server key are each refused with the reason named, and
  a refused import stores nothing. Round-trip is lossless —
  unknown lines and comments survive parse → export exactly.
- **A filter, not a wall** (the owner's standing criterion): in
  Blocker and VPN + Blocker, Sphinx's only action is the DNS
  decision — listed names get the sinkhole answer, built locally
  and immediately, and **every unlisted name resolves normally
  and its traffic passes untouched**, including names that merely
  look tracker-adjacent. The unlisted path keeps the forwarder's
  honest fallback discipline end to end: an unlisted name fails
  only when every upstream genuinely fails, never because an
  internal error swallowed the query. The suite proves this with
  named conformance tests
  (`tests/test_questions_names_conformance.py`): an unlisted
  name resolves **and** its traffic passes on the blocker path
  and on the VPN + Blocker path, a blocked name sinkholes fast
  even behind a dead upstream, and a dead first upstream is
  survived via the fallback. The only blocking anywhere in a
  tunnel mode beyond DNS decisions is the kill switch, below.
- **How the modes wire DNS.** VPN + Blocker: the local filter
  runs exactly as in Blocker only (system DNS at loopback, under
  the audited DNS backup), and its forwarder's upstreams become
  the profile's DNS servers, reached through the tunnel. VPN
  only: the filter does not run and DNS is **unfiltered — the UI
  says so where the mode is offered**; when the profile names DNS
  servers, the machine's DNS is pointed at them as *tunnel-record*
  state (saved first into `tunnel-state.json` in the data folder,
  verified, and restored exactly) — the DNS guard's backup
  contract is never rewritten for the tunnel's sake; the two
  records are parallel. A profile with no DNS field leaves system
  DNS as it was, reached through the tunnel, and claims nothing
  else. A split-tunnel profile (allowed IPs narrower than
  everything) is labeled "some traffic" at the picker.
- **Endpoint pinning.** A hostname endpoint is resolved *before*
  the tunnel engages, with the pre-tunnel resolver, and that
  answer is pinned for the session; the tunnel never re-resolves
  its own doorway from inside itself. The server's identity is
  the profile's pinned public key: a machine at the endpoint
  presenting a different key cannot complete a WireGuard
  handshake — and since Sphinx claims "connected" **only** from
  a fresh handshake reported by the backend (never from intent,
  configuration, or a process running), a wrong-key server shows
  as the disconnect state below, never as connected.
- **Kill switch.** While VPN intent is armed, a tunnel that
  drops **blackholes the traffic it covers** — the adapter and
  its routes stay, nothing falls back to the direct route — and
  the status says so in plain words: *"VPN disconnected —
  traffic is blocked, not going around the tunnel,"* with the
  two visible choices, **Reconnect** or **Disconnect**
  (disconnect returns to the mode you had before the VPN,
  through the ordinary stop path: tunnel down first, then the
  DNS restore). No silent full-block state exists in any mode,
  and no mode transition strands the machine without the UI
  saying so.
- **Elevation, plainly.** Connecting, disconnecting, and
  reconnecting change adapters and routes, so they need
  administrator rights. Without them the Connect button is
  disabled and the window says why: Windows asks once with its
  standard prompt when Sphinx is restarted as administrator; if
  you decline, the VPN stays off and Sphinx does not ask again
  in a loop. Nothing about a tunnel change is ever attempted
  unelevated.
- **Records and resumption.** The profile store
  (`vpn-profiles.json`) and the tunnel state record
  (`tunnel-state.json`: mode, profile, intent, the pinned
  endpoint, and any DNS originals a VPN-only session must
  restore) live in the per-user data folder under the same
  atomic-write discipline as every Sphinx store; a corrupt
  record is refused loudly and left exactly as found — never
  silently degraded to "empty" or "off." Private keys live only
  inside a profile's config text in that folder and are never
  logged. A record found at startup with no live tunnel is a
  *leftover*: it is surfaced for your own reconnect/disconnect
  decision — tunnel resume-by-re-proof at sign-in is **not**
  wired in Phase 1 (protection resume above is the blocker's);
  the record waits for you rather than taking anything over.
  Locally created profiles get their keypair on this device,
  from a vetted Curve25519 means only (the official `wg`
  tooling when present, else the `cryptography` library's
  X25519) — Sphinx never hand-rolls key material, and when no
  vetted means exists it says so instead of inventing one;
  importing a provider config works regardless, since the
  config carries its key.

### The WireGuard route — evaluated, with the license evidence

The ownership model decided the shape before licensing did: one
tray-resident process owns the window, the tray, the filter, and
the DNS guard state, so the tunnel has exactly one owner too.
Two routes were evaluated against that model and the spec's
license honesty rule (every component is **bundled** or
**invoked**, stated plainly):

**(a) EMBED WireGuardNT — CHOSEN (bundled).** The tray process
hosts the tunnel through the official WireGuardNT distribution:
it loads `wireguard.dll` at runtime and drives it through the
Permitted API of `wireguard.h` (`WireGuardCreateAdapter`,
`WireGuardSetConfiguration`, `WireGuardSetAdapterState`,
`WireGuardGetConfiguration`), programming the adapter's
addresses and the profile's routes through Windows' own
networking cmdlets. Terms, verified from the primary sources on
2026-10-23 — not assumed:

- `wintun.net` states Wintun's source is GPLv2, but "the
  prebuilt signed DLLs are released under a more permissive
  license than GPLv2," included in the zip. The actual text
  inside `wintun-0.14.1.zip` is WireGuard LLC's **Prebuilt
  Binaries License**: no modification, no reverse engineering,
  no removing notices, no use of the WireGuard/Wintun names to
  endorse — and redistribution is prohibited **except** "insofar
  as the Software is distributed alongside other software that
  uses the Software only via the Permitted API."
- The wireguard-nt distribution (`wireguard-nt-1.0.zip` from
  `download.wireguard.com`) carries the **same Prebuilt Binaries
  License** for `wireguard.dll`, with the same redistribution
  carve-out for software using only the `wireguard.h` API. Its
  own README's deployment model is exactly this: "Install the
  `wireguard.dll` file side-by-side with your application."
- So the obligations are: ship the DLL **unmodified**, use it
  only via its published API, ship its license text with it,
  and never call it MIT (Sphinx's own code is MIT; the DLL is
  WireGuard LLC's, under its own terms). The installer and
  portable editions ship `packaging/third-party/wireguard.dll`
  (the distribution's `bin/amd64` file, SHA-256
  `40add3d0…eca7`, pinned by the test suite) beside
  `WireGuardNT-LICENSE.txt`; `packaging/third-party/PROVENANCE.md`
  records the distribution, its hash, and this reasoning.
- **`wintun.dll` is not bundled**: WireGuardNT is a kernel
  implementation and does not use Wintun (which serves
  userspace implementations). Bundling an unused DLL would
  misstate what runs. Its terms check out for the same model
  if a future userspace backend ever needs it.

**(b) SUPERVISE the official WireGuard for Windows tunnel
service — not chosen (would have been invoked).** Sphinx would
write a config and install/control a named tunnel service
through the official tooling; the user would first have to
install WireGuard for Windows (a separate GPLv2 program —
arm's length, so the license story stays clean). It loses on
ownership and honesty-of-experience: a second program owns the
tunnel state Sphinx must report truthfully (handshake freshness
becomes someone else's process to interrogate), the install is
a dependency with a real UX cost ("install this other program
first"), and uninstall interplay runs both ways — removing
WireGuard for Windows would strand Sphinx's VPN, removing
Sphinx must not strand theirs. The embed route has none of
those, and its license terms (above) are expressly written for
this use.

### OpenVPN (Phase 2) — the route, evaluated

OpenVPN on Windows is a program the user installs; there is no
embeddable component to bundle the way WireGuardNT bundles.
Two routes were evaluated against the same ownership model as
Phase 1 (one tray-resident process owns the tunnel and its
state):

**(a) SUPERVISE the installed `openvpn.exe` as a child process
— CHOSEN (invoked).** Sphinx writes a sanitized config (below),
launches the installed client as its own child with its own
controlled flags only (its own loopback management endpoint,
`--script-security 0`, its own log capture), and owns the
lifecycle and the state. Routes and the TAP/Wintun adapter
need elevation, which fits the edition's existing UAC story
unchanged: the child inherits the elevation the user already
approved for Sphinx itself. "Connected" is proven the same
way as WireGuard's — never from the process having spawned:
the management interface must report CONNECTED/SUCCESS (the
client's "Initialization Sequence Completed" log line is the
fallback proof), and the status reads that proof, fresh, every
time it is asked.

**(b) Drive the official OpenVPNService / interactive service
— not chosen.** That service is a *second owner* of tunnel
state: it would hold the connection, its lifecycle, and its
own idea of "connected," and Sphinx would be interrogating
another program to report its own status truthfully — the
argument that rejected route (b) for WireGuard in Phase 1.
Teardown would split the same way (uninstall and quit
negotiating with a service Sphinx does not own). Route (a) is
workable, so (b) was not taken.

One WireGuard discipline does not translate literally, and
the difference is stated rather than papered over: a
WireGuard endpoint is resolved by Sphinx and pinned before
engagement (the backend takes only an address). An OpenVPN
config's `remote` is resolved by the OpenVPN client itself at
startup — before its routes exist, i.e. still on the
pre-tunnel network — and the server's certificate validation
is tied to that name, so Sphinx leaves `remote` as written in
the (sanitized) config and claims no pin of its own.

**Licensing — invoked, never bundled.** The OpenVPN community
client is GPLv2. Sphinx bundles nothing, links nothing, ships
no copy, and never downloads or installs one for you: it runs
*your* installed OpenVPN (the community installer or OpenVPN
Connect, from openvpn.net) at arm's length as a separate
process, which does not attach its license to Sphinx (MIT).
If OpenVPN isn't installed, connecting an OpenVPN profile says
exactly that and names the remedy — *"OpenVPN isn't installed
on this machine… Install OpenVPN yourself — the community
installer or OpenVPN Connect, from openvpn.net"* — never a
silent failure.

**Config sanitization — a stranger's config runs nothing.**
An OpenVPN config can do far more than describe a tunnel:
several directives make the client run programs, load
plugins, or hand itself to a control socket. So the text the
client runs is never the stored text. At connect time Sphinx
sanitizes a working copy — the stored profile is never edited
— removing, by name: `up`, `down`, `route-up`,
`route-pre-down`, `plugin`, `script-security`, `management`
(and every `management-*`), `iproute`, `tls-verify`,
`auth-user-pass` *when it names a file* (the bare interactive
form stays), `cd`, `chroot`, `daemon`, `writepid`, `status`,
`log`, `log-append`, and the other script-running directives
(`learn-address`, `client-connect`, `client-disconnect`). The
removals are named in the connect output and in the session's
status, and recorded in the tunnel record — no silent edits.
Sphinx's own flags are the only flags: even a directive that
somehow survived could not run, because the client is launched
with `--script-security 0`.

**DNS honesty for OpenVPN.** An OpenVPN server *pushes* DNS.
In VPN + Blocker the brain stays in front: the pushed set
becomes the filter's upstream set, reached through the tunnel,
and the status says so. In VPN only, the pushed set is
accepted as the server's DNS — applied as tunnel-record state
under the same save-first / verify / restore-exactly
discipline as everything else (the DNS guard's backup is never
touched) — and the status says whose DNS is in force. A server
that pushes no DNS gets no invented DNS: the status states
that the machine's existing DNS is in force. No DNS change
rides outside the tunnel record, and nothing is silent.

**Kill switch — the level actually achieved, stated plainly.**
This is **not** the WireGuardNT blackhole level, and this
README does not claim it is. `openvpn.exe` removes its own
routes when it exits, so if the child dies unexpectedly Sphinx
cannot blackhole routes it no longer owns. What Sphinx does
hold, it holds completely: it *notices* (the tray polls the
tunnel status; an unexpected exit is the next status read),
nothing is silently restored — your DNS stays exactly where
Sphinx placed it for the tunnel (the filter's loopback, or the
server's pushed set under the tunnel record), in the blocked
posture — and the status announces the state in plain words
("VPN disconnected — the OpenVPN program exited
unexpectedly…") with the two visible choices, **Reconnect** or
**Disconnect** (disconnect restores everything, exactly,
through the ordinary path). The posture is announced or it
does not exist: there is no silent unwrap to a direct
connection, and no silent full-block either — the held DNS is
the tunnel's own, and the state names itself.

### Public volunteer servers (the VPN Gate directory)

The window's VPN area has a separate section — its own box,
its own words — titled **Public volunteer servers**, visually
and verbally distinct from your own profiles. It is **never
pre-enabled**: nothing is fetched, loaded, or shown until you
press "Show public volunteer servers," on purpose. The list
comes from VPN Gate's published feed
(`https://www.vpngate.net/api/iphone/` — HTTPS only,
size-capped, timeout-bounded), fetched **at use time**: the
list churns hourly, so no snapshot is bundled, ever. A cached
copy may be shown when a fresh fetch fails, with its age
labeled ("List from cache — fetched 2 hours ago"); a dead
feed with no cache is an honest empty state ("Couldn't fetch
the list — check your connection"), never last week's servers
dressed as today's. Each row becomes an ordinary OpenVPN
connection choice labeled **"Public volunteer server —
\<Country\> (\<host\>)"**; connecting it runs the same
sanitizer, engine, mode model, and kill-switch posture as any
OpenVPN profile.

The disclosure ships at the point of use — in the section
itself **and again in the connect confirmation**, in these
words:

> These are strangers' machines, volunteered to a research
> project (VPN Gate, University of Tsukuba). The operator can
> see your traffic. VPN Gate states its servers keep
> connection logs — your real address, the times, the server
> you used — for three months or more. Fine for appearing to
> be somewhere else; not for anything sensitive.

A directory without that warning in those places does not
ship; the test suite pins its presence in both.

**Scope, honestly (Phases 1–2).** WireGuard profiles connect
(Phase 1); OpenVPN profiles — yours and the directory's —
connect through your installed OpenVPN (Phase 2). And the
real-machine boundary, stated as plainly as everywhere else
in this README: the mode model, the corpus, the sanitizer,
the feed parser and cache discipline, the store discipline,
and the config-blob layout are proven by the suite
(315 passed / 6 skipped in the dev environment, 338 passed /
2 skipped with Qt present — against the 277 passed / 5
skipped Phase 1 close and the 195 passed / 4 skipped pre-VPN
baseline; the Qt UI modules are among the skips wherever
PySide6 is absent and run in CI and in a Qt-complete
environment), but bringing a real adapter up on a real Windows
machine — a WireGuard handshake against a live server, an
OpenVPN session through a real installed client against a
real server (a VPN Gate node included), routes in force,
kill-switch behavior under a pulled cable — has **not**
happened yet and is a release gate, not a claim this section
makes. The OpenVPN supervisor's management-interface proof
path in particular is exercised only against the suite's fake
and its log parsers until that pass happens.

**Uninstalling with the tunnel up.** The uninstaller's first
act — before the DNS restore, before any file is removed — is
`Sphinx.exe --restore-vpn`: the tunnel session is torn down and
exactly what its record holds is restored and verified (a
running tray host's own quit disconnects the VPN first; the
uninstaller closes applications before it runs). For an
OpenVPN session the record also names the supervised
`openvpn.exe` child's pid, and the teardown ends exactly that
recorded process — never a stranger's — before the DNS
restore. If the teardown cannot be verified, the uninstall
**aborts with a plain explanation**, exactly the DNS
discipline.

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
pip install --require-hashes -r requirements.lock.txt
python -m sphinx_win.app.main        # with src/ on PYTHONPATH
```

(Set `PYTHONPATH=src`, or `pip install -e` style usage — the test
suite's `tests/conftest.py` shows the path setup.) Tests:
`pip install --require-hashes -r requirements-dev.lock.txt`, then `python -m pytest`.

Dependencies install from hash locks, not the ranges: the
`requirements*.txt` files name the ranges this edition accepts, and
the sibling `requirements*.lock.txt` files freeze one resolution of
them with a SHA-256 for every artifact (`--require-hashes` makes
pip fail loudly if a download does not match). Regenerate a lock
with the pip-compile command in its header and run the full suite
on any intentional bump — never edit a hash by hand. (The dev
lock's header also documents its one hand-added entry:
PyInstaller's Windows-only dependencies, which a Linux pip-compile
cannot see.)

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
