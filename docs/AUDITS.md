# Sphinx — Audit Log

Sentinel's standing cycle: build → audit → fix → re-audit. This file
is the record: what each independent audit found, what was fixed, and
what was documented-and-ignored with its reason (a finding is only
ever ignored when fixing it would break intended functionality —
never merely to make a report prettier).

---

## Debian Phase 1 audit — daemon, engage/restore guard, .deb (2026-10-21)

Scope: the Debian edition's Phase 1 as landed in a0d1a4c6 (the
`debian/**` tree, its CI workflow, and — for the docs findings —
the absence of any docs change in that commit), audited against
FILTER-SPEC and the Windows audits' inherited gates, with the
independently built alt implementation (`debian/` drop-in design)
as comparison input only. The alt design was NOT merged; the
landed mechanism was audited as it stands.

Method: full read of the landed tree; the pytest suite as baseline
(reproduced: 71 passed / 9 skipped — the skips are this sandbox's
blocked UDP loopback, which CI covers); a real .deb built locally
and its payload inspected file by file; the CI verdict for the
landed HEAD read through the API (run 39561311032, success —
suite, shellcheck, package build, payload listing); and targeted
probes beyond the suite for the link-change and symlink-swap
states below.

### Fixed

1. **MEDIUM — On the resolved stack, a moved default route read
   as ENGAGED while the live route bypassed the filter.** The
   engagement is a `resolvectl` override on the one link that
   carried the default route at engage time, and state matching
   checked only that link. Probe: engage on eth0, move the
   default route to wlan0 (never pointed) — `detect_state()`
   still returned ENGAGED, because eth0's override was intact.
   Filtering was silently off for all live traffic while every
   surface said on — the claim-of-protection failure the fleet's
   honesty rules exist to prevent. Fix: the resolved state match
   now also requires the recorded link to still be the default
   link (when a default exists); a moved route reads LEFTOVER,
   surfaced for the user's own re-engage decision. Regression
   test added. *(resolver/guard.py, tests/test_guard.py)*
2. **LOW — Restore would write over a resolv.conf that had become
   a symlink after engagement.** The direct stack engages a
   regular file (any symlink is refused at detection), but
   `disengage` never re-checked: if the file had since become
   another stack's symlink, the atomic write replaced the symlink
   itself with a regular file, retired the record, and reported
   success against a setup Sphinx no longer owned. Fix: restore
   on the direct stack refuses when the file is now a symlink,
   keeps the record, and says plainly to check the new setup and
   dismiss. Regression test added. *(resolver/guard.py,
   tests/test_guard.py)*
3. **MEDIUM — Unprivileged `sphinx status` reported a running
   daemon as not answering.** The control socket is mode 0660
   (daemon user/group + root) inside a 0755 runtime directory —
   the right security posture — but the CLI ran unprivileged by
   design, so its stats request died with EACCES, ControlClient
   collapsed that into the same "unreachable" as a dead daemon,
   and status printed "Filter: not answering (the service is not
   running)" in the same breath as "Service: running (systemd)".
   Fix: ControlClient now distinguishes permission-denied from
   unreachable, and status tells the truth in each case (running,
   counters need `sudo sphinx status`; or running but not
   answering its socket). The socket's permissions did not move.
   Regression test added. *(control.py, cli.py,
   tests/test_control.py)*
4. **MEDIUM — prerm could trap a machine into an unremovable
   package.** prerm ran `sphinx restore` unconditionally; on a
   machine whose DNS pointed at *any* loopback resolver with no
   Sphinx record (the guard's UNKNOWN state — e.g. a hand-run
   local DNS server, Sphinx installed but never engaged),
   restore correctly refuses (there is nothing Sphinx saved to
   restore), prerm exited 1, and dpkg aborted every removal —
   forever, with no path out short of reconfiguring DNS for an
   unrelated tool's sake. Fix: prerm now runs the restore only
   when a saved record file actually exists (the same gate its
   missing-binary branch already used); with a record, the law
   is unchanged — restore first, verified, or removal stops.
   Test pin added. *(packaging/prerm, tests/test_packaging.py)*

### Documented and ignored

- **The mechanism choice itself (direct rewrite + resolvectl
  runtime override) vs the alt drop-in design.** The direct path
  is symlink-safe by refusal (any symlinked resolv.conf other
  than resolved's stub pattern is refused; the write path is
  unreachable for symlinks, and restore now double-checks —
  finding 2). The resolved path's restore is `resolvectl
  revert`, and that is precisely what keeps it clear of the
  Windows Phase 1 HIGH: the record's `prior_servers` snapshot is
  effective, DHCP-flavored state, but it is kept as *information*
  (loopback-original refusal; the renewal note) and is never a
  restore target — revert returns the link to its configured /
  automatic state, so no lease address can be pinned. The
  override's volatility (no survival across reboot / link bounce
  / route change) is real, disclosed in debian/README.md, and
  every post-volatility state reads honestly as a leftover after
  finding 1's fix. Re-architecting to the drop-in mechanism is a
  product decision for the release gate, not an audit fix; the
  landed mechanism's promises, as documented, are the ones this
  audit verified. FILTER-SPEC gained a "Debian edition notes"
  section describing the landed mechanism, not the alt one.
- **FILTER-SPEC parity gap (functional, phased, disclosed).**
  The landed core has no store, no updater, and no profiles:
  the daemon runs the bundled list with an empty allowlist, so
  the installed edition cannot update its lists, cannot persist
  allowlist/custom entries, and cannot switch profiles — all
  core-spec capabilities the other editions have. debian/README.md's
  Phase 1 section already states this plainly ("No list
  updates yet… No profiles, no custom entries, no allowlist
  editing"), and FILTER-SPEC's Debian notes now carry the same
  phasing language. Recorded here as a MEDIUM functional gap,
  not a defect of what was built: it is Phase 2's named content
  (update path under the spec's HTTPS/gate/atomic/manual rules;
  stores + CLI editing; profiles parity), and inventing it
  inside an audit would be the re-architecture this audit was
  told not to perform.
- **Upgrade disengages.** prerm's restore also runs on upgrade,
  so an upgrade puts the original settings back and turns
  Sphinx off; postinst does not re-engage. Safe (never a broken
  or half-pointed machine) and now documented in
  debian/README.md; automatic re-engagement after upgrade is a
  Phase 2 / release-gate decision alongside boot resumption.
- **Hand-set `resolvectl` overrides are not restored.** Runtime
  state nothing on the machine records; disclosed in the landed
  README from the start. No honest promise exists to keep.
- **The wire-proof fallback counts its exchange.** When the
  control socket is unavailable, engage's loopback proof falls
  back to a direct sinkhole query, which the engine counts and
  logs as ordinary traffic (one query). The primary path (via
  the control socket) is uncounted and unlogged as specified;
  the fallback runs only when the daemon is up but its socket is
  not — an already-degraded state. Noted; not worth a second
  proof channel in Phase 1.
- **/var/lib/sphinx is mode 0755.** The saved record is readable
  by other local users. What it holds — the pre-engagement
  resolv.conf bytes and per-link servers — was world-readable
  resolver configuration before Sphinx engaged (resolv.conf is
  0644; `resolvectl dns` is unprivileged), and unprivileged
  status depends on reading the record to report state from real
  reads. Proportionate; left as landed.

### Verified clean (probed independently)

- **Q: can the installed daemon find its list? Yes — verified,
  not traced on paper only.** build-deb.sh copies the canonical
  Android asset into the package at
  /usr/share/sphinx/bundled-blocklist.txt with a byte-check
  (`cmp`) at build time; that path is exactly paths.py's default
  `SPHINX_LIST`. The built .deb's payload contains it
  (2,189,536 bytes), the suite's packaging test extracts the .deb
  and compares the shipped list byte-for-byte against the
  canonical asset, and the parsed count is the pinned 71,491.
  The "no copy forked into debian/" arrangement holds because
  the copy is made by the package build from the one asset, and
  the build fails loudly — never silently list-less — when the
  asset is absent. Building from a debian/-only export is
  therefore impossible by design, and says so.
- **Inherited gates re-probed, all holding:** forwarding
  validation (connected socket, source enforced by the kernel,
  ID + QR match, one 3 s deadline bounding the whole wait,
  fallback tried exactly once, truncated answers completed over
  TCP against the same deadline); bounded concurrency (one
  64-slot semaphore shared by all four listeners; refusals past
  the cap are unanswered/closed, never queued); list handling
  (the bundled list passes the ≥1,000-domain sanity gate at
  daemon start or the daemon refuses to run); the query log
  (in-memory 500-entry ring; nothing in daemon/control writes
  query names anywhere — the journal receives lifecycle lines
  only, and control stats expose counts, never names);
  manual-update-only (there is no fetch code in the edition at
  all — see the parity item above); status from real reads
  (systemd's word, the record's, the resolver's, and — after
  finding 3 — an honest account of what could not be read).
- **Unit / capability model:** the service runs as the
  dedicated `sphinx` system user (nologin, created by postinst)
  with AmbientCapabilities=CAP_NET_BIND_SERVICE and a matching
  CapabilityBoundingSet plus NoNewPrivileges — the standard
  systemd pattern for an unprivileged low-port bind; the filter
  never runs as root on any path (engage/restore run as root but
  serve no DNS). The control socket is not world-accessible
  (0660; runtime dir 0755). postinst changes no DNS and starts
  nothing; purge (not remove) deletes the state and the user.
- **Docs gap closed in this audit:** FILTER-SPEC "Debian edition
  notes" (landed mechanism, phasing, deviations), ROADMAP Debian
  Phase 1 record + Phase 2 contents, the root README's Editions
  line (was "Planned — not started"), and debian/README.md notes
  for route/link volatility, unprivileged status, and the
  record-gated prerm / upgrade behavior.

### Verification ceiling, stated plainly

As with every edition: the guard is proven on fakes, the package
in a build VM and CI, the daemon on loopback sockets. No real
Debian machine's DNS has been engaged by this code. The
real-machine pass — engage → reboot, DHCP renewal and route
change mid-engagement, install → engage → remove on Debian and
Kali/Parrot — is release-gate work, owed before this edition is
called done.

### Verdict

The landed Debian Phase 1 is a sound, honest core — the restore
discipline survived contact with two different resolver stacks,
and its restore on the resolved stack is exact in the way the
fleet's doctrine actually demands (back to configured/automatic,
never a pinned snapshot). The four fixes above were all in the
state-*reporting* and lifecycle edges, not in the discipline
itself. With the parity gap named as Phase 2's content, the
edition is ready for Phase 2 (updater + stores + profiles) and
then its release gate alongside the other editions.

---

## Windows Phase 3 audit — profiles parity and the palette HUD (2026-10-21)

Scope: the Windows edition's Phase 3 (commits ae2535c3..c9ea4f0d):
the profiles port (`core/profiles.py`, the store's profile
integration, the window's switch path), the palette
(`app/theme.py`, the tray icon's three states), and the phase's
presentation-only claim over every Phase 1–2 behavior. Plus the
build crew's flagged item: the test suite's intermittent
post-summary exit (green pytest, then a crash at interpreter
shutdown).

Method: full read of the Phase 3 diff (local tree verified
blob-identical to remote HEAD c9ea4f0d, 103 blobs; the diff itself
verified through the API to be exactly 15 files — no `dnsmgmt`
file, and no Phase 1–2 audited behavior file, appears in it; the
tray and store diffs were read hunk by hunk against their Phase 2
versions). The pytest suite as baseline (reproduced: 177 passed /
3 skipped on system Python, 187 passed / 1 skipped in the PySide6
environment). Independent probes beyond the suite: a
switch-while-running end-to-end pass against a live controller;
simulated process death injected after each individual write of
the switch sequence (and mid-rename) with byte-level comparison
of the profiles file; a death injected into the write-through
sync; garbage/duplicate/malformed profile files; an
independently implemented WCAG contrast computation and a
no-purple scan over every color the phase ships; and a
product-shaped lifecycle probe (one window, one host, engaged,
quit through the application) run repeatedly.

### Fixed

1. **LOW (test infrastructure) — The suite's post-summary crash:
   UI tests left live Qt objects behind, and shutdown destroyed
   them in arbitrary order.** The build crew flagged an
   intermittent nonzero exit after a green summary (segfault /
   abort at interpreter shutdown), correlated with window-heavy
   UI tests and latent since Phase 1–2. This audit reproduced it
   deterministically: `test_app_smoke.py` + `test_profiles_ui.py`
   together aborted 3/3 runs (glibc heap corruption reported
   after the green summary) and the full PySide6 suite crashed
   on every pre-fix attempt, while each UI file alone exited
   clean. Root cause: the smoke tests build MainWindows and
   TrayHosts and drop their references — the windows stay alive
   in Qt's registries for the rest of the process, one-second
   refresh timers armed, tray icons and menus attached. Later
   tests pump the event loop into those orphans, and interpreter
   shutdown destroys the accumulated QObjects in arbitrary
   order. **Not a product defect:** the shipped app's lifecycle —
   exactly one window and one host, held for the process's life,
   quit through the application — was probed directly and
   exited clean 5/5, engaged, with the refresh timer firing.
   Fix: an autouse fixture in `tests/conftest.py` destroys every
   top-level widget after each test (child timers stopped, tray
   context menus released, `deleteLater` with the deferred
   deletes pumped dry), so no Qt object outlives its test.
   Destruction deliberately bypasses `closeEvent` — the close
   discipline is product behavior, exercised directly by the
   tests that call it; re-entering it in teardown could raise
   message boxes mid-teardown. Evidence after the fix: the
   previously 3/3-aborting file pair is 3/3 clean; the full
   PySide6 suite ran **5 consecutive clean exits** (187 passed,
   1 skipped each); the system-Python run is unchanged
   (177 passed, 3 skipped). *(tests/conftest.py)*

### Verified clean (probed independently, not taken on the crew's word)

- **Switch integrity — the Android Phase 4 findings, re-probed.**
  A completed switch changes exactly one line of `profiles.txt`
  (the active marker); both snapshots are byte-identical before
  and after. Simulated process death after 0, 1, or 2 of the
  switch's three writes (and a death at the marker write's
  rename) leaves `profiles.txt` byte-identical and both
  snapshots whole; the live files hold at most one whole state
  per file, never a blend within a file. The discipline the crew
  claimed is the discipline the code runs: live writes with the
  write-through sync off, the marker saved from a fresh read.
- **A switch reaches the running filter completely.** With the
  controller engaged, switch + the ordinary reload: the
  incoming profile's custom entry is sinkholed by the live
  engine, its allowlist flips decisions, and the outgoing
  profile's entries leave no residue in the live lists.
- **Write-through completeness.** Grep-proved: the only callers
  of the two live-rule saves in the tree are the window's two
  editor handlers (sync on, the default) and the switch's own
  live-state write (sync off); nothing outside the store touches
  the rule files. A death injected into the sync itself degrades
  honestly: the live edit stands, the profile keeps its previous
  snapshot, nothing is half-written (single atomic profiles
  write).
- **Malformed data degrades per the rails.** Duplicate profile
  sections are first-wins; an active marker naming a missing
  profile is dropped; entries inside profiles pass through the
  shared parser rails (no single labels, no reserved names, no
  IP literals); garbage lines are ignored; a garbage profiles
  file never touches the live rules. Deleting the active
  profile clears only the marker — the live rules stay in force.
  Name rules are at parity with Android (trimmed, 1–40
  characters, no category-Cc control characters — Android's
  `isISOControl` is exactly that set).
- **Palette.** All 13 pinned text pairings re-measured with an
  independent implementation: 4.99:1–14.82:1, every one at or
  above WCAG AA 4.5:1; the stylesheet's unpinned text pairings
  (disabled text, details on panels) also pass. An independent
  no-purple scan over the theme constants and every hex literal
  in the app's UI files found no violet hues (all hues sit in
  the 3°–41° red-to-gold band). The danger red is the fleet
  standard `#e5534b`.
- **Tray icon states come from the read state.** The attention
  state is computed in the refresh from the throttled (15 s)
  real read — LEFTOVER or UNKNOWN, or running while the read
  state is not ENGAGED — never from the running flag alone; the
  status text, the throttle, and the refresh path are unmoved
  Phase 1–2 code.
- **Presentation-only, proven.** The behavior-bearing Phase 1–2
  modules (controller, host, autostart, `dnsmgmt/`, server,
  updater, validation, blocklist) are absent from the Phase 3
  diff — byte-identical. The files that did change moved only
  as claimed: `main.py` applies the stylesheet; the installer
  script changed only its version define (the two-writer
  Run-value pin still passes, unmodified); `tray_app.py` gained
  the profiles section, the palette icon states, and the
  attention computation — close-to-tray, the refused quit, and
  the refresh discipline are untouched hunks.

### Documented and ignored

- **Crash-consistency of a switch is per-file, not
  transactional — by design, and it degrades safely.** Death
  mid-switch can leave the live allowlist from the incoming
  profile beside the live custom entries from the outgoing one,
  under the outgoing marker. Nothing is corrupted, no snapshot
  is lost, and the next switch or edit restores coherence; the
  marker always names the profile whose switch last completed.
  A transactional multi-file commit would be machinery out of
  proportion to a two-file rule state whose worst case is a
  re-switch. Android has the identical property.
- **A live edit whose write-through sync dies is not rolled
  back** (probed above): the edit stands live, the profile
  keeps the older snapshot until the next successful edit.
  Same reasoning; the atomic profiles write means the failure
  can only ever lose the newest edit's sync, never data.

### CI and artifacts

- **CI and artifacts for the audited HEAD:** the fix above is
  commit `7686c51d`; the windows-latest run for it (39558932236)
  is green — suite, the real-manager read smoke, PyInstaller,
  portable assembly, installer build. The three artifacts were
  re-downloaded and re-verified locally: SHA256SUMS match;
  Sphinx.exe 50,756,462 B, a genuine x86-64 PE; SphinxSetup.exe
  52,245,519 B, a genuine Inno Setup binary; SphinxPortable.zip
  one folder (`SphinxPortable/`, with `portable.txt`) whose exe
  is byte-identical to the standalone. The suite stands at 187
  tests in the PySide6 environment, unchanged in count — the fix
  is teardown, not new tests.

### Verification ceiling, stated plainly

Everything above is VM-level: offscreen Qt, fake DNS managers,
simulated deaths. What this audit does not prove is the same set
the earlier rounds parked at the release gate, unchanged by
Phase 3: real-hardware behavior (the installer end-to-end, a
real-DHCP engage → stop → automatic restore, the two-process
instance timing, the tray on a real desktop), and the Android
edition's one real-device smoke pass. The profiles code paths
are exercised against the same store the real window drives,
but a switch clicked on a real machine, under a real engaged
filter, belongs to that same gate.

### Verdict

Phase 3 is what it claimed to be: profiles at true parity with
Android — the Phase 4 audit's corruption scenario designed out
and now independently probed shut — and a palette restyle that
moved no behavior. The one finding was in the suite, not the
product, and it is fixed with repeated-run evidence. **The
Windows edition is feature-complete: profiles, palette, tray
host, installer, and the audited filter are all landed and
audited, and it is ready to enter its release gate alongside
Android** — signed builds, published checksums, and the
real-machine proofs both editions have parked there. The
Debian edition is next per the roadmap.

---

## Windows Phase 2 audit — tray host, start-at-sign-in, installer (2026-10-21)

Scope: the Windows edition's Phase 2 (commits 660ca650..718f8c2d):
the tray-resident host, the startup decision table, the UAC
relaunch, start-at-sign-in, the installer, and a regression pass
over the Phase 1 audit's gates (which this phase inherited as law).

Method: full read of the Phase 2 diff against FILTER-SPEC and the
Phase 1 audit record (local tree verified blob-identical to remote
HEAD 718f8c2d, 97 blobs; the diff itself verified through the API
to be exactly the phase's 21 files — no `dnsmgmt` file, and no
other Phase 1 audited file, moved; the controller's only changes
are the four intent writes and the leftover dismissal moving onto
it, each inspected). The pytest suite as baseline (reproduced:
146 passed / 2 skipped on system Python, 153 passed / 1 skipped
in the PySide6 environment). A brute-force sweep of the startup
decision table (all 64 state × intent × launch × attempt ×
elevation cells, invariant-checked); headless TrayHost probes
(elevation success/decline, leftover at sign-in, resume fidelity,
failed sign-in engage); and CI's artifacts — re-verified for the
final audited HEAD below, as in the Phase 1 round.

### Fixed

1. **LOW — Two launches in the same instant could both become
   hosts.** The single-instance rule was a probe (connect to the
   running host's channel) followed by a claim (listen on it):
   two launches interleaved in that window both probed an empty
   channel, and the loser of the claim then ran on with no server
   as a full second host — a second owner of the machine's DNS
   state, the thing the one-owner design exists to prevent. The
   realistic consequences were bounded (the port-53 bind and the
   guard's backup discipline prevent dual filtering or DNS
   corruption, and each window's read-back status would show the
   fight), but the claim now retries: a failed claim is followed
   by fresh probes before the net is given up, so the loser finds
   the winner listening and becomes a "show" instead of a rival.
   The acquisition is factored into `acquire_instance`
   (app/main.py) and unit-tested with simulated races, including
   the exact lose-the-claim-then-show sequence; it was also
   exercised against real Qt local sockets (free channel →
   host; held channel → show, with the running host receiving
   the show request). *(app/main.py, tests/test_main.py)*

2. **LOW — The two writers of the sign-in value were pinned to
   nothing.** The app reads start-at-sign-in as "enabled" only
   when the stored Run value is *exactly* the command this build
   would write; the installer writes that value too, from its own
   script, in its own quoting. Had the two strings ever drifted —
   a quote, a flag, a path shape — an installer-set sign-in start
   would still have launched at sign-in while the app's checkbox
   showed it off: the status lying about the machine, the failure
   class the Phase 1 audit fixed for DNS state. They agree today;
   the agreement is now pinned by tests that derive the expected
   key path, value name, and full command string from the app's
   own constants and the frozen build's command builder, so a
   drift on either side fails the suite instead of reaching a
   user. *(tests/test_installer.py)*

### Documented and ignored

- **The per-user mechanism follows the elevated token's user.**
  The Run value (HKCU), the data folder (%LOCALAPPDATA%), and the
  intent record all belong to the account whose token the process
  holds. In the mainstream case (the user's own account, UAC
  consent) that is one person throughout. Under an
  over-the-shoulder elevation — a standard user entering a
  *different* administrator's credentials — the elevated surfaces
  would act on the administrator account's hive and data folder
  instead. That is a property of the per-user mechanism Windows
  offers, not of this implementation; changing it means a
  per-machine (HKLM) sign-in entry and a machine-wide data store,
  a product decision about who Sphinx belongs to on a shared
  machine — not an audit fix. Recorded here for the release gate
  to weigh, with the same note applying to the installer's HKCU
  entry. No behavior changed.

### Verified clean

- **The decision table, cell by cell.** All 64 combinations
  satisfy the invariants: UNKNOWN always surfaces and is never
  taken over; LEFTOVER always surfaces and waits; ENGAGE occurs
  in exactly one cell (disengaged + intent on + sign-in launch +
  elevated); RESUME only when engaged and elevated;
  `may_auto_elevate` only on a NEEDS_ADMIN from a sign-in launch
  with no attempt yet and no elevation. A manual launch never
  engages on its own, and intent plays no part in resuming an
  engagement — correctly: a machine found engaged has its DNS
  pointed at a resolver that is not answering until something
  serves again, and FILTER-SPEC's rule is resume-against-the-
  record, which the probes confirm is what happens.
- **The UAC discipline.** Probes: a sign-in NEEDS_ADMIN asks
  exactly once, with the relaunch carrying both the sign-in flag
  and the attempted marker; approval hands off (the old instance
  releases the channel and exits — the exit path in main releases
  before returning); a declined prompt leaves the host in the
  tray, off, with `needs_admin` set and protection honestly off;
  the flagged relaunched instance never asks a second time.
- **Intent is written only at successful transitions —
  grep-proved.** `set_protection_intent` is called from exactly
  four places, all in the controller: after a verified engage in
  start(), after a verified restore in stop(), after a verified
  restore in the leftover restore path, and after an actual
  dismissal. Nothing in the host, the window, or the entry point
  writes it. Pinned at failed transitions too: a failed start
  records nothing, a failed stop keeps intent on (protection is
  still on — the record tells the truth).
- **Resume never re-saves.** A fresh host over a machine left
  engaged resumes against the existing record; the backup file
  is byte-identical afterwards. A leftover at sign-in is
  surfaced untouched — no engage, no restore, the record intact
  for the user's own Restore / Dismiss. A sign-in engage that
  fails (filter cannot answer) surfaces in the window instead
  of sitting silent in the tray, and records nothing.
- **Tray lifecycle.** Closing the window hides it and stops
  nothing (probe: protection running across the close). Tray
  Quit runs the verified stop and is refused when the restore
  fails, exactly as the window's no-tray close is. The tray's
  status text is the window's read-back status, pushed on every
  refresh — never the running flag alone.
- **The single-instance channel cannot steer anything.** The
  "show" payload is discarded unread; any process that can reach
  the per-user channel can at most raise Sphinx's window, which
  shows the machine's real (read-back) state. It carries no
  commands and changes no state. That is the whole of its
  authority, assessed as proportionate for a per-user channel.
- **The headless restore.** `--restore-dns` exits 0 when nothing
  is held and when a leftover's record is restored (record
  retired, originals in force), 3 with the record kept when the
  restore fails or rights are missing — the contract the
  installer's InitializeUninstall abort depends on, which reads
  the script itself confirms: the restore runs from
  InitializeUninstall, before any file is removed, and any
  nonzero exit aborts the uninstall with a plain-language
  message. The user's data folder is left in place, as
  documented; the uninstall's Run-value removal matches the
  value the script and the app both write (fixed item 2).
- **The Phase 1 gates held.** The Phase 2 diff touches no
  `dnsmgmt` file; per-family proof, configured-not-effective
  reads, the 64-slot in-flight cap, proof hygiene, and the
  throttled (15 s) read-back status are exactly the audited
  code. The non-elevated tray toggle is a live button (the
  window's is disabled) — assessed and accepted: clicking it
  runs the normal start path, which changes nothing without
  rights and explains so in the guard's plain language, and the
  same menu carries Restart as administrator.
- **CI and artifacts for the audited HEAD:** the windows-latest
  run is green (suite, the real-manager read smoke, PyInstaller,
  portable assembly, installer build), and the three artifacts
  were downloaded and re-verified locally — SHA256SUMS match,
  Sphinx.exe a genuine PE, SphinxSetup.exe a genuine Inno Setup
  binary, the portable zip one folder with its exe byte-identical
  to the standalone. (Numbers in the closing report of this
  audit; the suite stands at 159 tests in the PySide6
  environment after the fixes.)

### Verification ceiling, stated plainly

As in the Phase 1 round: the installer is proven by compilation
in CI, by the script's pinned promises (now including the
two-writer pin), and by artifact inspection — an end-to-end
install → engage → uninstall pass on a real Windows machine
remains release-gate work, alongside the real-DHCP engage/stop
proof and the Android edition's real-device pass. The
single-instance race is proven closed at the logic level
(simulated interleavings + real-socket role checks); a timed
two-process reproduction belongs to the same real-machine pass.

### Verdict

Phase 2's hosting change kept the audited discipline intact —
the decision table is exact, intent is written only where the
crew claimed, and the host never presents a state it hasn't
read. The two findings were a race at the claim window and an
unpinned agreement between the sign-in value's two writers;
both are fixed and regression-pinned. **The Windows edition is
ready for its remaining roadmap items** — HUD polish in the
fleet's final style, and profiles parity if Skyler wants the
Android edition's profiles on Windows (the intent and store
discipline they need is already in place) — **and then the
release gate**: independent audit → fix → re-audit of the whole
edition, signed builds, published checksums, and the real-machine
proofs (installer end-to-end, DHCP engage/stop, two-process
instance timing) this audit and the last both parked there.

---

## Windows Phase 1 audit — the filter service and the DNS engagement (2026-10-21)

Scope: the Windows edition's Phase 1 (commits 69a58949..ede44dc9):
system-DNS backup/restore integrity and takeover safety,
FILTER-SPEC parity with the audited Android brain, dual-family
handling, query-log privacy, the CI artifacts (downloaded and
verified, not assumed), and a regression pass proving the Android
tree untouched.

Method: full read of the windows/ tree against FILTER-SPEC and the
Android audit record (local tree verified blob-identical to remote
HEAD ede44dc9 before starting); the pytest suite as baseline
(reproduced: 97 passed, 2 skipped on system Python — the skips are
the PySide6 smoke and the sandbox-blocked live round trip);
adversarial probes of the guard/controller/server against the fake
manager and live loopback sockets; the green CI run's artifacts
downloaded and re-verified locally (SHA256SUMS match byte-for-byte;
Sphinx.exe is a genuine x86-64 PE, 50,714,321 bytes; the portable
zip is one folder holding the exe and the portable.txt marker, its
exe identical to the standalone). Baseline suite after the fixes:
115 passed, 1 skipped (PySide6 venv; the remaining skip is the
sandbox round trip, which runs in CI).

### Fixed

1. **HIGH — Restore was not exact on DHCP machines: the
   production manager could not tell "automatic" from "static".**
   The DnsManager contract records the *configured* servers, with
   an empty list meaning "obtain DNS automatically (DHCP)".
   `WindowsDnsManager` read them with
   `Get-DnsClientServerAddress`, which reports the *effective*
   servers — on a DHCP adapter (the common case), the addresses
   DHCP handed out. So the "original" a backup recorded was a
   DHCP snapshot dressed as a static configuration, and
   disengaging pinned exactly those addresses with
   `-ServerAddresses` instead of resetting the adapter to
   automatic: stopping Sphinx silently converted the machine from
   automatic DNS to a static copy of one network's DNS — the exact
   failure the restore discipline exists to prevent, invisible to
   the whole suite because the fake honors the contract the real
   implementation couldn't. Reads now take what
   `Set-DnsClientServerAddress` itself writes: the per-interface
   `NameServer` registry value (Tcpip / Tcpip6, keyed by interface
   GUID), where absent/empty means automatic; the interpretation
   is a pure, unit-tested Python function, the contract in base.py
   now says "configured, not effective" in so many words, and a
   new CI smoke step executes the real manager's reads on
   windows-latest so the scripts are exercised on every build.
   FILTER-SPEC's Windows notes gained the configured-vs-effective
   rule for every future edition. *(dnsmgmt/windows_impl.py,
   dnsmgmt/base.py, .github/workflows/sphinx-windows.yml)*

2. **HIGH — A fresh engage could record a loopback as an
   "original."** The no-takeover refusal fired only when *every*
   adapter already pointed at a loopback. With one adapter/family
   pre-pointed at some other local resolver (another blocker, a
   local stub) and the rest normal, engage saved the backup with
   the loopback recorded as that adapter's original — and the
   eventual restore left it pointing at 127.0.0.1 with nothing
   listening: broken DNS, manufactured by the restore itself
   (probe: backup held `["127.0.0.1"]` as an original; after
   disengage the adapter sat at the dead loopback). A fresh save
   is now refused when *any* target already sits at its family's
   loopback, with the same plain-language guidance as the
   all-loopback case. *(dnsmgmt/guard.py)*

3. **MEDIUM — Engage aimed DNS at loopbacks the filter never
   bound.** The server binds IPv6 loopback best-effort, but the
   controller engaged *both* families unconditionally — on a
   machine where ::1 couldn't bind (IPv6 unavailable), IPv6 DNS
   was pointed at a resolver that isn't answering, against the
   server's own documented contract ("the DNS manager is pointed
   only at loopbacks that answer"). Engage now takes the set of
   proven loopbacks; unproven families are still recorded in the
   backup but their DNS is never moved, the result message says
   so, and state detection understands the partial engagement (a
   recorded adapter at its loopback, the rest at their recorded
   originals, is ENGAGED — not a leftover). An engagement that
   could switch nothing fails and retires its just-saved backup.
   *(dnsmgmt/guard.py, app/controller.py)*

4. **MEDIUM — Unbounded handler threads.** The threading servers
   spawned a thread per datagram/connection with no cap; every
   forwarded query can park its thread for the 3-second upstream
   wait, so a hostile or malfunctioning local app — the exact
   input this filter exists to sit in front of — grew the
   process without limit (probe: 150 datagrams → ~150 threads).
   In-flight work is now capped (64 across all listeners, the
   Android Phase 3 audit's disposition): excess UDP queries go
   unanswered, excess TCP connections are refused, and a stalled
   TCP client loses its slot after 10 s. The counters count
   processed queries, so under an extreme flood they understate
   the total stopped — stated in the server module, as in the
   Android record. Probe after the fix: thread growth exactly
   64. *(core/server.py)*

5. **MEDIUM — The window re-read the machine's DNS state every
   second.** The 1-second refresh timer ran detect_state
   unthrottled; on real Windows each detection is several
   PowerShell processes (one per adapter read), so a window meant
   to sit open all day would have burned a core on bookkeeping.
   State is now re-read at most every 15 seconds, immediately
   after any action that changes it, and failures are throttled
   the same way. The same rework closed an honesty gap: while
   running, the status used to claim "DNS points at the filter"
   from the running flag alone; if detection says the engagement
   is gone (something changed DNS underneath the filter), the
   status now says exactly that and tells the user to cycle the
   filter. *(app/tray_app.py)*

6. **LOW — The backup loader honored impossible records.** A
   corrupt or hand-edited `dns-backup.json` was applied as
   written: a pure-loopback "original" (which engage can never
   legitimately record) would be set onto a live adapter by the
   leftover Restore (probe: DNS set to 127.0.0.1, nothing
   listening), and an unknown family value crashed state
   detection with a KeyError. Entries are now validated one by
   one at load — known family, an alias, never a pure-loopback
   original — and bad entries are dropped individually instead of
   voiding (or poisoning) the whole record. *(dnsmgmt/guard.py)*

7. **LOW — The liveness proof polluted the counters and the
   query log.** Every start proved each bound loopback by running
   a real query through the engine — which counted it as an
   allowed user query and wrote `example.com` into the user's
   query log. The proof exchange is now registered by a one-shot
   token (random ID + name) and answered through the identical
   decision path with recording off: same answer, no count, no
   log entry. *(core/server.py)*

8. **LOW — Turning the query log off erased it.** The
   controller's toggle cleared the buffer, but FILTER-SPEC treats
   "off" and "clear" as separate controls (the Android edition's
   audited behavior is the same). The toggle now only stops
   recording; the Clear button is the only eraser.
   *(app/controller.py)*

9. **LOW — A timeout constant promised what the code didn't do.**
   The updater defined a 15 s connect timeout that was never
   used; urllib applies the single 30 s timeout to connect and
   reads alike. The dead constant is gone and the comment says
   what the timeout actually is. *(core/updater.py)*

### Verified clean

- **Engage/restore against the fake:** verified saves (read-back
  before any change), backups never overwritten, mid-engage
  failure rolls back and keeps the backup, failed restores keep
  the backup and are reported by name, leftover detection and
  dismissal change no settings, and the controller's close path
  refuses to close when a restore fails — all as the build
  claimed, suite- and probe-backed.
- **FILTER-SPEC parity:** parser rails (reserved names,
  single-label, IP literals), suffix matching with allowlist-wins
  (rule 5), sinkhole bytes (A→0.0.0.0, AAAA→::, TTL 60), the
  ≥1,000-domain gate counting unique domains, gated atomic
  updates with kept copies (including the Android Phase 2
  all-sources-failed fix, present here), HTTPS-only
  redirect-vetted downloads, and the forwarding discipline
  (connected socket, ID + QR validation, one overall deadline,
  fallback once, truncated answers completed over TCP) — the
  ported test suites pass against the same cases as the Android
  JVM suites, and the bundled list parses to exactly **71,491**
  domains in the Python core, pinned by test.
- **Privacy, grep-proved:** the query log has no disk or network
  path — every file write in the tree is a list, a user entry
  file, state, or the DNS backup, and every network egress is the
  forwarder (the user's own queries to the public resolvers), the
  updater (user-tapped, user-visible HTTPS sources), or the
  loopback server itself. Counters are counted at the decision,
  per the audited semantics.
- **Android untouched:** the tree diff between the audited
  Android HEAD (49d94fd4) and the audited Windows HEAD
  (ede44dc9) is exactly `windows/**`, the Windows workflow file,
  and the docs — no Android source file moved.
- **CI artifacts:** downloaded from the green run for the
  audited HEAD and verified (see Method) — checksums, PE
  validity, and the portable layout all check out; the portable
  script and the workflow assemble the same shape.

### Verification ceiling, stated plainly

PowerShell cannot run on this VM, so the corrected read path
(fixed item 1) is proven by the pure parser's unit tests, the
stubbed-runner mapping tests, and code review — and from this
audit on, by the CI smoke step executing the real reads on
windows-latest. End-to-end proof on a real Windows machine
(engage on a DHCP adapter, stop, confirm the adapter is back to
*automatic* — not pinned) belongs to the edition's release gate,
alongside the Android edition's real-device pass. Everything
guard-side — the state machine the user's networking depends on —
is fully proven here against the fake.

### Verdict

Phase 1's skeleton was honest: the fake-proven discipline was
real, and the defects were where the platform met the discipline
(the cmdlet's semantics, the unbound family, the unbounded
threads). All nine findings are fixed and re-probed; the suite
stands at 116 tests. **Windows Phase 2 (service/tray host +
installer) can build on this** — with the standing reminder that
Phase 2's host will own the same engage/restore paths, so it
inherits this audit's gates unchanged: no engagement without
proof per family, no save that could record a loopback or an
effective-DHCP snapshot, and no state the status line hasn't
actually read.

---

## Phase 4 audit — profiles, boot, notifications, battery (2026-10-20)

Scope: the boot path's three gates (opt-in, recorded intent,
consent) and every path that records intent; profile integrity
(write-through completeness, switch atomicity, deleting the active
profile); the one-time notification ask; the battery section; doc
honesty for every Phase 4 claim; and a whole-edition regression
pass over Phases 1–3.

Method: full read of the Phase 4 commits against the audited
34762898 tree (local tree verified blob-identical to remote HEAD
79f9ba13 before starting, and the 34762898→79f9ba13 tree diff shown
to be exactly the 13 Phase 4 files — nothing outside the phase
moved); the 90-test JVM suite as baseline (reproduced green;
bundled list parses to exactly 71,491); a file-level mirror of the
store's switch sequence run on the JVM with simulated process
death injected after each live-store write, before and after the
fixes; the Android layer re-type-checked against android.jar
(0 errors) after the fixes.

### Fixed

1. **A profile switch never reached the running filter's lists.**
   Switching writes the profile's allowlist and custom entries into
   the live stores, but those live only in the service's in-memory
   lists — and ACTION_RESTART rebuilt only the interface (app
   rules). The in-memory lists were reloaded at service creation
   and on ACTION_RELOAD_LISTS, never on a restart. So after
   switching profiles with the filter on, DNS kept being questioned
   with the *previous* profile's allowlist and custom entries —
   indefinitely, until an unrelated reload or a full stop/start —
   while the app announced the switch had taken. That is the
   "third, half-applied state" FILTER-SPEC's profile rules forbid:
   a real stop and start would have loaded the new state whole.
   A restart now also reloads the lists through the same background
   reload every list change uses, so a restart applies everything
   a stop and start would, for every caller. *(SphinxVpnService)*

2. **A switch could silently destroy the profile it switched
   *from*.** The live-store saves a switch performs ran the
   write-through sync — by design for edits, wrong for a switch:
   each save wrote the *incoming* state into the *outgoing*
   profile's snapshot on disk (the final save restored it from
   memory, but only if the switch ran to completion). A process
   death mid-switch left the outgoing profile's snapshot replaced
   by a partial-or-complete copy of the incoming one, still marked
   active — the user's saved profile gone, with no error anywhere,
   against the spec's "the snapshot itself is only read by a
   switch, never modified." Probed on the JVM with a faithful
   file-level mirror of the store: death after any of the three
   writes corrupted the outgoing snapshot. Now a switch's live
   writes skip the sync, and the active-marker save is computed
   from a fresh read of the untouched profiles file. Re-probed:
   the profiles file is byte-identical after a death at every
   step, both snapshots survive, the live state is at most a
   prefix of the target (each file holding one of the user's own
   states), and a clean switch is unchanged. *(ListStore)*

3. **Boot auto-start raced Android's foreground-service
   deadline.** The boot receiver is the only caller of
   startForegroundService, which gives the service a few seconds
   to call startForeground before the system kills the app
   (ForegroundServiceDidNotStartInTimeException on Android 12+) —
   but the start path waited for the first list load (up to 15 s)
   before startFilter posted the notification. At boot, with every
   app on the phone starting at once, a first parse can exceed the
   deadline: the app would crash at boot, the recorded intent
   would still say "on," and every later boot would retry the same
   path until a manual start. The start path now posts the
   foreground notification *before* waiting for the lists
   (startFilter posts it again — same ID, a no-op update), and the
   receiver's start is wrapped so a refused start is a silent
   no-op, never a crash dialog: boot failing looks exactly like
   boot not being set. *(SphinxVpnService, BootReceiver)*

4. **The battery dialog could never open.** The per-app
   exemption dialog (ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
   requires the caller to hold the
   REQUEST_IGNORE_BATTERY_OPTIMIZATIONS permission; the manifest
   never declared it, so the intent always threw and only the
   settings-list fallback ever ran — the documented primary path
   was dead. The permission is now declared (it grants nothing by
   itself: the dialog is the system's and the choice the user's).
   Release-gate note: Google Play policy restricts this
   permission — if a Play listing is ever pursued, re-decide it
   there; without the declaration the section degrades to the
   settings list, never to a broken flow. *(AndroidManifest)*

5. **The "profile switched" message overstated the off case.**
   It read "the filter now runs those rules" — also shown when the
   filter was off and nothing was running. It now reads "Sphinx
   now uses those rules," true in both states (the live stores are
   the rules in force; a running filter is restarted onto them).
   *(strings.xml)*

### Documented and ignored

- **The restart's list reload lands asynchronously.** The
  interface restarts synchronously onto the new app rules; the
  list swap completes on the reload thread moments later, under
  the same atomic-swap discipline as every list update (a query in
  the gap is answered with the previous profile's lists). The
  alternative — blocking the service's main thread on a full list
  parse — stalls the stop/start itself; the gap is the same
  eventually-consistent window ACTION_RELOAD_LISTS has always had.
- **Boot behavior when targetSdk is raised past 34** stays a
  release-gate re-examination item, as the Phase 4 crew flagged:
  foreground-service-type rules for BOOT_COMPLETED starts shift
  between Android releases. At targetSdk 34 the built path is the
  standard one; nothing about it was assumed silently.

### Verified clean

- **The intent record tells the truth on every path.** Probed by
  full code read: intent is written in exactly three places —
  set "off" when establish() fails, set "on" only once the
  interface is genuinely up, and set "off" in shutdown(), which
  every stop path runs (toggle, notification stop action,
  onRevoke, onDestroy, and the restart sequence, which then
  records "on" again from the fresh start). No path leaves intent
  "on" over a filter that is off, or "off" over one that is on.
- **The boot gates hold in order:** opt-in defaults OFF (read
  from the store, never assumed), intent honored next, consent
  last — with no consent the receiver returns having shown and
  started nothing. The receiver is exported for BOOT_COMPLETED
  only, a protected broadcast only the system can send, and it
  parses no lists and shows no UI.
- **Write-through is complete.** Every live rule-state edit path
  reaches the sync: allowlist and custom entries from the main
  screen, app rules from the picker (its own restart-on-leave
  path intact), and the switch — the one place the sync must
  *not* fire (fixed item 2) — is now the only exception, by
  explicit flag. Deleting the active profile clears only the
  marker; the live rules stay, as the spec's profile rules say.
- **The notification ask is asked once, honestly.** The marker is
  persisted *before* the system prompt shows; a refusal or
  dismissal is never re-asked, and the standing note says what is
  missing (the shade status only) and where to change it. Before
  Android 13 the flow is a no-op and the hint never appears; if
  the permission is already granted, no prompt and no hint.
- **Battery handling never forces anything.** Status is read live
  from the platform on every resume; the button offers the
  system's own dialog (fixed item 4) and falls back to the
  settings list; the app changes no setting itself.
- **Regression:** the Phase 4 tree diff against the audited Phase
  3 tree is exactly the phase's 13 files; the full JVM suite
  passes after the fixes (90/90), including the sinkhole layout,
  update atomicity, and attribution suites; the Android layer
  type-checks clean against android.jar. The store/service fixes
  are verified by the JVM mirror probe, type-check, and code
  re-read — the same ceiling prior audits worked to on this VM
  (no instrumented Android runtime here).

---

## Phase 3 audit — per-app rules and custom entries (2026-10-20)

Scope: the two-capture-mode routing model (the phase's new
packet-path surface, flagged for its own pass by the Phase 2 audit),
mode transitions, drop attribution, custom block entries,
permissions and privacy, doc honesty, and a regression pass over
Phases 1–2.

Method: full read of the Phase 3 commits against the audited
8e0ee1f6 tree (local tree verified blob-identical to remote HEAD
1e3e6f66 before starting); the 78-test JVM suite as baseline
(reproduced green); 33 additional adversarial probes (hostile and
truncated IpFlow packets plus a 20,000-case fuzz, AppRules conflict
orderings both directions, DropCounts under 8-thread concurrency,
custom-entry composition through the store's union path); the
Android layer re-type-checked against android.jar.

### Fixed

1. **The packet workers' queue was unbounded.** The pool behind the
   TUN reader was a fixed thread pool with an unbounded queue. In
   filter mode the input is throttled by design (only DNS packets
   to one address arrive), but app-block mode queues *every* packet
   a blocked app sends — and a blocked app is by definition one the
   user doesn't trust with the network. A flood (or a port scan,
   where nearly every packet is an attribution cache miss costing a
   platform lookup) grows the queue — each entry holding a packet
   copy — faster than four workers drain it, until the system kills
   the service and the filter with it. The pool now sits behind a
   bounded queue (512) with refuse-on-full: in app-block mode a
   refused packet is still dropped, never forwarded; in filter mode
   the query goes unanswered and the asker retries, as on an
   upstream timeout. The counters count packets actually processed,
   so under an extreme flood the drop counts understate the total
   stopped — bounded memory wins over exact bookkeeping in a flood.
   *(SphinxVpnService)*

2. **Attribution cache entries never expired.** The flow→app cache
   keys on protocol, addresses, and ports; in app-block mode every
   blocked app shares the same tunnel source addresses, so the key
   is effectively ports + destination. Ephemeral ports are reused
   after a connection closes, so a permanent entry could attribute
   one blocked app's packets to another that held the same flow
   earlier — a guess wearing a fact's clothes, against the spec's
   "unattributed, never guessed at." Entries now expire after 60
   seconds and the platform is asked again; an unanswered re-ask
   lands in the unattributed bucket. *(SphinxVpnService)*

3. **A restart that did nothing still claimed stickiness.**
   ACTION_RESTART on a stopped filter returned START_STICKY. The
   picker only sends it while the filter runs, but if the race ever
   landed, the sticky-but-idle service would later be resurrected by
   the system with a null intent — which the start path reads as
   "start the filter," switching protection on by itself after a
   crash while the user believes it is off. A restart that changes
   nothing now returns START_NOT_STICKY. *(SphinxVpnService)*

4. **A refused per-app rule could crash the start path.** Adding a
   package to the interface caught only NameNotFoundException; any
   other refusal from addAllowedApplication /
   addDisallowedApplication would have propagated out of the start
   path and crashed the service. Both loops now shrug off any
   refusal per package: the rule matches nothing, and if that leaves
   an app-block population empty, the existing fallback to filter
   mode catches it — a bad rule degrades the mode, it never crashes
   the start. *(SphinxVpnService)*

### Documented and ignored

- **AppRules' package shape is a hair stricter than the platform's
  edge cases.** Rule names must be dot-separated labels starting
  with a letter — the shape Android's build tools enforce for every
  normally installed app. Legacy or hand-built packages with an
  underscore-leading label segment (not producible through normal
  install channels) would be refused a rule, silently. Widening the
  shape is a product decision about which names are rules at all;
  the practical exposure is nil. Ignored on purpose.
- **The drop counters count processed drops.** Under a flood past
  the bounded queue (fixed item 1), excess packets are discarded at
  enqueue — dropped in every sense that matters, but not
  individually counted. Stated here and in the code, rather than
  pretending the number is exact under attack.

### Verified clean

- **Filter mode is the audited Phase 1/2 interface.** Diffed
  against the Phase 2 builder: identical addresses, route, DNS
  server, MTU, and session when no app is blocked; with exemptions,
  the only change is addDisallowedApplication per exempted package.
  handlePacket, the forwarding discipline, and the shutdown path
  are untouched by Phase 3.
- **App-block mode drops everything, for the named apps only.**
  The population is exactly the successfully-added blocked
  packages; default routes on both families draw all of a blocked
  app's traffic in — DNS on any port, DoT (853), DoH (443), TCP and
  UDP alike — and the reader's single code path drops every packet
  it reads, unconditionally. No other app's traffic enters the
  interface.
- **The empty-population trap is closed.** When every blocked app
  is uninstalled, buildInterface returns null and the service falls
  back to filter mode; no default-route interface with an empty
  allowlist can be established. A partially uninstalled set still
  blocks the apps that remain.
- **Attribution never guesses.** IpFlow returns ports 0 for
  fragments past the first, extension-header chains, and non-port
  protocols — all of which skip the owner lookup and land in the
  unattributed bucket; platform lookup failures do the same.
  20,000 fuzzed packets produced no exception.
- **Custom entries enter through one door only.** Grepped every
  construction and entry path: the UI validates with
  normalizeEntry, the store saves through normalizeEntry and loads
  through parseEntries, and the effective blocklist is a union of
  parsed sets. The allowlist still wins over custom entries
  (probed through FilterLists).
- **QUERY_ALL_PACKAGES is used for the picker, only.** Package
  enumeration exists nowhere else; the picker lists only apps that
  request INTERNET, excludes Sphinx itself, and stores nothing but
  the rules the user picked. Drop counters and the query log have
  no disk or network path (the only persisted log state is its
  on/off switch).
- **The app-block trade is disclosed everywhere the crew claimed:**
  README's honest-limits list ("It can't run the gate both ways at
  once"), FILTER-SPEC's "Per-app rules," the ROADMAP Phase 3 entry,
  and the in-app explainer on the main screen. Nothing presents
  app-block mode as filtering-plus.
- **Regression:** files outside the Phase 3 diff are byte-identical
  to the audited Phase 2 tree; the full JVM suite passes (78/78),
  including the sinkhole byte layout, upstream validation, and
  update-atomicity tests. The service-layer fixes above are
  verified by kotlinc type-check against android.jar plus code
  re-read — the same ceiling prior audits worked to on this VM
  (no instrumented Android runtime here).



---

## Phase 2 audit — blocklist engine (2026-10-20)

Scope: list parsing, remote updates and the atomic swap, the
allowlist, the query log's privacy, doc honesty, and performance —
plus a regression pass over Phase 1 behavior.

Method: full code read of the Phase 2 commits; the 48-test JVM suite
as baseline; 18 additional adversarial probes (hostile list content,
gate gaming, malformed allowlist storage, concurrent log recording,
the real 71,491-domain bundled list).

### Fixed

1. **An all-sources-failed update still recorded success.**
   If every download failed but the previous copies on disk passed
   the combined sanity gate, the updater reported success and
   advanced the "last updated" time — while downloading nothing.
   That broke the spec's "a failed update changes nothing" and made
   the status line lie. Now an update in which no source refreshed
   is a failed update: nothing is written, nothing is recorded.
   *(ListUpdater)*

2. **Downloads trusted the platform to refuse HTTP downgrades.**
   List fetches followed redirects automatically. "Sources are HTTPS
   only" has to hold for every hop — a downgrade to plain HTTP would
   let anyone on the network path substitute a different real-shaped
   list. Whether the platform refuses such a redirect varies by
   version, so the updater now follows redirects by hand (at most 5)
   and checks every hop through the new
   `ListValidation.redirectTarget`, which resolves the target and
   accepts only HTTPS. Regression-tested in the JVM suite.

3. **Two write paths could leave a torn file.** The downloaded-list
   writer fell back to copying straight over the target when its
   rename failed (a crash mid-copy leaves half a file — and a
   half-written list can still pass the sanity gate as a silently
   weaker list), and the allowlist was written with a plain
   non-atomic write. Both now go through one write path:
   temp file → rename; on rename failure, a second staged file is
   renamed instead; if that fails too, the old file stays.
   *(ListStore)*

4. **Allowlist entries bypassed the parser's safety rails.**
   The UI and the store validated entries with plain normalization,
   which accepts single labels and reserved names the loader then
   silently drops — an entry could look "added" and do nothing.
   Entry validation now lives in one place,
   `Blocklist.normalizeEntry` (normalization + single-label +
   reserved-name rails), used by the parser, the store, and the UI,
   so an unusable entry is refused where it is typed.
   Regression-tested in the JVM suite.

### Documented and ignored

- **Underscore/IDN names are skipped by the parser.** The strict
  domain shape drops names with underscores or non-ASCII labels.
  Exactly one such name exists in the bundled 71,492-domain source
  list; the effect is under-blocking (an ad domain not blocked),
  never over-blocking. Loosening the shape would admit junk tokens
  from error pages and malformed lines. Ignored on purpose.
- **`*.` means the bare name, per spec.** Some upstream engines read
  a wildcard entry as "subdomains only"; FILTER-SPEC defines it as
  the bare name (which blocks the name and its subdomains). The
  behavior matches this product's own spec, stated in the open.
- **The `Blocklist(entries)` constructor normalizes but does not
  apply the parsing rails** — by design: the rails are a *parsing*
  rule (FILTER-SPEC, "Safety rails while parsing"), and every
  production construction path goes through the parser or unions of
  parsed sets. Any future entry path (e.g. Phase 3 custom block
  entries) must enter through `Blocklist.normalizeEntry` or
  `parseEntries`, never by constructing around them.
- **Two-label public suffixes (e.g. `co.uk`) are permitted.** The
  spec's over-blocking rail is single-label entries only; no bundled
  or default remote list contains a public-suffix entry. Changing
  the rail would be a spec change, not a fix.
- **Turning the query log off takes effect on the service's next
  list reload (sent immediately by the UI)** — a sub-second window,
  and "recording off" deliberately does not erase the existing
  buffer; clearing is its own control, per spec.
- **A worst-case 300-label query name costs ~1 ms to walk.** Such a
  name cannot arrive from the wire (DNS caps names at 255 bytes,
  enforced by the Phase 1 parser), and realistic names are 2–4
  labels (microseconds). No fix warranted.

### Verified clean

- Parser never crashes on hostile input (1M-char lines, control
  characters, wildcard edge cases, duplicate floods, IPv6 literals)
  and never produces single-label/TLD-level entries; the sanity gate
  counts *unique* domains, so duplicate floods can't game it.
- The bundled list parses to exactly **71,491** domains — the number
  the README prints (the source list's own header counts 71,492;
  the parser intentionally drops one underscore name).
- The query log is memory-only: no code path writes it to disk,
  logs it, or transmits it; the 500-entry ring holds under
  concurrent recording.
- Phase 1 behavior (forwarding validation, sinkhole responses,
  service lifecycle) untouched by Phase 2 and by these fixes.

