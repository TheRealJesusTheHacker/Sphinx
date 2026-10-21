# Sphinx — Audit Log

Sentinel's standing cycle: build → audit → fix → re-audit. This file
is the record: what each independent audit found, what was fixed, and
what was documented-and-ignored with its reason (a finding is only
ever ignored when fixing it would break intended functionality —
never merely to make a report prettier).

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

