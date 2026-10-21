# Sphinx — Roadmap

Tagline: *Every request gets questioned.*

Sphinx is one product line with multiple editions in this repo — the
Argus precedent: one repo, several platform editions, one brain. Every
edition implements the shared rules in [FILTER-SPEC.md](FILTER-SPEC.md):
DNS queries are matched against a blocklist, blocked names get a
sinkhole answer, allowed queries are forwarded to an upstream resolver.
No root/admin tricks beyond what each platform normally requires, no
remote VPN server, and filtering always happens on the user's own
device.

Editions in build order: **Android** first, then **Windows**, then
**Debian/Linux**, then further platforms as feasible.

---

## Edition 1 — Android

System-wide ad & tracker blocking (apps + browser) through a local
VpnService: the app creates a TUN interface on the phone, intercepts DNS
queries, sinks the ones that match a blocklist, and forwards the rest.
Traffic never leaves the phone.

### Android Phase 1 — Core DNS filter (this build)

- VpnService that establishes the TUN interface and routes only the
  virtual DNS server address through it, so the app sees DNS traffic and
  nothing else.
- IPv4 packet parsing; DNS query parsing (pure Kotlin, JVM-testable).
- Blocklist matching: exact + subdomain (listing `example.com` blocks
  `ads.example.com` too).
- Blocked names get a sinkhole answer (0.0.0.0 / ::). Allowed queries
  are forwarded to an upstream resolver (1.1.1.1, fallback 9.9.9.9)
  over UDP and the real answer is written back.
- Minimal UI: start/stop toggle, blocked/allowed counters, foreground
  service notification.
- Small starter blocklist bundled with the app.
- JVM unit tests for DNS parsing and blocklist matching.
- The DNS parsing and blocklist core is kept fully platform-neutral
  (pure Kotlin, no Android APIs) — it is the reference implementation
  of the shared spec.

Known Phase 1 limits (stated in the README too): IPv4 only; counters
reset when the service stops; the starter list is small and static.

### Android Phase 2 — Blocklist engine (landed)

- **A substantial bundled list** replaces the Phase 1 starter:
  the StevenBlack unified hosts file (ads + malware), **71,491
  domains** as one bundled asset. (The plan said "multiple bundled
  starter lists"; one large curated list plus two remote sources
  turned out to be the same coverage with less to go stale.)
- **Remote list updates:** HTTPS fetch from user-visible,
  user-editable sources — defaults are StevenBlack (hosts format)
  and HaGeZi Multi LIGHT (wildcard/plain format); the parser handles
  both shapes, plus IPv6 hosts lines. Every download is parsed and
  sanity-checked (≥1,000 domains) and the combined set must pass the
  same gate before anything on disk changes; each file swaps in by
  temp-file-and-rename, a failed source keeps its previous copy, and
  a failed update changes nothing. The running filter switches to
  the new lists only once they are complete. Manual "Update lists
  now" only — no background fetching. Last-updated time and the
  active domain count are shown in the app.
- **User allowlist** (never block these names): editable in the app,
  persisted on the phone, wins over the blocklist per FILTER-SPEC
  rule 5. *Custom block entries* (the other half of the original
  Phase 2 line) move to Phase 3, alongside per-app rules — the
  allowlist covers Phase 2's "a site broke, unblock it" need.
- **Query log:** what was asked, blocked or allowed, when — a
  500-entry ring buffer held **in memory only**, viewable and
  clearable in the app, never written to disk, never transmitted.
  Recording is on by default (stated in the README) with an off
  switch in the app.

Measured on the build machine's JVM (kotlinc + JUnit harness):
parsing the bundled 71,491-domain list takes ~1.5 s cold and under a
second warm; the parsed set retains ~9 MB of heap; matching runs at
roughly 150k lookups/second warm. Sane for a phone; the numbers are
reproduced by the bundled-list test in the suite.

### Android Phase 3 — Per-app rules and custom entries (landed)

- **Per-app rules.** Exempt an app from filtering, or block an app's
  network access entirely. Android's shape decided the build —
  routes are per-interface, not per-app, and an allowlist flips the
  whole VPN's population — so the edition runs one of two capture
  modes (FILTER-SPEC.md, "Per-app rules"). With nothing blocked:
  the Phase 1/2 DNS-only interface, exempted apps disallowed from
  it. With anything blocked: an app-block interface whose
  population is only the blocked apps, under an IPv4 + IPv6 default
  route, dropping everything they send and counting the drops per
  app (owner attribution via the platform's connection-owner
  lookup where Android offers it; unattributed where it can't be,
  never guessed). The honest cost is stated in the app and the
  README: while app-block mode lasts, other apps bypass the VPN and
  their DNS is not filtered. Rules are set from a searchable
  installed-apps picker (apps that can use the network; Sphinx
  itself is not listed) and take effect by rebuilding the interface
  through the ordinary shutdown/start lifecycle when the picker is
  left — no half-applied state.
- **Custom block entries** (the other half of the original Phase 2
  line): user-added domains on the block side, entered only through
  the parser's `normalizeEntry`/`parseEntries` front door — the
  Phase 2 audit rule — stored in their own file so list updates
  never overwrite them, honored alongside list entries with
  allowlist-wins intact.
- **Visibility.** A rules summary on the main screen (what's
  blocked, what's exempt) plus the memory-only drop counters.
- **Not in this phase, stated plainly:** a connection log beyond
  DNS is still future work — in filter mode Sphinx sees only DNS,
  and in app-block mode it counts blocked apps' packets without
  logging destinations. IPv6 *DNS filtering* is also still future;
  app-block mode does capture a blocked app's IPv6 traffic (and
  drop it), which is capture, not filtering.

### Android Phase 4 — Polish (landed)

- **Notification permission flow.** Phase 1 declared
  POST_NOTIFICATIONS but never asked, so on Android 13+ the status
  notification missed the shade. The app now asks exactly once, at
  the moment the user first turns the filter on; a refusal is
  recorded, never re-asked, and explained in place (what is
  missing — the shade status only — and where to re-enable it).
  The filter itself is unaffected either way.
- **Auto-start on boot (opt-in, off by default).** A
  BOOT_COMPLETED receiver restarts the filter after a reboot only
  when the user opted in AND the filter was on at shutdown — the
  service records the user's on/off intent at every genuine start
  and stop, and boot honors the intent, not process state. The
  start goes through the ordinary ACTION_START path, so the
  booted filter runs in the capture mode the stored rules
  produce; with no VPN consent in place it does nothing (no UI
  from a receiver, ever).
- **Profiles (e.g. Home / Kids / Aggressive).** A profile
  captures the user's rule state — per-app rules, allowlist,
  custom block entries (FILTER-SPEC.md, "Profiles"). Switching
  copies the snapshot into the live stores and applies it through
  the audited ACTION_RESTART path; edits to the live state write
  through to the active profile, so a profile never drifts from
  what it does. **Deviation from this section's original line,
  stated plainly:** profiles do not carry per-profile blocklists
  or sources — the lists are shared across profiles. The lists
  are the product's shared brain-data, updated under the atomic
  swap discipline; per-profile lists would let a profile silently
  run a stale or user-forgotten list, and switching would become
  a list change in disguise. What differs between profiles is
  the user's own choices, and those are all captured.
- **Battery handling.** The app shows whether Sphinx is exempt
  from battery optimization and, when it isn't, offers Android's
  own per-app settings dialog (falling back to the settings list)
  so the user decides — the app never forces or changes the
  setting. The status display keeps reflecting the real service
  state: a filter the battery saver stopped shows as off, never
  as protecting. List updates stay manual-only (FILTER-SPEC's
  no-silent-fetching rule), so the original "batch list updates"
  thought does not apply and was not built.
- **Not built in this phase, stated plainly:** the
  quick-settings tile from this section's original line. The
  main-screen toggle and the notification's stop action cover
  the same need for now; the tile stays on the future-work list
  below rather than shipping unexamined in a polish phase.

The Android edition is **feature-complete** with Phase 4. What
remains before a public release is the release gate (below):
a signed release build with a reproducible recipe, an
independent audit of the complete Android edition — fix, then
re-audit — and published SHA256SUMS verified by re-download.
Known future work that is **not** part of the gate (and must not
be claimed until built): IPv6 DNS filtering, a connection log
beyond DNS, and a quick-settings tile.

---

## Edition 2 — Windows (SPHINX.EXE)

Starts after the Android core lands.

- A local DNS-filter service listening on loopback; setup points the
  system's DNS at it, removal restores the previous settings exactly.
- Same brain: the FILTER-SPEC matching, sinkhole, and forwarding rules,
  with the spec's behavior verified against shared test cases.
- Plain-language UI in the fleet's style: status, blocked/allowed
  counters, allowlist, on/off.
- Two forms, like the rest of the fleet: an installer edition and a
  portable no-install edition.

### Windows Phase 1 — Core filter service (landed)

- **The brain, in Python** (`windows/src/sphinx_win/core/`): a direct
  port of the Android core — list parsing with the spec's safety
  rails, suffix matching with allowlist-wins (rule 5), the sanity
  gate, HTTPS-only redirect-vetted downloads, atomic list storage
  and updates (a failed update changes nothing, including the
  recorded time — the Android Phase 2 audit fix, present here from
  the start), custom entries through the parser's front door only,
  and the memory-only 500-entry query log. The bundled list is the
  identical StevenBlack file and parses to the identical **71,491**
  domains under the same parser rules.
- **The filter server:** UDP + TCP listeners on 127.0.0.1 **and**
  ::1 (Windows consults IPv6 DNS servers in parallel; IPv4-only
  would leave a bypass lane). Blocked → the spec's sinkhole;
  allowed → forwarded unchanged under the audited validation
  discipline (connected socket, ID + QR match, one overall 3 s
  deadline per resolver, fallback tried once), with truncated
  answers completed over TCP.
- **System DNS engagement, restore-first:** administrator rights
  gate any change (without them the app says so and touches
  nothing); the active adapters' original settings are saved to
  `dns-backup.json` and **verified by read-back before anything
  changes**; a backup on disk is never overwritten (a loopback can
  never be recorded as an original); every change is verified;
  stop restores exactly — DHCP included — and only a verified
  restore retires the backup; a backup found with DNS no longer
  engaged is a distinct *leftover* state with Restore / Dismiss,
  and loopback DNS with no backup is never taken over. Before DNS
  moves, the filter must prove it answers on each loopback it
  bound. FILTER-SPEC gained a "Windows edition notes" section
  recording this engagement model.
- **UI:** one plain PySide6 window — real-state status, on/off,
  counters, list status, manual update, source editor, allowlist
  and custom-entry editors (entry rails enforced where typed), the
  in-memory query log, the leftover banner. Closing the window
  stops cleanly (DNS restored first; a failed restore refuses the
  close). Phase 1 runs as this app — a background Windows service
  and tray host are later work, stated in windows/README.md.
- **Packaging + CI:** a PyInstaller spec for the one-file
  `Sphinx.exe`, a portable-zip build script (portable.txt marker →
  data beside the exe) with SHA256SUMS, and a GitHub Actions
  workflow on windows-latest that runs the suite and builds both
  artifacts — the edition's build gate, since the dev VM (Linux)
  cannot produce a Windows binary.
- **Tests:** the pytest suite ports the Android JVM tests' spirit —
  parser hostility and rails, gate rejections (including the
  duplicate-flood game), allowlist precedence, sinkhole byte
  layout, updater atomicity and kept copies, forwarder spoof
  discipline against fake upstreams, the engage/restore discipline
  against a fake DNS manager, and controller start/stop ordering.
  One live-socket round-trip test self-skips where the build
  sandbox blocks unconnected UDP replies; it runs in CI.
- **Independent audit (2026-10-21):** nine findings fixed and
  re-probed — two highs where the platform met the restore
  discipline (DHCP-vs-static reads; a loopback recordable as an
  "original" in the partial case) — full record in
  docs/AUDITS.md. CI artifacts were downloaded and re-verified
  (checksums, PE, portable layout).

### Windows Phase 2 — Tray host, start-at-sign-in, installer (landed)

- **Hosting shape: a tray-resident host process**, chosen over a
  true Windows Service and recorded here as the decision it is.
  One process owns the window, the tray icon, the filter server,
  and the DNS guard, so the backup/restore record the Phase 1
  audit proved has exactly one owner, in the user's own session —
  a SYSTEM service would split that ownership across a process
  boundary (and a state store both sides must agree on) for the
  single benefit of elevation without a prompt. The service
  question can be revisited if that trade ever changes; the
  Phase 1 audit's gates were inherited unchanged either way.
- **The window is a view, not the app.** Closing it hides it to
  the tray and stops nothing; the tray menu carries the real
  (read-back) status, Open, Turn on/off, Restart-as-administrator,
  and Quit — and Quit runs the audited stop, refused when a
  restore fails, exactly as Phase 1's window close did (that close
  discipline remains the fallback on a desktop with no tray). A
  second launch never starts a rival host: a per-user
  single-instance channel hands "show" to the running host.
- **Start-at-sign-in** is the standard per-user Run value — one
  value, written by the installer's option or the app's checkbox
  alike (the checkbox shows the registry's actual state). Resume
  follows the recorded-intent discipline: the controller records
  intent at every successful start, stop, and leftover resolution
  (and at no failed transition), and a sign-in launch resumes only
  when intent is on — through the same prove-first engagement,
  against the *existing* record when the machine is found still
  engaged. Leftover and unknown states are surfaced, never
  auto-handled. The honest friction, documented rather than
  designed away: a sign-in program cannot silently elevate, so a
  resume may put up exactly one UAC prompt; the
  `--elevated-attempted` marker guarantees a declined prompt is
  never retried in a loop, and the host then waits in the tray,
  off, saying so. The pure decision table (`app/host.py`) and the
  autostart policy (`app/autostart.py`) are unit-tested off
  Windows; the tray shell is smoke-tested headlessly.
- **Installer:** Inno Setup (`packaging/Sphinx.iss`), compiled in
  CI next to the portable zip. Its uninstaller runs the new
  headless `Sphinx.exe --restore-dns` mode from
  `InitializeUninstall` — before any file is removed — and aborts
  with a plain-language explanation when the restore cannot be
  verified, so an uninstall can never strand a machine on a dead
  resolver; the sign-in value is removed with the install, and the
  user's data folder is deliberately left in place. The script's
  load-bearing promises are pinned by tests; an end-to-end
  install → engage → uninstall pass on a real machine is
  release-gate work, stated as such in windows/README.md.
- **No dnsmgmt behavior changed.** Hosting consumed the audited
  guard/controller contracts as they stood; the only controller
  changes are recording intent at the transitions it already
  owned, each pinned by regression tests. Suite: 153 tests
  (PySide6 environment) at the Phase 2 HEAD.

### Windows Phase 3 — Profiles parity and HUD polish (landed)

- **Profiles, the Android model over Windows rule state**
  (`core/profiles.py`, the store, and the window's Profiles
  section): a profile captures the allowlist and the custom
  block entries — Windows has no per-app rules — while the
  blocklists and their sources stay shared under every profile,
  so a switch can never become a disguised list change. The
  store mirrors the Android store's audited disciplines:
  atomic storage; a malformed profiles file degrades to the
  profiles that parse, never a wiped live ruleset; live edits
  write through to the active profile from every save path; a
  switch writes the snapshot into the live stores *without* the
  write-through — the profile switched from is only read, the
  Android Phase 4 audit's corruption scenario designed out from
  the start — and the window applies the switch whole through
  the controller's ordinary reload, so the running filter never
  sits on a half-switched state. The pure model mirrors the
  Android ProfilesTest cases: round-trip, garbage tolerance,
  first-wins duplicates, the parser's rails on stored entries,
  replace/delete/active semantics, name validation.
- **HUD polish in Sphinx's own palette** (`app/theme.py`):
  basalt black, sandstone, bronze-gold — the stone guardian,
  recorded in windows/README.md as the identity the Android
  polish and any Toolkit card inherit. One application
  stylesheet in the fleet's shape (wordmark, stone panels, a
  bronze primary action), every text pairing pinned at WCAG
  4.5:1 or better by the suite, the danger red the fleet's
  standard value, no purple. The tray icon follows the real
  state in three palette states: dulled bronze off, bronze-gold
  on, danger red for attention (a leftover or unrecorded
  loopback waiting on the user, or a filter running while DNS
  no longer points at it). Presentation only — no Phase 1–2
  behavior moved: the status still comes from throttled real
  reads, and close-to-tray, the refused quit, the one-UAC ask,
  and the startup decision table are untouched.
- **Packaging:** version 0.3.0 (package and installer kept in
  step, as a test pins them). The installer's branding surfaces
  are its name/publisher/version strings; a wizard image or an
  embedded exe icon would need shipped binary assets and was
  not taken on in this phase.
- Suite: 187 tests in the PySide6 environment at the Phase 3
  HEAD.

Still ahead for this edition: the release gate below
(independent audit → fix → re-audit before any public release),
and — only if the hosting trade ever changes — a true service
host.

## Edition 3 — Debian/Linux

Starts after the Windows edition lands.

- A local DNS-filter daemon (systemd service) listening on loopback;
  setup integrates with the system's resolver configuration and removal
  restores it.
- Same brain, same shared test cases as every other edition.
- Shipped as a .deb, with the service disabled until the user enables
  it — installing the package never changes DNS silently.

### Debian Phase 1 — Core daemon, engage/restore guard, .deb (landed)

- **The brain, in Python** (`debian/src/sphinx_deb/core/`): the
  shared FILTER-SPEC core — parser rails, suffix matching with
  allowlist-wins, sinkhole, forwarding discipline (connected
  socket, ID + QR validation, one 3 s deadline per resolver,
  single fallback, truncated answers completed over TCP), the
  64-slot bounded-concurrency cap, and the memory-only 500-entry
  query log. The bundled list is the identical canonical asset,
  parsing to the identical **71,491** domains.
- **Engagement, two stacks** (FILTER-SPEC, "Debian edition
  notes"): a plain regular-file `/etc/resolv.conf` is rewritten
  byte-exactly-restorable; systemd-resolved in stub setup is
  engaged by a `resolvectl` runtime override restored by
  `resolvectl revert` — the recorded per-link servers are
  information only, never a restore target, so no DHCP lease is
  ever pinned. NetworkManager / generated / unrecognized setups
  are protected refusals. The full fleet discipline holds:
  save + read-back-verify before change, never overwrite a
  record, never record a loopback as an original, proof per
  family before pointing, verified restore before the record
  retires, leftover/unknown as surfaced states.
- **The .deb:** dedicated `sphinx` system user, ambient
  CAP_NET_BIND_SERVICE (the daemon never runs as root), hardened
  unit, postinst that changes no DNS and starts nothing, prerm
  that restores before removal and aborts on an unverified
  restore, remove-keeps-data / purge-deletes discipline. The
  package build copies the canonical list byte-checked into
  /usr/share/sphinx/ — the exact path the installed daemon reads.
- **Phase 1 scope, stated plainly:** CLI only; bundled-list only
  (no list updates, no allowlist/custom stores, no profiles);
  boot behavior is deliberate non-resumption on the resolved
  stack (a reboot leaves a leftover record for the user's own
  engage/restore decision).
- **Independent audit (2026-10-21):** three mediums and three
  lows found and fixed or documented — a moved default route
  silently reading as engaged on the resolved stack; restore
  writing over a resolv.conf that had become a symlink;
  unprivileged status misreporting a running daemon's counters;
  a prerm trap that could block removal when no Sphinx record
  existed — full record in docs/AUDITS.md. CI run for the landed
  HEAD was green (suite + package build).
- **Phase 2 owes:** the list-update path under the spec's update
  rules, allowlist/custom-entry stores with CLI editing, profiles
  parity, and a decision on boot/route-change resumption for the
  resolved stack. Real-machine proofs (engage → reboot, DHCP
  renewal mid-engagement, route change, install/remove cycle on
  Debian + Kali/Parrot) remain release-gate work.

## Further platforms

As feasible after the three editions above, and only where the same
honesty rules hold (names, not content; nothing leaves the device).

---

## Release gate — all editions

- Signed release builds (APK / EXE + portable / .deb) with a
  reproducible build recipe per edition.
- **Independent audit, then fix, then re-audit** — Sentinel's standing
  build → audit → fix → re-audit cycle. No public release of any
  edition ships before its audit gate passes.
- Published checksums (SHA256SUMS) alongside every release, verified by
  re-download.
