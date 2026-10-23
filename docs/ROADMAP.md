# Sphinx — Roadmap

Tagline: *Every request gets questioned.*

Sphinx is one product line with multiple editions in this repo — the
Argus precedent: one repo, several platform editions, one brain. Every
edition implements the shared rules in [FILTER-SPEC.md](FILTER-SPEC.md):
DNS queries are matched against a blocklist, blocked names get a
sinkhole answer, allowed queries are forwarded to an upstream resolver.
No root/admin tricks beyond what each platform normally requires; in
blocker mode there is no remote VPN server, and filtering always
happens on the user's own device. VPN mode is the separate,
user-chosen exception governed by [TUNNEL-SPEC.md](TUNNEL-SPEC.md)
and recorded in its own section below.

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

### Debian Phase 2 — FILTER-SPEC parity, resumption (landed)

- **The update path** (`sudo sphinx update`): the spec's two
  default sources, HTTPS only, redirects followed by hand with
  every hop vetted, the ≥1,000-domain gate per source and again
  on the merged set's unique domains, atomic temp-and-rename
  swaps, manual only — nothing fetches in the background, ever.
  Failure is all-or-nothing: any source failing means nothing
  swapped and the last-updated time untouched. Downloaded lists
  take over from the bundled floor only while valid; the floor
  means an update can never leave the daemon listless.
- **Stores + CLI editing:** allowlist and custom block entries
  persist under /var/lib/sphinx (root edits via `sphinx allow` /
  `sphinx block`; the daemon, as the unprivileged sphinx user,
  only reads). The store's scalars live in store.json — the
  guard's intent keeps state.json; neither overwrites the
  other. The daemon watches the store's files and reloads the
  whole working set on change: updates, edits, and profile
  switches land in the running filter without a restart,
  proven at the engine's decision point by tests.
- **Profiles parity:** the spec model (allowlist + custom
  entries; lists and sources shared — a switch is never a
  disguised list change) with the audited disciplines:
  write-through from every save path, switch with sync off +
  fresh-read marker, both snapshots byte-intact across a
  switch, delete removes only the snapshot.
- **Boot / route-change resumption — decided:** intent (written
  only at verified transitions) + a saved record + live DNS no
  longer at the filter is reconciled honestly: surfaced by the
  daemon's journal at start and by `sphinx status`, and
  performed only by the user's `sudo sphinx engage` through the
  ordinary prove-then-point path — against the record (never
  re-saved) on the same link, retargeted (stale override undone
  and verified, new link's originals saved and verified) when
  the default route moved. An upgrade still disengages and
  records intent off, so upgrades are never auto-resumed.
- **Not in this phase, stated plainly:** editing the update
  source list from the CLI; NetworkManager machines remain a
  protected refusal; no graphical interface. The real-machine
  proofs above remain release-gate work, alongside this
  phase's own independent audit.

## VPN mode — TUNNEL-SPEC Phases 1–2 (landed on `main`, unreleased)

A real VPN mode beside the blocker, governed by the shared rules
in [TUNNEL-SPEC.md](TUNNEL-SPEC.md). Blocker mode is unchanged —
local, DNS-only, nothing leaves the device for filtering. VPN
mode is a separate, user-chosen mode: traffic passes through the
server the user chooses, Sphinx ships no servers, the server
list starts empty, profiles are the user's own or their
provider's, and the `server/` package in this repo lets anyone
run their own endpoint. Landed on `main` after v1.0.1
(2026-10-23); **in no release** — the current release remains
v1.0.1, and the program audit is recorded in docs/AUDITS.md.

### VPN Phase 1 — WireGuard (landed)

- **The four-mode model in every edition:** Off, Blocker, VPN
  only, VPN + Blocker, with the spec's disclosure where the
  mode is offered, hostname endpoints resolved and pinned
  before the tunnel engages, and a kill switch whose level is
  stated per edition in its README.
- **Per edition:** Android runs WireGuard through the official
  tunnel library; Windows embeds WireGuardNT unmodified under
  its Prebuilt Binaries License (hash-pinned in the suite);
  Debian drives the kernel's WireGuard through the invoked
  `wireguard-tools`. The shared profile corpus
  (`docs/tunnel-corpus.json`) and the named owner-criterion
  conformance test (an unlisted name resolves and its traffic
  passes) exist in every edition.
- **The `server/` package (landed):** install / add-client /
  remove-client scripts that turn a stock Debian VPS into the
  user's own WireGuard endpoint — the operator is whoever runs
  it, never Sentinel Safeguard.

### VPN Phase 2 — OpenVPN + public volunteer servers (landed)

- **OpenVPN:** profiles connect on Debian and Windows through
  the system OpenVPN program those editions invoke (GPL,
  invoked only — never bundled). On Android there is no system
  binary and the embeddable engines are GPLv3/AGPLv3 against
  Sphinx's MIT license, so the Android edition shows the
  directory and saves OpenVPN profiles but refuses OpenVPN
  connections with that license reason named.
- **Public volunteer servers (VPN Gate):** an opt-in directory
  in all three editions, fetched at use time, with the
  strangers/logging disclosure traveling with it. Debian and
  Windows connect its nodes via the system OpenVPN; Android
  saves them and refuses the connection, as above.
- **VPN + Blocker, honestly per edition:** Windows and Debian
  filter DNS through the tunnel. Android does not yet — the
  tunnel library owns the TUN, the gate logic is built and
  tested, the in-tunnel wiring is future work, and the app
  discloses the limit in place.
- **Proofs so far are CI's:** the Debian suite at 223 with both
  network-namespace tunnel proofs (WireGuard and OpenVPN),
  Windows CI green, and Android CI green at HEAD. The
  same-domain ad limit (YouTube) is unchanged by VPN mode.

### VPN mode — what remains (not landed)

- **A release decision.** VPN mode ships in no release until
  one is made; v1.0.1 contains none of it.
- **The three real-machine passes, now including VPN** —
  Android phone, Windows machine, Debian machine — with real
  connects and real kill-switch drops. CI carries the tunnel
  proofs until then.
- **The Android in-tunnel filtering decision** — whether and
  how DNS filtering is wired into the tunnel packet path on
  Android. The gap is disclosed in the app; the decision is
  the owner's, pending.
- **A live-server deploy** of the `server/` package, as a
  separate coordinated step — not part of landing the code.

## Further platforms

As feasible after the three editions above, and only where the same
honesty rules hold (names, not content; in blocker mode, nothing
leaves the device).

---

## Release gate — all editions

- Signed release builds (APK / EXE + portable / .deb) with a
  reproducible build recipe per edition.
- **Independent audit, then fix, then re-audit** — Sentinel's standing
  build → audit → fix → re-audit cycle. No public release of any
  edition ships before its audit gate passes.
- Published checksums (SHA256SUMS) alongside every release, verified by
  re-download.
- **VPN mode is behind this gate too.** It landed on `main`
  unreleased (Phases 1–2, above); shipping it needs the release
  decision, the three real-machine passes including VPN, the
  Android in-tunnel filtering decision, and a live-server
  deploy as a separate coordinated step.

- **v1.0.0 — PUBLISHED 2026-10-23.** First public release:
  https://github.com/TheRealJesusTheHacker/Sphinx/releases/tag/v1.0.0
  (release id 419322679, tag `v1.0.0` on audited HEAD
  `f1afdffc8c27`). Assets: `SphinxSetup.exe`, `Sphinx.exe`,
  `SphinxPortable.zip` (Windows v0.3.0, from CI run 39569349230),
  `sphinx_0.2.0_all.deb` (Debian 0.2.0), and `SHA256SUMS.txt` —
  every asset re-downloaded from the release and its sha256
  verified against `SHA256SUMS.txt`. Android (v0.4.1) is not in
  this release: a public APK needs the owner's release keystore,
  which does not exist yet, and no debug-signed build ships. The
  three real-machine passes named in the release notes (Android
  phone, Windows machine, Debian machine) remain owed.
- **v1.0.1 — PUBLISHED 2026-10-23.** The fix release:
  https://github.com/TheRealJesusTheHacker/Sphinx/releases/tag/v1.0.1
  (release id 422099166, tag `v1.0.1` on HEAD
  `00b3a6760166`). Assets: `SphinxSetup.exe`, `Sphinx.exe`,
  `SphinxPortable.zip` (Windows v0.3.1), `sphinx_0.2.1_all.deb`
  (Debian 0.2.1), and `SHA256SUMS.txt` — built by the release
  workflow (run 39991150614) on the tagged commit; every asset
  re-downloaded and its sha256 verified against
  `SHA256SUMS.txt` and the API digests, the portable's inner
  exe byte-identical to the standalone. This release carries
  the twelve fix-wave commits below and the Fleet Sweep #4
  Debian parity fixes (liveness proof, atomic-write
  durability). Android is not in this release either — the
  release keystore still does not exist — and the three
  real-machine passes remain owed.
- **Post-v1.0.0 fix wave — on `main`, NOT in v1.0.0.** The twelve
  fix-wave commits after `f1afdffc8c27` (W-1–W-7 Windows
  restore-discipline fixes, the Android truncated-answer TCP
  completion and its forwarder hardening, the Android
  quick-settings tile, and R-17 installer branding) landed after
  the v1.0.0 tag was cut. They shipped in v1.0.1 (above);
  nothing in this roadmap should be read as putting them in
  v1.0.0. (The Phase 4 note further up that lists the
  quick-settings tile as future work is the phase record as it
  stood when Phase 4 closed; the tile has since been built and
  its code is in the v1.0.1 tag — the Android edition itself
  still ships nothing, per the v1.0.1 record above.)
- **Android completion pass — 2026-10-23.** The Android
  unit-test suite has been run end-to-end for the first
  time: **115 tests, 115 passed, 0 failed** — the full
  JUnit run over the real sources with the project's own
  toolchain (Temurin 17, Kotlin 2.0.20), corroborated by a
  green Gradle `testDebugUnitTest` in CI (workflow run
  40004668287). The "90 tests" figure carried before this
  pass was stale; 115 is the counted, run figure. (The
  sandbox the fleet works from blocks the JVM networking
  Gradle's daemon and raw UDP need, so the counted run
  used the standalone Kotlin compiler with the same
  friend-module semantics AGP applies; the Gradle route
  itself is the one proven in CI.) The signed-release path
  is now wired: `app/build.gradle.kts` takes signing only
  from the `SPHINX_ANDROID_*` environment variables — the
  owner's keystore; a partly-set signing environment fails
  configuration outright, and the `signedRelease` task
  refuses without them (proven in CI, run 40005602946:
  "No signed Sphinx release can be built here: the signing
  environment is not set… Unsigned and debug-signed builds
  are compile proofs only — never releases."). A dispatch
  workflow (`.github/workflows/sphinx-android.yml`) runs
  the test gate on demand and, when dispatched with
  `build_signed` after the owner adds the keystore
  secrets, produces the apksigner-verified signed APK as
  a workflow artifact — its own secret gate proven
  refusing without the secrets (run 40005050493). No
  debug-key fallback exists anywhere in the path.
  **Android still ships nothing** — the owner's release
  keystore does not exist yet, and the phone smoke pass
  remains owed; the APK joins a release when those two
  owner steps are done.
