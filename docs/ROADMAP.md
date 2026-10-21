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

## Edition 3 — Debian/Linux

Starts after the Windows edition lands.

- A local DNS-filter daemon (systemd service) listening on loopback;
  setup integrates with the system's resolver configuration and removal
  restores it.
- Same brain, same shared test cases as every other edition.
- Shipped as a .deb, with the service disabled until the user enables
  it — installing the package never changes DNS silently.

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
