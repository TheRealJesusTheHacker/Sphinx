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

### Android Phase 3 — Firewall rules

- Per-app rules: block an app's network access entirely, or exempt an
  app from filtering.
- Custom block entries: user-added domains on the block side — the
  counterpart of the Phase 2 allowlist (moved here from Phase 2).
- Connection log beyond DNS: destinations by app, with plain-language
  summaries.
- Optional IPv6 DNS filtering.

### Android Phase 4 — Polish

- Notification permission flow on Android 13+: Phase 1 declares
  POST_NOTIFICATIONS but never asks, so on newer Android the status
  notification only appears in the foreground-service list, not the
  notification shade. Ask, with a plain-language reason.
- Auto-start on boot (opt-in), quick-settings tile.
- Profiles (e.g. Home / Kids / Aggressive) with per-profile lists.
- Battery handling: keep the filter cheap, batch list updates, honor
  Android power management without silently dropping protection.

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
