# Sphinx — Audit Log

Sentinel's standing cycle: build → audit → fix → re-audit. This file
is the record: what each independent audit found, what was fixed, and
what was documented-and-ignored with its reason (a finding is only
ever ignored when fixing it would break intended functionality —
never merely to make a report prettier).

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

