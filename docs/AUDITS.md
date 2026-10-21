# Sphinx — Audit Log

Sentinel's standing cycle: build → audit → fix → re-audit. This file
is the record: what each independent audit found, what was fixed, and
what was documented-and-ignored with its reason (a finding is only
ever ignored when fixing it would break intended functionality —
never merely to make a report prettier).

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

