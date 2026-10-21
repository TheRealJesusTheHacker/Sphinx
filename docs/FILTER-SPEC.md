# Sphinx — Shared Filtering Spec

Every Sphinx edition (Android, Windows, Debian, and any that follow)
implements **the same brain**. This file is that brain, in plain
language. If an edition behaves differently from this spec, the edition
is wrong — fix the edition, or change the spec on purpose and in the
open.

## What gets questioned

Sphinx filters **DNS queries only** — the name lookups devices make
before connecting anywhere. It does not inspect, decrypt, or modify the
contents of any connection (no HTTPS interception, ever).

## Matching rules

1. Names are compared case-insensitively, without a trailing dot:
   `ADS.Example.COM.` and `ads.example.com` are the same name.
2. The blocklist holds plain domain names, one per line. Blank lines and
   lines starting with `#` are ignored.
3. A query name is **blocked** when it equals a blocklist entry **or is
   a subdomain of one**:
   - Entry `example.com` blocks `example.com`, `ads.example.com`, and
     `a.b.ads.example.com`.
   - Entry `ads.example.com` blocks `ads.example.com` and below, but
     **not** `example.com` itself and not `other.example.com`.
4. If nothing matches, the query is **allowed**.
5. An allowlist, when present, wins over the blocklist at the same or
   deeper level: allowlisting `example.com` unblocks it and all its
   subdomains even if a broader entry blocks them. The allowlist uses
   the same matching walk as the blocklist (rule 3): a name is covered
   when it, or any parent of it, is allowlisted.

## List files

Blocklists and allowlists are plain-text files, parsed by these rules:

- **Plain format:** one domain per line. A leading `*.` (wildcard
  style, as some published lists use) means the same as the bare name.
- **Hosts format:** an IP literal (IPv4 or IPv6) followed by one or
  more names; every name on the line is an entry.
- Blank lines and comments are ignored: `#` starts a comment anywhere
  on a line.
- Entries are normalized by the matching rules above. Anything that
  doesn't normalize to a domain name is skipped.

Safety rails while parsing:

- **Reserved local names are never entries** — `localhost` and the
  other names hosts files use for the machine itself
  (`localhost.localdomain`, `broadcasthost`, the `ip6-*` names) are
  infrastructure, not ad servers.
- **Single-label entries are ignored.** A one-word entry (`com`)
  would, by the subdomain rule, block an entire top-level domain. No
  legitimate blocklist needs one.
- **IP literals are never entries.** An address by itself is not a
  name.

## Custom block entries

A user may add their own blocked domains on top of every list.
Custom entries match exactly like list entries (rules 1–5 above —
subdomains included, allowlist still wins), and they are held to the
same entry discipline as list content: an entry is accepted only
through the same normalization and safety rails the parser applies
(`normalizeEntry` / `parseEntries` — no single labels, no reserved
names, no IP literals), so a stored entry always does what it appears
to do. Editions keep custom entries in their own store, apart from
downloaded lists, so a list update never overwrites them and removing
a list source never removes the user's own entries.

## Per-app rules

Editions on platforms that can route per application may offer two
user-set rules per app:

- **Exclude an app from filtering** — the app bypasses the filter
  entirely.
- **Block an app entirely** — the app gets no network access at all
  while the filter runs.

The Android edition implements these on its one VPN interface, whose
routes are per-interface rather than per-app, and whose app
population is all-or-nothing (an allowlist flips the whole VPN to
just the listed apps). That constraint produces two capture modes,
and the edition must state plainly which one is in force:

- **Filter mode** — in force while no app is blocked outright. The
  interface routes only the virtual DNS server address: every app's
  DNS queries are questioned under the rules above, and no other
  traffic enters the tunnel. An exempted app is removed from the
  VPN's population, so neither the route nor the VPN's DNS server
  applies to it — it connects exactly as if the filter were absent.
- **App-block mode** — in force while at least one app is blocked
  outright. The interface's population is only the blocked apps, and
  it carries a default route (IPv4 and IPv6). Everything a blocked
  app sends enters the tunnel and is **dropped on the device** —
  never forwarded, never answered, never inspected beyond the IP and
  transport headers read to attribute the drop. Every app that is
  not blocked bypasses the VPN in this mode — including its DNS,
  which is therefore **not filtered** while app-block mode lasts.
  No edition may present app-block mode as filtering-plus; the trade
  is stated wherever the block rule is offered.

Rules are read when the interface (re)starts. Changing a rule takes
effect by restarting the interface through the same shutdown/start
path as a stop followed by a start — there is no third, half-applied
state.

## Profiles

An edition may let the user save their own rule state under a
name — a *profile* — and switch between profiles. A profile
captures exactly the user's own choices:

- the per-app rules,
- the allowlist,
- the custom block entries.

A profile never captures the blocklists or their sources: every
profile questions with the same lists, so switching profiles
cannot change which lists are in force, and a list update never
disturbs a profile.

The mechanism's rules, so every edition behaves the same:

- **Switching is a copy, applied by restart.** Switching writes
  the profile's state into the live stores and applies it by
  restarting the filter through the ordinary shutdown/start path
  (the per-app rules rule above — no third, half-applied state).
  The snapshot itself is only read by a switch, never modified.
- **The active profile does not drift.** While a profile is
  active, edits to the live rule state are edits to that profile
  too (written through by the store), so what a profile says is
  always what it does.
- **Profiles degrade; they never destroy.** Profile storage uses
  the same discipline as list storage — entries normalized
  through the parser's rails, files replaced atomically. A
  malformed profile file degrades to the profiles that parse —
  worst case, none — and never to a wiped live ruleset: the live
  state changes only when the user explicitly switches.
- **Deleting a profile deletes only the snapshot.** The live
  rules stay as they are; if the deleted profile was active, the
  rules simply stop being under a profile.

## Sinkhole behavior (blocked queries)

A blocked query is answered locally and never leaves the device:

- **A** queries → `0.0.0.0`
- **AAAA** queries → `::`
- Any other query type → a valid NOERROR response with no answer
  records (the name "exists", it just gets nothing).
- Answer TTL: **60 seconds**.
- The response echoes the query's ID and question section exactly.

## Forwarding behavior (allowed queries)

- Allowed queries are forwarded **unchanged** to an upstream resolver
  over UDP/53 — default **1.1.1.1**, fallback **9.9.9.9** — and the
  upstream answer is returned to the asker unchanged.
- Timeout: 3 seconds per upstream attempt; try the fallback once before
  giving up. If both fail, the query goes unanswered (the asking app
  retries on its own schedule).
- A response counts as the answer only if it comes from the resolver
  the query was sent to and its DNS ID matches the query's ID with the
  response (QR) bit set. Anything else arriving on the socket is
  ignored — a stray or spoofed datagram is never delivered to the
  asker as if it were the answer.
- Upstream traffic must never be routed back into the filter itself
  (on Android: the forwarding socket is protected from the VPN).

## List updates

Editions may refresh their blocklists from remote sources, under
these rules:

- Sources are **HTTPS only**, and they are **visible and editable** by
  the user. An edition fetches only from the sources it shows, and
  only when the user asks (no silent background fetching). A redirect
  during a download is followed only while **every hop stays on
  HTTPS**; a downgrade to plain HTTP fails the download (the list is a
  security control — it must not be substitutable by anyone on the
  network path).
- A download is **fully parsed and sanity-checked before it may
  replace anything**: the parsed list must hold at least **1,000
  domains**. An error page, a truncated file, or an empty response
  never passes — real blocklists hold tens of thousands.
- The swap is **atomic from the filter's point of view**: the combined
  replacement set (fresh downloads plus any kept previous copies) must
  pass the same sanity gate before any stored list changes, each
  stored file is replaced by temp-file-and-rename, and the running
  filter switches to the new lists only once they are complete. A
  failed update changes nothing.
- A source that fails keeps its **previous downloaded copy**.
- A **bundled list** ships with the app and is never modified by
  updates. Downloaded lists, when valid, take over from it; if no
  valid downloaded list exists, the bundled list is the blocklist.

## Counting and the query log

Each edition counts queries it **blocked** and queries it **allowed**
(forwarded). Counts are informational only and live on the device.

An edition may also keep a **query log** — recent query names, whether
each was blocked, and when. The log:

- lives **only on the device, in memory** — it is never written to
  disk by the filter and never transmitted anywhere;
- is a **ring buffer with a hard cap** (500 entries in the Android
  edition), so it cannot grow without bound;
- is **on by default** in the Android edition, stated plainly in the
  README, and the user can turn recording **off** or **clear** the log
  at any time.

App-block mode keeps **drop counters** under the same discipline:
packets dropped, counted per blocked app and in total, held **only
in memory on the device** — never written to disk by the filter,
never transmitted. A packet whose owning app the platform cannot
identify is counted as *unattributed*, never guessed at. Headers
read for attribution (addresses and ports) feed the count and a
bounded, memory-only attribution cache, and nothing else; they are
never written to disk or transmitted.

One degenerate case, for the record: a blocked app that has since
been uninstalled routes nothing into the interface. If *every*
blocked app is gone, the population would be empty — and an empty
allowlist with a default route would capture the whole phone — so
the interface runs in filter mode until the rules once again name
an installed app.

## Staying on: notifications, boot, battery

A filter that is off protects no one, and a filter that *claims*
to be on while stopped is worse than off. An edition's status
display therefore reflects the real filter state, never the
desired one, and staying on follows these rules:

- **Notifications inform; they are never the protection.** Where
  the platform wants the user's permission for notifications
  (Android 13+: POST_NOTIFICATIONS, declared since Phase 1), the
  edition asks at most once, at the moment the user first turns
  the filter on. A refusal changes nothing about filtering; the
  edition states plainly that the status notification won't
  appear and where to re-enable it — and does not ask again.
- **Boot auto-start is opt-in and honors intent.** An edition may
  restart the filter after a reboot only when the user turned
  that setting on AND the filter was on when the device shut
  down — the user's recorded on/off intent, not process state.
  It comes up through the ordinary start path, in the mode the
  stored rules produce. If a platform consent the filter needs
  (Android's VPN consent) is not in place, boot does nothing:
  no UI, no prompts from a background receiver.
- **Battery exemption is the user's decision.** Where platform
  battery management can stop the filter (Android's battery
  optimization), the edition explains the risk in plain language,
  shows whether it is currently exempt, and offers the
  platform's own settings path so the user decides. It never
  forces or changes the setting itself.

## Honesty rules baked into the design

- Ads served from the same domain as requested content (YouTube /
  YouTube Music) **cannot** be blocked by these rules — the query name
  is the content's own name. No edition may claim otherwise.
- The filter sees names, not content. No edition may log or transmit
  query contents off the device; any query log is local, user-visible,
  and user-clearable.
