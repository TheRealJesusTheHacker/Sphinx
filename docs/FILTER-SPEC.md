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
5. (Phase 2) An allowlist, when present, wins over the blocklist at the
   same or deeper level: allowlisting `example.com` unblocks it and all
   its subdomains even if a broader entry blocks them.

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
- Upstream traffic must never be routed back into the filter itself
  (on Android: the forwarding socket is protected from the VPN).

## Counting

Each edition counts queries it **blocked** and queries it **allowed**
(forwarded). Counts are informational only and live on the device.

## Honesty rules baked into the design

- Ads served from the same domain as requested content (YouTube /
  YouTube Music) **cannot** be blocked by these rules — the query name
  is the content's own name. No edition may claim otherwise.
- The filter sees names, not content. No edition may log or transmit
  query contents off the device; any query log is local, user-visible,
  and user-clearable.
