# Sphinx

**Every request gets questioned.**

Sphinx is a free Android app from Sentinel Safeguard that blocks ads and
trackers across your whole phone — in apps and in the browser, not just on
web pages.

## How it works

Android only lets an app filter the whole phone's traffic one way: through
the VPN interface. Sphinx uses that interface **locally**. It opens the
VPN slot on your phone, looks at the address lookups (DNS requests) your
apps make, and refuses to answer the ones that point at known ad and
tracker servers. Everything else is passed straight through to a public
resolver and the answer comes right back.

- **No remote VPN server.** There is no tunnel to us, or to anyone. Your
  traffic never leaves your phone for filtering — the "VPN" is a doorway
  inside your own device, and Sphinx is standing in it asking questions.
- **No root.** Sphinx uses only the VPN permission Android offers to any
  app. You approve it once, in the standard Android prompt.
- **System-wide.** Because it works at the network layer, it covers apps
  and browsers alike — not just one browser.
- **Free.** No accounts, no subscription, no ads of our own.

## Your lists, your log — the privacy facts

- **A real blocklist, built in.** Sphinx ships with the StevenBlack
  unified list (ads + malware) — **71,491 domains** — so it protects
  you from the first minute, before any update.
- **Updates only when you tap.** "Update lists now" downloads fresh
  lists over HTTPS from the sources shown in the app (defaults:
  StevenBlack and HaGeZi Multi LIGHT). You can see and edit those
  addresses. Sphinx contacts nothing else on its own behalf — the only
  other traffic is your own allowed lookups going to the public
  resolver, as they would without Sphinx. A download that fails or
  doesn't parse as a real list changes **nothing**: your working list
  is never wiped by a bad download.
- **An allowlist that always wins.** If a site or app breaks, add its
  domain to the allowlist in the app and it will never be blocked,
  even when a list covers it.
- **Your own block entries.** Domains you add yourself are blocked
  exactly like list entries — subdomains included — and the allowlist
  still wins over them. They live in their own store on the phone, so
  a list update never overwrites them.
- **Per-app rules.** You can exempt an app from filtering entirely,
  or block an app outright so it gets no network at all while Sphinx
  is on. To show you the apps, Sphinx asks Android for the installed
  app list — that is what the QUERY_ALL_PACKAGES permission is for.
  The list is used on this phone, for that screen, and is never sent
  anywhere; all Sphinx stores is the rules you picked.
- **Blocked-app drop counts.** While an app is blocked outright,
  Sphinx counts the packets it drops, per app — memory only, under
  the same rules as the query log below: never written to permanent
  storage by the filter, never sent anywhere.
- **A query log that stays on the phone.** So you can see Sphinx
  working, it keeps the most recent 500 lookups — the name, whether it
  was blocked, and the time — **in memory only**. The log is never
  written to permanent storage, never sent anywhere, and disappears
  when the app's process stops. Recording is **on by default**; you
  can turn it off, or clear the log, any time in the app.

## What Sphinx cannot do — stated plainly

- **It cannot remove ads that are served from the same address as the
  content you asked for.** YouTube and YouTube Music are the famous case:
  the ads and the music come from the same servers, so at the network
  layer they look identical. Blocking the ad would block the song. No
  DNS or network blocker can honestly promise otherwise, and we won't.
- **It does not inspect your traffic.** Sphinx reads DNS requests —
  the names being looked up — and nothing else. It does not open,
  decrypt, or read the contents of your HTTPS connections.
- **The Android edition currently filters IPv4 DNS.** IPv6 filtering is
  on the roadmap; on an IPv6-only path, lookups can pass around the
  filter today.
- **Apps with built-in encrypted DNS can walk around it.** Some apps
  and browsers do their own encrypted lookups (DNS-over-HTTPS —
  Chrome calls it "secure DNS") and never ask the phone's resolver,
  so Sphinx never sees those queries. Turning that feature off in the
  app puts its lookups back where Sphinx can question them.
- **It uses the phone's one VPN slot.** While Sphinx is on, a separate
  VPN app can't run at the same time — Android allows one VPN at a time.
- **It can't run the gate both ways at once.** That same one
  interface has two shapes. Normally it questions DNS and nothing
  else. Blocking an app outright needs the other shape — so while
  any app is blocked outright, the blocked apps get no network, and
  every other app connects *without* DNS filtering for as long as
  the block lasts. Android's routing is per-interface, not per-app;
  there is no third shape that does both, and the app says this
  where the rule is set.

## Editions

Sphinx is one product with multiple editions in this repo, all built on
the same filtering brain (the rules in [docs/FILTER-SPEC.md](docs/FILTER-SPEC.md)):

1. **Android** — the app described above (local VPN mode). *In build now.*
2. **Windows (SPHINX.EXE)** — a local DNS-filter service the system DNS
   points at, with installer and portable editions like the rest of the
   Sentinel fleet. *Planned — not started.*
3. **Debian/Linux** — a local DNS-filter daemon (systemd service),
   shipped as a .deb. *Planned — not started.*
4. Further platforms as feasible after those three.

Only the Android edition exists today. The others are named here so the
plan is public and honest — not because they're ready.

## Status

This is **Phase 3: the filter, plus per-app rules and custom block
entries — not a finished product.** The DNS filter runs on a bundled
71,491-domain list, updates itself from public list sources when you
tap the button (with a sanity check and an atomic swap, so a bad
download can never wipe your protection), honors your allowlist, and
keeps a short on-device query log. Phase 3 adds your own custom
block entries; per-app rules (exempt an app from filtering, or block
an app outright — with the trade stated plainly above); and per-app
drop counters, so you can watch a blocked app being stopped. A
polished release build is still on the [roadmap](docs/ROADMAP.md).
Nothing here is a finished public release yet — under Sentinel's
standing rule, no release ships before it passes an independent
audit.

## Building

Requires JDK 17 and the Android SDK (platform 34, build-tools 34).

```
./gradlew :app:assembleDebug      # debug APK
./gradlew :app:testDebugUnitTest  # JVM unit tests (DNS parsing, blocklist)
```

## Credits

Built by **Sentinel Safeguard LLC** — Kansas City, Missouri.
Security for everyone.
