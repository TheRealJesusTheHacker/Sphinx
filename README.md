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

## What Sphinx cannot do — stated plainly

- **It cannot remove ads that are served from the same address as the
  content you asked for.** YouTube and YouTube Music are the famous case:
  the ads and the music come from the same servers, so at the network
  layer they look identical. Blocking the ad would block the song. No
  DNS or network blocker can honestly promise otherwise, and we won't.
- **It does not inspect your traffic.** Sphinx reads DNS requests —
  the names being looked up — and nothing else. It does not open,
  decrypt, or read the contents of your HTTPS connections.
- **Phase 1 filters IPv4 DNS.** IPv6 filtering is on the roadmap; on an
  IPv6-only path, lookups can pass around the filter today.
- **Apps with built-in encrypted DNS can walk around it.** Some apps
  and browsers do their own encrypted lookups (DNS-over-HTTPS —
  Chrome calls it "secure DNS") and never ask the phone's resolver,
  so Sphinx never sees those queries. Turning that feature off in the
  app puts its lookups back where Sphinx can question them.
- **It uses the phone's one VPN slot.** While Sphinx is on, a separate
  VPN app can't run at the same time — Android allows one VPN at a time.

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

This is **Phase 1: a working core, not a finished product.** The DNS
filter runs, with a small starter blocklist baked in. The blocklist
engine, per-app rules, and a polished release build are on the
[roadmap](docs/ROADMAP.md). Nothing here is a finished public release
yet — under Sentinel's standing rule, no release ships before it passes
an independent audit.

## Building

Requires JDK 17 and the Android SDK (platform 34, build-tools 34).

```
./gradlew :app:assembleDebug      # debug APK
./gradlew :app:testDebugUnitTest  # JVM unit tests (DNS parsing, blocklist)
```

## Credits

Built by **Sentinel Safeguard LLC** — Kansas City, Missouri.
Security for everyone.
