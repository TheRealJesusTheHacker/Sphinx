# Sphinx

**Every request gets questioned.**

Sphinx is a free ad and tracker blocker from Sentinel Safeguard, built
in editions for Android, Windows, and Debian from this one repo. This
README describes the Android edition in detail: it blocks ads and
trackers across your whole phone — in apps and in the browser, not
just on web pages. (The Windows and Debian editions have their own
READMEs, linked under *Editions* below.)

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
- **Profiles.** Save your app rules, allowlist, and custom block
  entries under a name — Home, Kids, Strict — and switch between
  them. The block lists are shared by every profile; a profile is
  your choices on top of them. While a profile is active, editing
  those rules edits the profile too, so a profile never silently
  drifts from what it does.
- **The status notification asks once.** On Android 13 and later,
  the first time you turn Sphinx on, Android asks whether it may
  show notifications. If you say no, the filter still works exactly
  the same — only the shade notification is missing — and the app
  says so, with where to change it, instead of asking again.
- **Start on boot is your choice, and off until you make it.** If
  you turn it on, and Sphinx was running when the phone shut down,
  it starts again after the restart — same mode, same rules. If
  you had turned Sphinx off, it stays off.
- **Battery honesty.** Android's battery saver can put apps to
  sleep, and a sleeping filter filters nothing. The app shows
  whether Sphinx is exempt from battery optimization and offers
  Android's own settings screen so *you* can exempt it — Sphinx
  never changes that setting itself. And if the filter does stop,
  the app shows it as off. It never pretends to be protecting you
  when it isn't.

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
- **Android can still put it to sleep.** Unless you exempt Sphinx
  from battery optimization (your choice, in the app), an
  aggressive battery mode can stop the filter. When that happens
  Sphinx is simply off — the app shows it as off.

## Editions

Sphinx is one product with multiple editions in this repo, all built on
the same filtering brain (the rules in [docs/FILTER-SPEC.md](docs/FILTER-SPEC.md)):

1. **Android** — the app described above (local VPN mode).
   *Feature-complete and audited; not yet in a release — a public
   APK must be signed with the owner's release keystore, which
   does not exist yet (see Status below).*
2. **Windows (SPHINX.EXE)** — a local DNS filter listening on loopback
   (127.0.0.1 and ::1) that the system DNS is pointed at while it
   runs, under a save-first / restore-exactly discipline for the
   machine's original DNS settings. Hosted by a system-tray process
   (closing the window doesn't stop it), with an opt-in
   start-at-sign-in that resumes protection under the same intent
   discipline as the Android edition. One-file exe, a portable
   edition, and an installer whose uninstaller restores your DNS
   settings before it removes anything. *Current release v0.3.1 in
   v1.0.1 (2026-10-23; first shipped as v0.3.0 in v1.0.0) — Phases 1–3 (core filter service; tray
   host, start-at-sign-in, installer; profiles and the Sphinx
   palette); see [windows/README.md](windows/README.md).*
3. **Debian/Linux** — a local DNS-filter daemon (systemd service)
   listening on loopback, shipped as a .deb, with engage/restore
   commands under the same restore discipline (a plain
   /etc/resolv.conf rewritten byte-exactly-restorable, or a
   systemd-resolved runtime override restored by revert — never a
   pinned DHCP lease). *Current release 0.2.1 in v1.0.1 (2026-10-23; first
   shipped as 0.2.0 in v1.0.0) — Phases 1–2 (daemon, guard, CLI, .deb; manual list updates,
   rule stores, profiles, and boot/route-change resumption) — see
   [debian/README.md](debian/README.md).*
4. Further platforms as feasible after those three.

All three editions exist today. The Windows and Debian editions
are released (current release v1.0.1, 2026-10-23); the Android edition is
feature-complete and audited but not yet in a release, for the
signing-key reason stated plainly in the Status section below.

## Status

**v1.0.1 — the current release — was published on
2026-10-23.** It carries the Windows edition (v0.3.1) and the
Debian edition (0.2.1): the post-v1.0.0 fix wave and the Debian
parity fixes, built from the release commit, with published
checksums verified by re-download. **v1.0.0 — the first public
release — was published the same day**, carrying the Windows
edition (v0.3.0) and the Debian edition (0.2.0). Both releases'
notes name what is proven and what is not: the three
real-machine passes (Android phone, Windows machine, Debian
machine) are still owed, and until they land Sphinx is
audited, tested software whose last hardware proofs are still
in front of it.

The **Android edition is feature-complete** per the
[roadmap](docs/ROADMAP.md). The DNS filter runs on a bundled
71,491-domain list, updates itself from public list sources when
you tap the button (with a sanity check and an atomic swap, so a
bad download can never wipe your protection), honors your
allowlist, and keeps a short on-device query log. On top of
that: your own custom block entries; per-app rules (exempt an
app from filtering, or block an app outright — with the trade
stated plainly above); per-app drop counters; profiles; an
opt-in start on boot; and plain battery handling. The edition
has passed the same build → audit → fix → re-audit gate as the
shipped editions. It is **not** in any release yet, for one plain reason:
a public release APK must be signed with the owner's release
keystore, and that key does not exist yet. The Android APK joins
a release as soon as that one owner step is done; no
debug-signed build ships in its place.

Fixes landed on `main` after the v1.0.0 commit — the
quick-settings tile, truncated-answer completion over TCP, the
Windows W-1–W-7 restore-discipline fixes, and the Fleet Sweep #4
Debian parity fixes (the liveness-proof timeout and the atomic-
write durability fixes, carried to the Debian edition) — were
**not** in v1.0.0. They shipped in **v1.0.1** (2026-10-23),
the current release.

## Building

Requires JDK 17 and the Android SDK (platform 34, build-tools 34).

```
./gradlew :app:assembleDebug      # debug APK
./gradlew :app:testDebugUnitTest  # JVM unit tests (DNS parsing, blocklist)
```

## Credits

Built by **Sentinel Safeguard LLC** — Kansas City, Missouri.
Security for everyone.

## License

Sphinx is released under the [MIT License](LICENSE) — anyone can use
it as they wish.
