# Sphinx — Windows edition (SPHINX.EXE)

The Windows edition of Sphinx: the same filtering brain as every
edition (the shared rules in [../docs/FILTER-SPEC.md](../docs/FILTER-SPEC.md)),
running as a local DNS filter on this machine.

**Status: Phase 1 — the core filter service, landed.** The filter,
the list engine, the system-DNS engagement with its restore
discipline, and a plain functional window exist and are tested. What
does *not* exist yet: an installer, HUD polish, a system-tray host,
and a background Windows service — Phase 1 runs as an app you keep
open (closing the window stops the filter cleanly, restoring DNS
first). The release gate in the roadmap (independent audit → fix →
re-audit, signed builds, published checksums) has not run for this
edition; nothing here is a finished public release.

## How it works

- Sphinx listens for DNS queries on the loopback addresses —
  **127.0.0.1 and ::1**, port 53. (Both families: Windows consults
  IPv6 DNS servers in parallel with IPv4 ones, so an IPv4-only
  listener would leave a bypass lane open.)
- When you turn it on, Sphinx points the DNS settings of the
  adapters that carry your connections (up, with a default route)
  at those loopbacks. Blocked names get the spec's sinkhole answer
  (0.0.0.0 / ::, TTL 60); allowed queries are forwarded unchanged
  to 1.1.1.1 (fallback 9.9.9.9) under the spec's answer-validation
  rules — connected socket, matching ID, response bit, one overall
  3-second deadline — with truncated answers completed over TCP.
- Everything runs on this machine. There is no Sphinx server, no
  account, and the query log never leaves memory.

## The restore discipline (read this — it's the point)

Changing a machine's DNS can break its networking, so Sphinx treats
the original settings the way Charon treats its restore point:

1. **Administrator rights are required** to change DNS. Without
   them, Sphinx says so plainly and changes nothing.
2. Before anything changes, the current settings of every adapter
   it will touch are **saved to `dns-backup.json` in the data
   folder — and read back to prove the save is real.** No verified
   save, no change.
3. An existing backup is **never overwritten**: if one is on disk,
   its recorded settings are the truth, so a loopback address can
   never be recorded as an "original."
4. Every change is verified by reading the adapter back. A failure
   midway rolls back the adapters already changed.
5. Turning Sphinx off (or closing its window) restores the recorded
   settings **exactly** — including "automatic (DHCP)" where that
   was the original state — verifies each one, and only then
   deletes the backup. If a restore can't be verified, the filter
   stays running (a working resolver beats a dead one) and the
   window says what failed.
6. If Sphinx starts and finds a backup whose settings are no longer
   in force (a crash, a hand edit), that is shown as its own state —
   with Restore and Dismiss offered — never silently treated as
   "on," and DNS that points at a loopback Sphinx has no record of
   is never taken over, because it could not be restored honestly.

Before DNS is pointed at the filter, the filter must prove it
answers on each loopback it bound; before that proof, nothing about
the machine's DNS changes.

## Lists

The same brain-data as the Android edition: the bundled StevenBlack
unified list (**71,491 domains**, the identical file), the same two
default sources, the same gates — HTTPS only, every redirect hop
vetted, a download must parse to at least 1,000 domains, the
combined replacement set must pass the same gate, swaps are atomic,
a failed update changes nothing, and updates happen **only when you
tap the button**. The allowlist always wins; your own block entries
live in their own file where list updates never touch them.

## Running from source

```
cd windows
pip install -r requirements.txt
python -m sphinx_win.app.main        # with src/ on PYTHONPATH
```

(Set `PYTHONPATH=src`, or `pip install -e` style usage — the test
suite's `tests/conftest.py` shows the path setup.) Tests:
`pip install -r requirements-dev.txt`, then `python -m pytest`.

Data directory: `%LOCALAPPDATA%\Sphinx` for an installed/frozen
build; a `portable.txt` beside a frozen exe switches to `.\data`
next to the exe (the portable edition); `SPHINX_DATA_DIR` overrides
both; from source, `~/.sphinx`.

## Building

`packaging/build-portable.ps1` produces `dist\Sphinx.exe` (one
file), `dist\SphinxPortable.zip`, and `dist\SHA256SUMS.txt`. The
GitHub Actions workflow `.github/workflows/sphinx-windows.yml` runs
the tests and this build on windows-latest for every change under
`windows/` — that workflow is the edition's build gate.

## Honest limits, Windows edition

- Same-domain ads (YouTube / YouTube Music) cannot be blocked at
  the DNS layer — the spec's standing honesty rule, unchanged.
- Apps that do their own encrypted DNS (DNS-over-HTTPS inside the
  app) never ask the system resolver, so Sphinx never sees those
  queries — same as every edition.
- Phase 1 filters the adapters that carry a default route at the
  moment you turn it on. Switching networks (a new Wi-Fi, a VPN
  client connecting later) after that can put new adapters outside
  the engagement; turning Sphinx off and on re-engages against the
  adapters then in force. The status line always shows the real
  state.
- Per-app rules are an Android-edition feature (they ride on
  Android's per-app VPN routing); the Windows Phase 1 scope is the
  DNS filter the roadmap's Edition 2 section describes.
