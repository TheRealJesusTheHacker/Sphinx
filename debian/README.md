# Sphinx — Debian edition

**Every request gets questioned.**

Sphinx is Sentinel Safeguard's free, system-wide ad and tracker
blocker. It filters the DNS lookups your machine makes: names on
its blocklist are answered locally with a sinkhole (0.0.0.0, so the
connection goes nowhere), and everything else is forwarded to the
upstream resolver unchanged. Sphinx sees *names only* — it never
inspects, decrypts, or modifies the contents of any connection.

This is the Debian edition. The filtering brain is shared with the
Android and Windows editions and specified in
[../docs/FILTER-SPEC.md](../docs/FILTER-SPEC.md) — the editions
agree on the lists (the bundled list parses to exactly **71,491
domains** in every edition) and on the matching rules.

## What this is, and what it is not

The Debian edition, through Phase 2:

- the filter daemon (a hardened systemd service) listening on
  loopback — 127.0.0.1 and ::1, UDP and TCP, port 53;
- the bundled blocklist, loaded through the spec's sanity gate,
  as the floor beneath any downloaded lists;
- `sphinx engage` / `sphinx restore` / `sphinx status` — turning
  the filter on and off under the restore discipline below;
- `sudo sphinx update` — fresh blocklists from Sphinx's two shown
  sources, under the spec's update rules (see "List updates");
- `sphinx allow` / `sphinx block` — your own rules, and
  `sphinx profile` — named sets of them;
- the `.deb` package (`packaging/build-deb.sh`).

It is **not** the finished product:

- **No graphical interface yet.** The command line is the whole
  interface.
- **The update sources are shown but not yet editable from the
  command line.** `sphinx update` names the two sources it
  fetches from; changing that list from the CLI is later work.
- **Boot and route changes never re-point anything by
  themselves.** The resolved engagement is runtime state on the
  one link that carried the default route when you engaged — a
  reboot, a link bounce, or the default route moving to another
  connection ends it. What happens then is a *resumption*, and it
  is honest about being one: Sphinx remembers that protection
  was on (an intent record written only when a change was
  verified), the service's journal notes the leftover at start,
  and `sphinx status` shows the saved record waiting and names
  your choice — `sudo sphinx engage` turns Sphinx back on
  (against the saved settings; on the connection that carries
  your traffic now, if that changed), `sudo sphinx restore` puts
  the saved settings back and finishes turning it off. Nothing
  is ever re-pointed or restored behind your back, and status
  shows a leftover (a saved record waiting), never a false "on."

## The honest limit

Ads served from the **same domain as the content itself** — YouTube
and YouTube Music are the famous cases — **cannot** be blocked by
any DNS filter, Sphinx included: the lookup name is the content's
own name. No edition claims otherwise.

## Installing

Build the package from a checkout of this repository:

```sh
sh debian/packaging/build-deb.sh        # writes debian/dist/
sudo apt install ./debian/dist/sphinx_0.2.1_all.deb
```

The package is architecture `all` (pure Python, standard library
only, plus data files) — there is nothing compiled to be
architecture-specific.

**Installing never changes your DNS.** The post-install step only
creates the `sphinx` service user and the state directory. The
service is not started or enabled by the install. Turning Sphinx
on is always a separate step you take yourself:

```sh
sudo systemctl enable --now sphinx   # start the filter
sudo sphinx engage                   # point this machine's DNS at it
sphinx status                        # the truth, from real reads
sudo sphinx restore                  # turn it off, settings back exactly
```

## List updates

```sh
sudo sphinx update
```

`sphinx update` downloads fresh copies of the two blocklists
Sphinx shows — **StevenBlack unified** (ads & malware) and
**HaGeZi Multi LIGHT** (ads, trackers, telemetry) — under the
shared spec's rules:

- **HTTPS only, every hop.** Redirects are followed by hand and
  each one is checked: a hop that drops to plain HTTP fails the
  download.
- **Every list is parsed and sanity-checked** (at least 1,000
  domains) before it may replace anything, and the combined set
  must pass the same gate on unique domains.
- **All-or-nothing.** If any source fails, the update has
  failed: nothing is swapped, every source keeps the copy it
  had, and the "last updated" time Sphinx reports does not move.
- **Manual only.** Updates happen when you run the command —
  never on a timer, never in the background.

Downloaded lists, while valid, are the blocklist; the bundled
list stays underneath them as the floor, so no update can leave
the filter listless. The running service notices new lists (and
rule edits, and profile switches) on its own and uses them from
the next question it answers — no restart.

## Your own rules, and profiles

```sh
sudo sphinx allow add example.com      # never block this name (or its subdomains)
sudo sphinx block add tracker.example.net
sphinx allow list                      # reading needs no sudo
sudo sphinx block remove tracker.example.net
```

Your rules live in `/var/lib/sphinx`, edited by the command as
root and read by the service. An allowlist entry wins over every
list, per the spec; a custom block entry blocks on top of every
list. Entries go through the same checks the list parser uses —
a single word, an IP address, or a reserved local name is
refused with the reason, because such an entry could never do
what it appears to do. List updates never overwrite your rules,
and your rules are never query history: the query log stays in
the service's memory only, and nothing in this directory records
what was asked.

**Profiles** are named sets of those two rule lists:

```sh
sudo sphinx profile save Home     # snapshot the current rules as "Home" (now active)
sudo sphinx profile use Quiet     # switch the live rules to "Quiet"
sphinx profile list               # what exists, and which is active
sudo sphinx profile delete Quiet
```

While a profile is active, editing your rules edits the profile
too — what it says is what it does. Switching applies the chosen
profile's rules to the running filter without ever modifying the
profile you switched *from*. A profile holds **only your rules** —
never the blocklists or their sources — so switching profiles
cannot change which lists Sphinx questions with. Deleting a
profile deletes only the snapshot; the rules in force stay as
they are.

## How turning it on works (the restore discipline)

Turning a machine's DNS over to anything is a trust exercise, so
`engage` follows the fleet's toll discipline — no step is skipped:

1. **The filter proves it answers first** — on each loopback family
   separately, with a real question the daemon answers without
   counting it as your traffic. A family is only ever pointed at a
   loopback that answered. If the service is not running, engage
   refuses and says so; nothing changes.
2. **Your current settings are saved before any change**, and the
   save is verified by reading it back. No verified save, no
   change. An existing saved record is **never overwritten** — if
   Sphinx was left on (or died) earlier, its record is the truth,
   and re-engaging works against it. A loopback address is **never
   recorded as an "original"**: if DNS already points at a resolver
   on this machine and Sphinx has no record of what came before,
   engage refuses — those previous settings are unknowable, and
   Sphinx will not guess at settings it cannot restore.
3. **Every change is verified** by reading the resolver back, and
   by a live question through the new path. Anything that fails is
   rolled back to the saved settings, and the record is kept.
4. **Restore is exact and verified.** `restore` puts back exactly
   what was recorded, verifies it, and only then retires the
   record. A restore that cannot be verified **fails loudly** and
   keeps the record. Uninstalling keeps the same rule: the
   package's pre-removal step runs the restore before any file is
   removed, and stops the removal if the restore cannot be
   verified.

### Which machines Sphinx can turn on

- **A plain `/etc/resolv.conf`** that you maintain yourself (the
  "direct" setup). Engage rewrites it — keeping every
  non-nameserver line (search domains, options) — and restore puts
  back the recorded file **byte-for-byte**.
- **systemd-resolved in its standard stub setup** — resolv.conf
  points at 127.0.0.53, and resolved manages the rest. Engage sets
  a runtime override on your connection (`resolvectl dns`), and
  restore removes it (`resolvectl revert`), which returns the
  connection to exactly what its configuration and DHCP provide.
  The override lives on the connection that carried the default
  route when you engaged. If the machine's route later moves to a
  different connection (say, Ethernet unplugged and Wi-Fi takes
  over), that connection was never pointed at Sphinx — status
  shows a leftover rather than pretend the new route is filtered.
  `sudo sphinx engage` is the fix, and it knows the route moved:
  it undoes Sphinx's (now inactive) setting on the old connection,
  saves the *new* connection's own settings, and only then points
  the new connection — the same save-then-point discipline as a
  first engage, never a quiet re-point.
  Two things about this, stated plainly:
  - Sphinx never binds 127.0.0.53 and never touches the stub file:
    that address and file are resolved's own. There is no port
    conflict (Sphinx binds 127.0.0.1, a different address), and no
    query loop (Sphinx's upstream is your configured upstream
    resolver — never the stub, never itself; the daemon refuses to
    start with a loopback upstream).
  - A per-link DNS override you set *by hand* with `resolvectl`
    before engaging is replaced by Sphinx's override while Sphinx
    is on, and restore returns the connection to its automatic
    settings rather than to the hand-set override. Hand-set
    resolvectl overrides are runtime-only by design (they do not
    survive a reboot, and nothing on the machine records them), so
    there is no honest way to promise them back.
- **NetworkManager-managed machines are refused, plainly.**
  NetworkManager owns and re-asserts the DNS settings there;
  Sphinx does not fight it, and will not pretend it can promise an
  exact restore. The same applies to resolver files generated by
  other tools (dhcpcd, resolvconf) and to any setup Sphinx does not
  recognize: engage changes nothing and explains why.

## The service

`sphinx.service` runs the daemon as a dedicated `sphinx` user with
exactly one capability (CAP_NET_BIND_SERVICE, so it can use port
53), `NoNewPrivileges`, `ProtectSystem=strict`, and the rest of
systemd's standard hardening. The daemon writes nothing to disk:
it *reads* its working set from `/var/lib/sphinx` (downloaded
lists over the bundled floor, your rules on top) and watches
those files, reloading the whole set when they change; its query
log lives only in memory (capped at 500 entries, never written
to disk, never sent anywhere), and its counters live in memory
too. Only the command, as root, writes the state directory. The
command talks to the daemon through a control socket in
`/run/sphinx/` to prove liveness and read the real counters —
`sphinx status` reports what the daemon itself says, and says
"not answering" when it isn't.
The socket is deliberately not open to every local user (mode
0660, the daemon's user/group and root), so an unprivileged
`sphinx status` shows the service and resolver state from real
reads and says the counters need `sudo sphinx status` — it never
reports a running daemon as stopped just because it may not read
its counters.

While the filter runs, it counts questions blocked and let
through. Allowed questions are forwarded unchanged along the
spec's upstream chain: the upstream resolver (standard:
**1.1.1.1**, fallback **9.9.9.9** — the shared spec's resolvers),
then this machine's own DNS servers as the chain's floor — read
from the settings saved when Sphinx was turned on, so a network
where the public resolvers cannot be reached (an ISP that
intercepts outside DNS, a filtered port 53, a captive portal)
still answers allowed names through the network's own resolver
instead of silence. The forwarding discipline is the spec's: a
connected socket per question, the answer accepted only from the
resolver it was sent to with the matching ID and response bit
set, one 3-second budget per resolver, truncated answers
completed over TCP, and the resolver that last answered tried
first on the next question. You can set your own upstream in
`/etc/sphinx/sphinx.conf`; the floor is automatic and is never
a resolver on this machine itself.

## Removing

```sh
sudo apt remove sphinx     # restores your DNS first — and verifies it
sudo apt purge sphinx      # also removes the saved state and the user
```

A plain remove leaves `/var/lib/sphinx` (the saved DNS record,
the recorded on/off decision, downloaded lists, your rules, and
your profiles) in place, so a reinstall picks up where it left
off; purge deletes it. Your `/etc/sphinx/sphinx.conf`
edits are a conffile: kept on remove, removed on purge, by dpkg's
usual rules. Two removal details, stated plainly: the pre-removal
restore runs only when a saved record actually exists (a machine
Sphinx never engaged has nothing of Sphinx's to restore, and an
unrelated resolver on this machine — a hand-run local DNS server,
say — never traps the package into being unremovable); and an
**upgrade runs the same restore**, so upgrading the package turns
Sphinx off and puts your saved settings back — run
`sudo sphinx engage` after an upgrade to turn it on again.

## Layout

```
debian/
  src/sphinx_deb/
    core/       the shared brain: lists, wire format, forwarding,
                the filter engine, the store, the updater, the
                profile model (pure Python, stdlib only)
    resolver/   stack detection, the engage/restore guard, proofs
    daemon.py   the service entry point
    control.py  the daemon's local control socket
    cli.py      the sphinx command
  tests/        the suite (core parity, forwarding discipline,
                guard on fakes, store/updater/profiles, CLI,
                packaging) — never touches the host's real
                resolver configuration
  packaging/    dpkg-deb build, control metadata, maintainer
                scripts, the systemd unit, the default config
```

## Status

Debian Phase 2, version **0.2.1** — shipped in Sphinx **v1.0.1
(2026-10-23)**, carrying the liveness-proof and atomic-write
parity fixes; first shipped as 0.2.0 in v1.0.0 the same day. The suite and the package build run locally and
in CI (`.github/workflows/sphinx-debian.yml`).

**Not yet proven on a real machine** — this edition was built and
tested on fakes and a build VM, and no real machine's DNS has been
touched by it. The end-to-end pass on real Debian hardware —
engage, reboot behavior, restore, an install/remove cycle — was
named in the release notes as still owed; both releases
shipped with that stated plainly rather than waiting on it.
