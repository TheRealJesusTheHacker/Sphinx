# Sphinx server package — run your own WireGuard endpoint

This directory is a small, plain package for turning a stock
**Debian 12 or 13 VPS** into a WireGuard server that Sphinx clients
(and any other WireGuard app) can connect to.

Read this first, because it is the whole deal:

> **Running this makes you a VPN operator.** Every client you enroll
> sends its traffic through your machine. That traffic leaves your
> machine with **your IP address** on it, as if you had done it
> yourself. You **can see** where your clients' traffic goes — the
> destinations, the timing, the amounts — and for the shrinking
> amount of traffic that is not encrypted end-to-end (plain HTTP and
> the like), you can see the contents too. That is not a flaw in this
> package; **that is what a VPN is.** Only enroll people who trust
> you with that, and only connect to servers whose operators *you*
> trust. Sphinx and Sentinel Safeguard operate no servers for you —
> this package makes *you* the operator, on *your* machine.

There is no account, no subscription, no phone-home, and no panel.
Three shell scripts, one config template, and files you can read.

## What's in here

| File | What it is |
|---|---|
| `install.sh` | One-time setup of the server (idempotent — safe to re-run) |
| `add-client.sh` | Enroll one client, write its Sphinx config |
| `remove-client.sh` | Remove one client — access ends immediately |
| `lib/clients.sh` | Shared logic the two client scripts source (paths, validation, the registry, address assignment) |
| `templates/wg0.conf.tmpl` | The server config template (placeholders only — no real keys, ever) |
| `tests/run.sh` | A smoke test that needs no root and no server |

## Quick start

On the VPS, as root, from this directory:

```sh
sudo bash install.sh --endpoint vpn.example.com:51820
sudo bash add-client.sh my-phone --public-key <public key from the phone>
sudo bash remove-client.sh my-phone        # when it should stop working
```

`--endpoint` is how clients reach this server: a DNS name or the
public IP, a colon, and the listen port (default `51820`). A VPS's
public address is often not visible from inside the machine (the
provider NATs it), so the package never guesses it — you state it,
once at install or per client.

## What install.sh does — step by step, nothing else

1. **Refuses the wrong stage.** Not root, or not Debian (checked in
   `/etc/os-release`): it stops and says why, having changed nothing.
   Debian versions other than 12/13 get a warning, not a refusal.
2. **Installs packages** with apt: `wireguard-tools` and `iptables`
   (the generated config's NAT lines use it) when they are missing.
   `qrencode` is attempted too and is **optional** — if it cannot be
   installed, everything still works; you just don't get QR codes.
3. **Turns on forwarding** through one drop-in,
   `/etc/sysctl.d/99-sphinx-wireguard.conf`: IPv4 always, IPv6 too
   when the machine has IPv6. Delete that file and reboot to undo.
4. **Creates the server keypair — only if none exists.** The private
   key goes to `/etc/wireguard/server-private.key`, mode `0600`. If a
   key (or an existing `wg0.conf` with one) is already there, it is
   **kept**. Re-running install will never regenerate the server key:
   doing so would orphan every client already enrolled, and the
   script says so when it keeps yours.
5. **Renders `/etc/wireguard/wg0.conf`** from the template — **only
   if no config exists.** An existing config is left completely
   untouched, peers and all. Listen port (default `51820`), tunnel
   subnet (default `10.8.0.0/24`, the server takes `.1`) and the
   egress interface (detected from the default route, overridable
   with `--egress-if`) are baked in at that first render.
6. **NAT, the wg-quick way.** The config's `PostUp`/`PostDown` lines
   add forwarding-accept and masquerade rules for the tunnel subnet
   when the interface comes up, and remove them when it goes down.
   A stopped tunnel leaves no rules behind.
7. **Enables and starts `wg-quick@wg0`** and verifies it is active.
   If it is not, the script fails loudly and tells you where to look
   — it never prints success over a dead service.
8. **Writes two bookkeeping files** in `/etc/wireguard`: `clients`
   (the registry, below) and `sphinx-settings.conf` (subnet, port,
   egress interface, endpoint, and the server's **public** key — no
   secrets; the private key is never in it).
9. **Prints a summary** — what changed, what was already in place,
   the server public key, and what to do next.

Every step checks before it changes. Re-running install is the way
you confirm the server is still set up the way you left it.

## The filtering boundary — stated once, plainly

This endpoint **carries all of a connected client's traffic** (for a
full-tunnel profile) and **filters none of it**. Ad and tracker
blocking is the Sphinx *client's* job, done on the device by the
filter — the tunnel changes where traffic exits, not what it is.
There are no blocklists here, no DNS filtering here, and no rule in
this package that drops client traffic: the only iptables lines are
the forwarding-accept and NAT masquerade lines in the template.
Anyone who tells you a plain tunnel endpoint also blocks ads is
selling you something.

## Adding a client

```sh
# Preferred — the keypair was made on the client's device:
sudo bash add-client.sh NAME --public-key <the device's public key>

# Convenience — this server makes the keypair:
sudo bash add-client.sh NAME --generate
```

WireGuard has no sign-up page and no passwords: a client can connect
only because the server has its **public key** registered as a peer
with an assigned tunnel address. That registration is the whole job
of `add-client.sh`:

- It validates the name and the key strictly (a name becomes a file
  name and a config comment; a key is 44 characters of base64 —
  anything else is refused before anything is written).
- It assigns the **next free tunnel address**, tracked in the
  registry (below). Two adds running at the same moment cannot
  collide: every registry and config change happens under a lock.
- It appends the peer to `wg0.conf` and applies it to the **running**
  interface with a single targeted `wg set … peer …` — deliberately
  *not* `wg syncconf`, which would re-apply the whole file. Adding
  your phone does not touch, re-read or drop your laptop's session.
  If the interface is down, the client is still enrolled and
  connects when it starts; the script says which of those happened.
- It writes the client config (mode `0600`) to
  `/etc/wireguard/clients.d/NAME.conf` and prints it.

Useful options: `--endpoint host:port` (override the stored one),
`--dns 10.8.0.1` (see DNS, below), `--allowed-ips 10.0.0.0/8` (a
**split tunnel** — only that traffic enters the tunnel; the script
and the config call it what it is, never full protection),
`--keepalive 25` (default; helps clients behind home NAT stay
reachable — `0` omits it).

### The two key routes, honestly

**`--public-key` (preferred).** Sphinx generates the client's
keypair **on the device**, and only the public key ever reaches the
server. The private key has never existed on your server and cannot
leak from it. Because the server never knew the private key, the
file this route writes is a **profile completion sheet**: a complete,
correctly-shaped config whose `PrivateKey` line reads

```
PrivateKey = YOUR-PRIVATE-KEY-HERE
```

with comments explaining the one edit left: paste in the device's
own private key. As written it **cannot connect** — the placeholder
is not a key and WireGuard will refuse it — and that is deliberate:
an unfinished sheet can never silently half-work with a wrong key.
No QR code is printed for this route, for the same reason.

**`--generate`.** The server makes the keypair and the exported
config is complete and works as-is — and the client's private key
now **exists on your server** (in the `0600` config file under
`clients.d/`, and in your terminal scrollback unless you clear it).
The script prints this warning before it generates anything. Treat
the exported config as a secret: send it over a channel you trust,
and delete the server's copy once the client has it if you don't
want the custody.

### Importing the config in Sphinx

The emitted file is standard WireGuard config text whose first line
is `# Sphinx profile: NAME` — the name comment every Sphinx edition
reads back, and which every other WireGuard tool simply ignores.

- **File:** copy the `.conf` to the device and import it in Sphinx
  (Add server → import from file). Same file also imports into the
  official WireGuard apps.
- **Paste:** copy the printed text and use Add server → paste.
- **QR (Android):** with `--generate`, if `qrencode` is installed,
  `add-client.sh` prints a terminal QR of the complete config —
  scan it with Sphinx's QR import. It contains the private key;
  don't screenshot it or scan it in front of an audience.

## Removing a client

```sh
sudo bash remove-client.sh NAME
```

Removal happens access-first: the peer is removed from the **running
interface first** (the client's access ends that second), then from
`wg0.conf`, then from the registry (its address becomes available
again), and the exported config copy on the server is deleted. If
the live removal fails, the script stops and changes **nothing
else** — the client can still connect and every file still says so,
rather than the paperwork claiming a removal that didn't happen.
Copies of the config already on the client's device are out of your
reach, but they stop working the moment the peer is gone. Removal
is not a pause: to let the device back in, enroll it again.

## Files, permissions, and the registry

Everything lives in `/etc/wireguard` (directory mode `0700`):

| Path | Mode | What it is |
|---|---|---|
| `wg0.conf` | `0600` | The server config — contains the server private key inline, as wg-quick configs do |
| `server-private.key` | `0600` | The canonical copy of the server private key |
| `server-public.key` | `0600` | The server public key (not secret; kept with the rest) |
| `sphinx-settings.conf` | `0600` | Subnet, port, egress, endpoint, server public key — read by `add-client.sh`; no secrets |
| `clients` | `0600` | The registry |
| `clients.d/NAME.conf` | `0600` | Exported client configs (secrets in the `--generate` route) |

The **registry** is a plain tab-separated text file — name, tunnel
address, public key, date added, and key source (`device` or
`server`). It is the record of who *should* have access. You can
read it any time; edit it only with the scripts running stopped, or
better, don't — use the scripts, which keep it, the config and the
live interface in step.

**Key custody, in one place:** the server private key never leaves
the server and is never printed. Client private keys exist on the
server **only** when you chose `--generate`, and then only in that
client's exported config. Backups of `/etc/wireguard` are therefore
backups of keys — encrypt them like it.

## No-logging posture — by configuration, with the edges named

This package's posture is **no logging by configuration**, and here
is exactly what that does and does not mean:

- **WireGuard itself keeps no traffic logs.** It has no log of what
  clients did, visited or sent, because it never writes one.
- **This package adds none.** No daemon, no accounting, no counters
  written to disk, nothing scheduled, nothing sent anywhere. The
  scripts print to the terminal that ran them and exit.
- **What still exists, because pretending otherwise would be a lie:**
  - `wg show` lists the **currently known peers** and each peer's
    latest handshake time and byte counters — while the interface is
    up, in memory. That is the protocol working, not a log file, and
    it is gone at reboot; anyone with root on your server can look
    at it, including you.
  - The **clients registry** — names, addresses, public keys, dates.
    Enrollment is a record by nature; that's the file above.
  - Your **SSH login** is in the system auth log, like any login.
  - **Debian's own system journals** exist as they do on any Debian
    machine; this package neither extends nor ships them anywhere.
  - Your **VPS provider** sees the machine's traffic at their layer
    no matter what this package does. No software on the box can
    change that, and this README won't pretend it can.

## Firewall — your machine, your call, nothing silent

`install.sh` does **not** install, enable or modify any firewall.
Silently changing a machine's firewall is how operators get locked
out of their own servers, and this package doesn't do it. Only two
inbound openings are your concern:

- **SSH** — already how you got in; keep it as you like it.
- **UDP 51820** (or your `--port`) — WireGuard. Clients cannot reach
  the server until it is open **both** in the machine's own firewall
  (if you run one) **and** in any provider firewall / security group
  in front of the VPS.

If you use ufw: `ufw allow 51820/udp`. With nftables, add a rule
like `nft add rule inet filter input udp dport 51820 accept`,
adjusted to your own table and chain names. If you run no firewall
on the box and your provider doesn't filter, there is nothing to
open — the port is already reachable, and that fact is also worth
knowing about your server.

## Reboots, restarts, updates

- **Reboot:** `wg-quick@wg0` is enabled, so the tunnel comes back at
  boot with every peer from `wg0.conf`. The registry and the
  exported configs persist — they are ordinary files. The `wg show`
  handshake state does not persist, because it is not a log.
- **Restart by hand:** `systemctl restart wg-quick@wg0`. Connected
  clients drop and reconnect; their configs don't change.
- **OS updates:** this package has **no updater of its own** — it
  says so rather than implying one. Updating the package means
  copying the newer files from this repo over these and, if you
  like, re-running `install.sh` (safe: it keeps your key, your
  config and your clients). For the OS, enable unattended security
  updates and keep the machine patched — an internet-facing endpoint
  is exactly the kind of machine that gets scanned within hours of a
  disclosure:
  `apt-get install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades`
- **The kernel's WireGuard** updates with your normal Debian kernel
  updates; `wireguard-tools` with normal apt updates.

## DNS — what the client config does and doesn't do

By default the emitted client config has **no `DNS` line**: this
package runs no resolver, and writing `DNS = 10.8.0.1` when nothing
listens there would break the client's lookups while looking
helpful. Without a DNS line, the client keeps its system resolvers,
reached through the tunnel (per the shared tunnel spec). If you run
your own resolver on the server — Unbound, dnsmasq, Sphinx's own
Debian filtering, whatever — pass it when enrolling:
`add-client.sh NAME ... --dns 10.8.0.1`. Filtering DNS for clients
is then that resolver's job and configuration, stated in its own
docs, not implied by this package.

## Limits of this version, plainly

- **IPv4 tunnel addressing.** Assignment, NAT and the registry are
  IPv4. `install.sh` enables IPv6 *forwarding* when the host has
  IPv6, but this version does not assign IPv6 tunnel addresses or
  NAT IPv6; a dual-stack tunnel is future work, not a hidden toggle.
- **One interface** (`wg0`), one subnet, on one machine. No roaming
  of clients between servers, no load balancing, no web panel.
- **The endpoint is a name or an address you supply.** If your VPS's
  public address changes, re-issue client configs with the new
  `--endpoint` (a DNS name you control makes this painless).
- **This package is software and documentation only.** Sentinel
  Safeguard does not run a server for you, cannot see your server,
  and cannot recover its keys. If `/etc/wireguard` is gone, the
  server key is gone, and every client needs re-enrolling. Back it
  up (encrypted) or accept that.

## Licensing

Sphinx is MIT-licensed, including this package. WireGuard and
`wireguard-tools` (`wg`, `wg-quick`) are GPL-2.0 programs: this
package **invokes** them as separate processes installed from
Debian's repositories — it bundles, links or copies none of them —
and nothing about their license attaches to this package's own
files. That invoked-not-bundled line is the one the shared tunnel
spec (`docs/TUNNEL-SPEC.md`) requires, and it is stated here for the
same reason it is stated there: so nobody has to take it on faith.

## Testing

```sh
bash tests/run.sh
```

Renders the template, exercises address assignment and both
enrollment routes and removal against a fixture registry and a fake
`wg`, and syntax-checks every script (plus ShellCheck when it is
available). It needs no root, no server and no network — and passing
it does not prove a real install on a real VPS; it proves the logic
and the file formats. The real proof is a Debian VPS, `install.sh`,
and a phone that connects.
