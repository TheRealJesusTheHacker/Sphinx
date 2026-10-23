# Sphinx — Shared Tunnel Spec (VPN Mode)

Every Sphinx edition (Android, Windows, Debian, and any that follow)
implements **the same tunnel behavior** on top of the filtering brain
in [FILTER-SPEC.md](FILTER-SPEC.md). This file is that behavior, in
plain language. If an edition behaves differently from this spec,
the edition is wrong — fix the edition, or change the spec on
purpose and in the open.

## What VPN mode is — and is not

The blocker (FILTER-SPEC) questions DNS names on the device itself.
Nothing leaves the device for filtering; that promise is unchanged
and it is scoped to blocker mode.

**VPN mode is a real tunnel.** The user picks a server — a *server
profile* — and the edition routes the device's traffic through
that server, encrypted, so the device's public address becomes the
server's address. That is what a VPN is, and every edition says so,
in the app and in its README, where the mode is offered:

> In VPN mode, your traffic passes through the server you choose —
> that's how a VPN works. Sphinx ships no servers of its own in
> your list; a profile is a server you added or one your provider
> gave you.

Hard rules that follow:

- **The server list starts empty.** No bundled servers, no sample
  locations, no mock entries — ever. The first-run state is an
  honest "add your server" path.
- **Sphinx operates no VPN servers for users.** A profile is the
  user's own server, their employer's, or their provider's. The
  `server/` package in this repo lets anyone run their own; it
  does not make Sentinel Safeguard the operator of anything.
- **The same-domain ad limit is untouched.** A tunnel changes
  where traffic exits; it does not change what a name lookup can
  and cannot separate. YouTube's ads still come from YouTube's
  servers, tunnel or no tunnel.

## Server profiles

A **server profile** is the unit of the picker: one named server
the user can connect to. Every profile names its **protocol**.
This build implements `wireguard`. Other protocol values may be
*recognized* (see "Public volunteer servers" below) but a profile
whose protocol an edition does not implement parses, displays,
and is **refused at connect time with a plain explanation** —
never silently ignored, never half-connected. (Phase 1
implements `wireguard` everywhere; Phase 2 adds `openvpn`
connections on the editions whose licensing gate passes —
see "Public volunteer servers" below.)

### WireGuard profile fields

A WireGuard profile carries exactly what the WireGuard protocol
itself needs:

- **Name** — the user's label for the server ("Home", "Office —
  Toronto"). On import from config text, the name comes from the
  Sphinx name comment when present (below), else from the file
  name, else the user is asked. A name is a label only; it is
  never trusted as a location claim.
- **Endpoint** — `host:port` of the server. A hostname endpoint
  is resolved **before** the tunnel engages, using the
  pre-tunnel resolver, and that answer is pinned for the
  session (the tunnel cannot resolve its own doorway from
  inside itself). If the name stops resolving mid-session the
  tunnel reports unreachable — it does not re-resolve through
  the tunnel and does not fall back to anything.
- **Server public key** — the profile *is* this pin. WireGuard
  authenticates the server cryptographically: a machine at the
  endpoint presenting a different key **cannot complete a
  handshake**, and the edition reports exactly that — "the
  server's identity did not match this profile" — never
  "connected", never a silent retry against a different key.
- **Client addresses** — the tunnel addresses assigned to this
  device (`Address`), IPv4 and/or IPv6 as the profile states.
- **Allowed IPs** — which traffic enters the tunnel. The
  profile's value is authoritative. `0.0.0.0/0` (and `::/0`
  when present) means *all traffic*; anything narrower is a
  split tunnel, and the UI says "some traffic" for it, in those
  words or plainer — a split tunnel is never presented as full
  protection.
- **DNS servers** — the resolvers used while the tunnel is up
  (see the mode model for how they interact with the blocker).
  Absent a DNS field, VPN-only mode uses the system resolvers
  reached through the tunnel; the UI does not claim otherwise.
- **The client's own keypair, per profile** — generated **on
  the device** the first time the profile is created locally,
  or imported as part of a provider config. The private key
  never leaves the device except inside an export the user
  explicitly makes (below). Keypairs are generated with a
  vetted Curve25519 implementation for the platform — never
  hardcoded, never derived from the profile name, never shared
  between profiles unless the user imports the same key twice
  on purpose.
- **Optional fields, preserved end-to-end**: preshared key,
  persistent keepalive, MTU, and the peer's own allowed-IPs as
  distinct from the interface's where the config separates
  them. An edition may not drop a field it does not use; it
  preserves it or refuses the profile loudly at import.

### Config text: the interchange format

The standard WireGuard config text (`[Interface]` / `[Peer]`,
the format `wg-quick`, the official apps, and every provider
export) is Sphinx's import/export format. Interoperability with
the wider WireGuard ecosystem is a feature, not an accident.

- **Round-trip is lossless.** Parse → export reproduces the
  profile exactly: every recognized field, every unrecognized
  line preserved in order in an "extra" bag, comments included.
  Export of an unmodified imported config equals the imported
  text, modulo a single trailing-newline normalization. A
  field an edition cannot represent is a field it refuses at
  import — silent data loss is a spec violation.
- **Sphinx writes its profile name as a comment** on the first
  line of its own exports: `# Sphinx profile: <name>`. Other
  WireGuard tools ignore comments; Sphinx reads its own back.
  The name comment is metadata, never a config directive.
- **Validation happens at import, against the corpus** (below).
  Keys must be 32-byte base64 (44 characters, canonical
  padding); endpoints must carry a port; addresses and
  allowed-IPs must parse as CIDR. A malformed profile degrades
  the way FILTER-SPEC profiles degrade: the bad profile is
  refused with the reason named, the rest of the store is
  untouched, and no profile is ever half-written (atomic
  replace, the fleet's store discipline).
- **Private keys in storage** live in the most protected
  per-edition store available (Android: app-private storage;
  Debian: a root-only directory, files `0600`; Windows: the
  per-user data folder), and **never in logs, never in the
  query log, never in diagnostics**. Test fixtures and doc
  examples use clearly-marked example keys only.
- **Android QR import** accepts exactly this same config text
  carried in a QR code. There is no second format.

## The mode model

Four modes. The blocker modes behave exactly as FILTER-SPEC
says; VPN mode adds the tunnel without quietly changing them.

1. **Off** — nothing runs.
2. **Blocker only** — today's behavior, untouched.
3. **VPN only** — the tunnel is up. All traffic the profile's
   allowed-IPs cover routes through the server. DNS goes to the
   profile's DNS servers *through the tunnel*, **unfiltered** —
   the brain is not in this path and the UI says so ("ads are
   not blocked in this mode" or plainer).
4. **VPN + Blocker** — the tunnel is up **and** DNS queries
   pass the FILTER brain first. Allowed queries are forwarded
   to the profile's DNS servers through the tunnel; blocked
   queries get the FILTER-SPEC sinkhole answer locally. The
   status shows both facts ("VPN on — <profile>" and "ad
   blocking on"), never a merged claim.

Arbitration rules, every edition:

- **One tunnel at a time.** Connecting a second profile
  disconnects the first through the ordinary stop path first —
  no overlap, no third state.
- **A mode states what it cannot do, where it is offered.**
  Each edition's existing disclosure discipline (Android's
  FILTER / APP_BLOCK trade statement is the model) extends to
  the tunnel: VPN + Blocker on Android is a third population
  shape and says what bypasses it (below); split tunnels say
  "some traffic"; VPN-only says DNS is unfiltered. A limitation
  the user can discover is a limitation the UI failed to state.
- **Disconnect returns to the mode the user had before VPN**
  (Blocker only, or Off) through the ordinary stop path — and
  the connect screen says that before the user connects.
- **Intent and resumption follow the blocker discipline.**
  Intent is recorded only at *successful* transitions. A
  tunnel that was up at shutdown resumes on boot / sign-in
  only if its intent was on — and only by re-proving the
  handshake; a leftover or unknown tunnel state is shown as
  a leftover and waits for the user, never silently taken
  over, never silently dropped.

### Android population honesty (third shape)

In TUNNEL shapes (modes 3 and 4) the VPN interface carries a
default route for the whole device **except** apps the user
excludes. An excluded app bypasses the tunnel entirely — its
traffic leaves the device directly, with the device's real
address, and in mode 4 its DNS is not filtered either (it never
enters the interface). The picker where exclusions are set
states this in plain words. Apps blocked outright under
FILTER-SPEC's app-block rule cannot be "blocked" inside a
tunnel shape; offering both at once is refused with the trade
stated, the same way app-block mode already states its trade
against filtering.

## Kill-switch semantics

**A tunnel that drops never becomes a direct connection by
itself.** While VPN intent is armed:

- If the endpoint is unreachable or the handshake goes stale,
  covered traffic **blocks** — it does not fall back to the
  device's direct route, not for DNS, not for anything the
  profile covers. The status says so in plain language
  ("VPN disconnected — traffic is blocked, not going around
  the tunnel") with the user's two visible choices: reconnect,
  or disconnect intentionally (which returns to the pre-VPN
  mode, per the mode model).
- A tunnel counts as **connected** only when a handshake has
  completed *and* is fresh (per the backend's latest-handshake
  report) — and, where the platform allows, a routed-traffic
  proof agrees. Status never claims "connected" from intent,
  from configuration, or from a process merely running.
- Platform bounds, stated honestly per edition:
  - **Debian / Windows**: routes and DNS are Sphinx-managed,
    so a dead tunnel blackholes covered traffic exactly as
    above until the user acts; teardown restores the exact
    pre-tunnel state through the same save-first / verify /
    exact-restore discipline as the DNS guard, in the order:
    tunnel down first, then DNS restore.
  - **Android**: while the Sphinx service lives, a dead
    backend drops packets — nothing is forwarded outside the
    tunnel. If Android itself kills the service, Android
    tears its VPN down with it; Sphinx mitigates with the
    intent/resume discipline and by surfacing Android's own
    "always-on VPN" and "block connections without VPN"
    settings, in the app, as the user's choice — it does not
    change those settings itself and does not claim a
    stronger guarantee than the platform gives.

## Logging honesty

- The client logs **no traffic content** in any mode. In VPN
  modes the client necessarily *carries* encrypted packets;
  carrying is not inspecting, and no payload is read, stored,
  or counted beyond byte/packet counters the backend reports.
- The FILTER-SPEC query log is unchanged: memory-only, 500
  entries, names and verdicts, in blocker paths only. In
  VPN + Blocker mode the log records the same DNS facts it
  always did — the queries Sphinx itself answered or
  forwarded — and nothing about other traffic.
- Connection facts the UI may show (profile name, connected
  since, bytes up/down) are display state, memory-only, the
  same discipline as the drop counters. Nothing about a
  tunnel session is written to permanent storage except the
  tunnel state record (mode, profile, intent — no traffic
  data) each edition already keeps for its resume discipline.

## Licensing of tunnel components

Sphinx is MIT (the owner's order) and its license story must
stay honest: every tunnel component is either **bundled**
(shipped inside the edition) or **invoked** (a separate
program the edition runs at arm's length), and the difference
is stated wherever the edition's licensing is stated.

- **Android — bundled, clean.** The official WireGuard tunnel
  library (`com.wireguard.android:tunnel`) is Apache-2.0;
  its userspace backend is wireguard-go, MIT. Bundling either
  does not change Sphinx's license. Apache-2.0 requires the
  license text and attribution to travel with the app; the
  edition ships them (a notices screen/file).
- **Debian — invoked, clean.** The edition drives the kernel's
  WireGuard through `wireguard-tools` (`wg`, `wg-quick`),
  GPL-2.0 programs the .deb declares as a package dependency
  and executes as separate processes. Nothing GPL is bundled,
  linked, or copied into Sphinx; arm's-length execution of a
  system tool does not attach its license to Sphinx.
- **Windows — evaluated, route recorded in the edition.**
  Wintun's *source* is GPLv2, but the prebuilt `wintun.dll`
  from wintun.net is distributed under WireGuard LLC's
  permissive binary terms expressly for redistribution
  unmodified; wireguard-nt follows the same binary model.
  Supervising the official WireGuard for Windows tunnel
  service (a separate GPLv2 program the user installs) is the
  arm's-length alternative. Whichever route the edition
  takes, it ships the component's own license text, says
  bundled-vs-invoked in its README, and never represents a
  GPL component as MIT-licensed. If neither route can be
  taken without misrepresenting a license, the edition stops
  and reports instead of shipping around it.
- **OpenVPN (Phase 2 of this program — see below).** The
  OpenVPN community client binary is GPLv2: *invoking* a
  system `openvpn` (the desktop pattern) is arm's-length and
  clean. On Android there is no system binary to invoke; the
  embeddable options are ics-openvpn (GPLv3) and the
  OpenVPN 3 core (AGPLv3) — linking either into the APK
  would make the combined Android work GPL/AGPL and end the
  edition's honest MIT story. The owner's approval of public
  nodes is **not** approval of a license change: if Android
  OpenVPN cannot be built without contaminating the MIT
  story, that edition's public-node leg stops and reports
  the conflict with alternatives. Everything else proceeds.

## Public volunteer servers (VPN Gate directory — Phase 2)

The owner asked how other products offer "so many servers,"
and on 2026-10-23 approved building this route: *"Public
nodes a go."* It is Phase 2 of this same program — after the
WireGuard core, under the same build → audit → fix → re-audit
discipline. The honest map:

**Where the servers come from.** Commercial VPNs rent or own
fleets. The volunteer world is essentially one project: **VPN
Gate** (University of Tsukuba's academic research project),
whose relay servers are volunteers' own machines, published as
a live list with an API (a CSV feed whose rows carry country,
score, and the server's whole OpenVPN config as base64). Its
protocols are **OpenVPN, SoftEther, L2TP/IPsec, and MS-SSTP —
not WireGuard.**

**There is no large public WireGuard equivalent, for a
structural reason.** A published OpenVPN config works for
everyone who downloads it: the server's certificate is in the
file and the trust is one-directional. WireGuard has no
certificates and no handshake enrollment: the server must
register *each client's public key* as a peer, with an
assigned tunnel address, before that client can connect at
all. A static published file therefore cannot grant WireGuard
access — a public WireGuard service needs an enrollment step
(an API that takes the client's public key and returns a
profile), which is why public WireGuard access exists only
inside account-based services, free tiers included, never as
an anonymous published list.

**What ships in Phase 2 (normative — an edition that skips a
rule here does not ship the feature):**

- **An opt-in directory inside the server picker**, sourced
  from VPN Gate's published feed, visually and verbally
  distinct from the user's own profiles. It is **never
  pre-enabled**: the user opens the public-nodes section on
  purpose, and the section is labeled as what it is — public
  volunteer servers, run by strangers, not Sentinel's
  servers, not Sphinx servers.
- **The disclosure rides at the point of use**, in the
  picker itself and again at connect, in plain words to this
  effect: *These are strangers' machines. The operator can
  see your traffic. The VPN Gate project states that its
  servers keep connection logs — your real address, the
  times, the server you used — for three months or more.
  Fine for appearing to be somewhere else; not for anything
  sensitive.* A directory shipped without that warning, in
  that place, is a spec violation.
- **Rows become ordinary OpenVPN profiles.** Connecting uses
  each edition's OpenVPN engine (below) under the same mode
  model, kill-switch semantics, and logging honesty as
  WireGuard — with one stated difference: an OpenVPN profile
  has no pinned client keypair enrollment; identity is the
  server certificate inside the config, and the profile is
  trusted exactly as far as its source (the feed) is.
- **The feed is fetched fresh at use time.** The list churns
  hourly; no snapshot is bundled and nothing cached is ever
  presented as live. A cache may be shown with its **age
  labeled** ("list from 2 hours ago"); a dead feed shows an
  honest empty state ("couldn't fetch the list — check your
  connection"), never last week's servers dressed as
  today's.
- **Engines, through the licensing gate:** Debian and
  Windows invoke the system `openvpn` binary (GPLv2,
  arm's-length — clean) under the same save-first / verify /
  exact-restore guard discipline as the WireGuard path;
  a missing binary is an honest "OpenVPN isn't installed"
  state with the remedy named, never a silent failure.
  Android has no system binary: its embeddable options are
  GPLv3 / AGPLv3 (above). Unless an embed route is found
  that keeps the edition's MIT story true, **Android's
  public-node leg stops at the directory + disclosure layer
  with the connect action refused and the reason stated**,
  and the conflict is reported to the owner with
  alternatives — the approval of public nodes does not
  silently relicense the app.
- Profiles are protocol-extensible (above) precisely so an
  OpenVPN profile is a *format* the store holds and labels
  from Phase 1, and a *connection* in Phase 2. In Phase 1 an
  OpenVPN profile parses, displays, and is refused at
  connect with the reason named — that refusal is the
  honest Phase 1 behavior, not a bug.

## The canonical corpus

`docs/tunnel-corpus.json` is to the tunnel what the shared
blocklist pin is to the brain: **one file, every edition's
suite reads it.** Each case names a config text (or an import
input) and the expected verdict — the parsed profile facts
(name, protocol, endpoint, server key, addresses, allowed
IPs, DNS, extras preserved) or the named refusal reason, and
the exact export text for round-trip cases. An edition that
disagrees with the corpus is wrong, the same rule as
FILTER-SPEC. The corpus uses clearly-marked example keys
only; no real key material appears in it, in tests, or in
docs.

## What this spec does not promise

- **No server is vouched for.** A profile connecting proves
  the machine at the endpoint holds the profile's key (for
  WireGuard) — nothing about who operates it or what they do
  with traffic. Choosing a server is trusting its operator
  with your traffic; the editions say so where servers are
  added.
- **No anonymity claim.** A tunnel changes the address the
  world sees and encrypts the path to the server. It does not
  make the user anonymous, and no edition's copy says it does.
- **Server-side behavior is the operator's.** The `server/`
  package ships a no-logging *posture by configuration* for
  people running their own; Sphinx the client cannot verify
  or promise what any server actually does.
