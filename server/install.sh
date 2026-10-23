#!/usr/bin/env bash
# install.sh - install the Sphinx WireGuard server package on a stock
# Debian 12 or 13 VPS.
#
# What it does (and nothing else - see README.md for the full picture):
#   1. checks it is root on Debian,
#   2. installs wireguard-tools and iptables with apt (qrencode is
#      tried as a nicety and is NOT required),
#   3. turns on IPv4 forwarding - and IPv6 forwarding when the machine
#      has IPv6 - through a sysctl drop-in,
#   4. creates the server keypair in /etc/wireguard (0600) IF none
#      exists. An existing server key is never overwritten: replacing
#      it would orphan every client already enrolled,
#   5. renders /etc/wireguard/wg0.conf from templates/wg0.conf.tmpl
#      IF no config exists yet. An existing config is left untouched,
#      peers and all,
#   6. enables and starts wg-quick@wg0, and checks it is running.
#
# Firewall: this script does NOT install, enable or change any
# firewall. It prints the exact commands that would open the
# WireGuard port, as a recommendation, and the operator runs them -
# or not - themselves. No silent actions.
#
# Filtering: this script adds no traffic-blocking rules of any kind.
# The only iptables lines anywhere in this package are the PostUp /
# PostDown lines in the config template, and they only ADD forwarding
# and NAT masquerade for the tunnel subnet. A tunnel endpoint carries
# the client's traffic; it does not decide which of it is allowed.
#
# Re-running install.sh is safe: every step checks before it changes,
# and a step that finds its work already done says so and moves on.
# A failure stops the script loudly; whatever was already changed is
# named in the summary at the end, never claimed as more than it is.
#
# Usage:
#   sudo bash install.sh [--port 51820] [--subnet 10.8.0.0/24]
#                        [--egress-if eth0] [--endpoint vpn.example.com:51820]
#                        [--enable-only]
#
#   --port        UDP listen port (default 51820)
#   --subnet      IPv4 tunnel subnet (default 10.8.0.0/24)
#   --egress-if   interface holding the default route (default: detected)
#   --endpoint    the server's public host:port clients will use; stored
#                 (not secret) so add-client.sh can fill in client
#                 configs without asking every time
#   --enable-only enable wg-quick@wg0 at boot but do not start it now
#
# Environment overrides exist for the test suite and non-standard
# layouts: SPHINX_WG_DIR, SPHINX_SYSCTL_FILE, SPHINX_TEMPLATE,
# SPHINX_APT (set to "skip" to skip package installation entirely),
# SPHINX_TEST_MODE. A normal install needs none of them.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/clients.sh
. "${SCRIPT_DIR}/lib/clients.sh"

TEMPLATE="${SPHINX_TEMPLATE:-${SCRIPT_DIR}/templates/wg0.conf.tmpl}"
SYSCTL_FILE="${SPHINX_SYSCTL_FILE:-/etc/sysctl.d/99-sphinx-wireguard.conf}"

PORT=51820
SUBNET="10.8.0.0/24"
EGRESS_IF=""
ENDPOINT=""
ENABLE_ONLY=0
CHANGES=()
NOTES=()

note_change() { CHANGES+=("$1"); }
note_info() { NOTES+=("$1"); }

usage() {
    sed -n '2,50p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --port)       [ "$#" -ge 2 ] || sphinx_die "--port needs a value."; PORT="$2"; shift 2 ;;
        --subnet)     [ "$#" -ge 2 ] || sphinx_die "--subnet needs a value."; SUBNET="$2"; shift 2 ;;
        --egress-if)  [ "$#" -ge 2 ] || sphinx_die "--egress-if needs a value."; EGRESS_IF="$2"; shift 2 ;;
        --endpoint)   [ "$#" -ge 2 ] || sphinx_die "--endpoint needs a value."; ENDPOINT="$2"; shift 2 ;;
        --enable-only) ENABLE_ONLY=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) sphinx_die "unknown argument: $1 (see --help). Nothing was changed." ;;
    esac
done

# --- 1. root on Debian -------------------------------------------------------

if [ "${SPHINX_TEST_MODE}" != "1" ]; then
    [ "$(id -u)" -eq 0 ] || sphinx_die "install.sh must be run as root (try: sudo bash install.sh). It installs packages, writes ${SPHINX_WG_DIR} and enables a systemd service. Nothing was changed."
fi

[ -r /etc/os-release ] || sphinx_die "cannot read /etc/os-release, so this system cannot be confirmed as Debian. This package is built for a stock Debian 12/13 VPS and refuses to guess. Nothing was changed."
# shellcheck disable=SC1091 # the file under test is the target system's os-release
. /etc/os-release
if [ "${ID:-}" != "debian" ] && [ "${SPHINX_TEST_MODE}" != "1" ]; then
    sphinx_die "this system reports ID=${ID:-unknown} in /etc/os-release, not Debian. This package is built and tested for a stock Debian 12/13 VPS only. Nothing was changed."
fi
case "${VERSION_ID:-}" in
    12|13) : ;;
    *) sphinx_warn "this Debian reports VERSION_ID=${VERSION_ID:-unknown}; the package targets Debian 12/13. Continuing, but this exact version is untested." ;;
esac

# --- validate the operator's choices before changing anything ----------------

sphinx_valid_port "${PORT}" || sphinx_die "--port '${PORT}' is not a valid UDP port (1-65535). Nothing was changed."
sphinx_parse_subnet "${SUBNET}" || sphinx_die "--subnet '${SUBNET}' is not a usable IPv4 tunnel subnet. Give the network address with a prefix from /8 to /30, e.g. 10.8.0.0/24. Nothing was changed."
SERVER_ADDRESS="$(sphinx_server_address "${SUBNET}")"
if [ -n "${ENDPOINT}" ]; then
    sphinx_valid_endpoint "${ENDPOINT}" || sphinx_die "--endpoint '${ENDPOINT}' is not HOST:PORT (a DNS name, IP or [IPv6] address, a colon, and a port). Nothing was changed."
    endpoint_port="${ENDPOINT##*:}"
    endpoint_port="${endpoint_port%\]}"
    case "${ENDPOINT}" in
        *"]:"*) : ;; # bracketed IPv6 endpoint: its colons are not the port separator to second-guess here
        *)
            if [ "${endpoint_port}" != "${PORT}" ]; then
                sphinx_warn "--endpoint port (${endpoint_port}) differs from --port (${PORT}). That is right when a router or provider forwards a different outside port; otherwise one of them is a typo."
            fi
            ;;
    esac
fi
[ -f "${TEMPLATE}" ] || sphinx_die "config template not found at ${TEMPLATE}. Run install.sh from the server/ directory of a complete copy of this package. Nothing was changed."

# --- egress interface ----------------------------------------------------------

if [ -z "${EGRESS_IF}" ]; then
    if command -v ip >/dev/null 2>&1; then
        EGRESS_IF="$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
    fi
    [ -n "${EGRESS_IF}" ] || sphinx_die "no default IPv4 route was found, so the outside interface cannot be detected. Pass it yourself, e.g.: sudo bash install.sh --egress-if eth0. Nothing was changed by this step."
    note_info "egress interface detected as ${EGRESS_IF} (the default route). Override with --egress-if if that is wrong."
fi
[[ "${EGRESS_IF}" =~ ^[A-Za-z0-9_.-]+$ ]] || sphinx_die "--egress-if '${EGRESS_IF}' contains characters an interface name cannot have. Nothing was changed."

# --- 2. packages ---------------------------------------------------------------

if [ "${SPHINX_APT:-}" = "skip" ]; then
    note_info "package installation skipped (SPHINX_APT=skip); assuming wg, iptables and sysctl are already present."
else
    missing=()
    command -v wg >/dev/null 2>&1 || missing+=("wireguard-tools")
    command -v iptables >/dev/null 2>&1 || missing+=("iptables")
    if [ "${#missing[@]}" -gt 0 ]; then
        command -v apt-get >/dev/null 2>&1 || sphinx_die "apt-get is not available, so ${missing[*]} cannot be installed. This package expects a stock Debian system."
        printf 'Installing: %s\n' "${missing[*]}"
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
        note_change "installed packages: ${missing[*]}"
    else
        note_info "wireguard-tools and iptables already installed; no packages changed."
    fi
    # qrencode only draws the optional QR code in add-client.sh. Its
    # absence costs nothing else, so a failure here is a note, not a stop.
    if ! command -v qrencode >/dev/null 2>&1; then
        if DEBIAN_FRONTEND=noninteractive apt-get install -y qrencode >/dev/null 2>&1; then
            note_change "installed qrencode (optional; used only to draw QR codes for client configs)"
        else
            note_info "qrencode is not installed and could not be added; that is fine - client configs are also written as files and printed as text."
        fi
    fi
fi
command -v wg >/dev/null 2>&1 || sphinx_die "the wg tool is not available after the package step, so no keys can be made. Install wireguard-tools and re-run."

# --- 3. forwarding ---------------------------------------------------------------

want_ipv6=0
if [ -d /proc/sys/net/ipv6 ] && { [ -s /proc/net/if_inet6 ] || ip -6 addr show 2>/dev/null | grep -q 'inet6'; }; then
    want_ipv6=1
fi
sysctl_tmp="$(mktemp)"
{
    printf '# Sphinx WireGuard server - forwarding for the tunnel.\n'
    printf '# Written by install.sh. Deleting this file and rebooting\n'
    printf '# turns forwarding back off.\n'
    printf 'net.ipv4.ip_forward = 1\n'
    if [ "${want_ipv6}" -eq 1 ]; then
        printf 'net.ipv6.conf.all.forwarding = 1\n'
    fi
} > "${sysctl_tmp}"
mkdir -p "$(dirname "${SYSCTL_FILE}")"
if [ -f "${SYSCTL_FILE}" ] && cmp -s "${sysctl_tmp}" "${SYSCTL_FILE}"; then
    note_info "forwarding drop-in already in place at ${SYSCTL_FILE}; unchanged."
else
    install -m 0644 "${sysctl_tmp}" "${SYSCTL_FILE}"
    note_change "wrote forwarding drop-in ${SYSCTL_FILE} (IPv4 forwarding on$( [ "${want_ipv6}" -eq 1 ] && printf ', IPv6 forwarding on - this machine has IPv6' )). Note: the Sphinx tunnel itself assigns IPv4 addresses; see README.md."
fi
rm -f "${sysctl_tmp}"
if command -v sysctl >/dev/null 2>&1; then
    sysctl -q -p "${SYSCTL_FILE}" || sphinx_warn "sysctl could not apply ${SYSCTL_FILE} right now; the settings are in the file and will apply at boot. Check 'sysctl net.ipv4.ip_forward'."
else
    sphinx_warn "sysctl is not available to apply forwarding now; ${SYSCTL_FILE} will apply at boot."
fi

# --- 4. server keys (never overwrite) -------------------------------------------

sphinx_ensure_registry

server_private_key=""
if [ -s "${SPHINX_SERVER_PRIVATE_KEY_FILE}" ]; then
    server_private_key="$(cat "${SPHINX_SERVER_PRIVATE_KEY_FILE}")"
    note_info "existing server private key kept (${SPHINX_SERVER_PRIVATE_KEY_FILE}); it was NOT regenerated, so enrolled clients keep working."
elif [ -f "${SPHINX_WG_CONF}" ] && grep -q '^PrivateKey = ' "${SPHINX_WG_CONF}"; then
    # A config but no key file: adopt the config's key into the key file
    # so there is one canonical copy. The config itself is untouched.
    server_private_key="$(sed -n 's/^PrivateKey = //p' "${SPHINX_WG_CONF}" | head -n 1)"
    sphinx_valid_key "${server_private_key}" || sphinx_die "the existing ${SPHINX_WG_CONF} has a PrivateKey line that is not a valid WireGuard key, and no separate key file exists. Fix the config by hand or move it aside and re-run; nothing was overwritten."
    ( umask 077; printf '%s\n' "${server_private_key}" > "${SPHINX_SERVER_PRIVATE_KEY_FILE}" )
    chmod 0600 "${SPHINX_SERVER_PRIVATE_KEY_FILE}"
    note_change "adopted the private key from the existing wg0.conf into ${SPHINX_SERVER_PRIVATE_KEY_FILE} (0600). The config itself was not changed."
else
    server_private_key="$(wg genkey)"
    sphinx_valid_key "${server_private_key}" || sphinx_die "wg genkey produced output that is not a valid WireGuard key. Stopping rather than writing a broken key."
    ( umask 077; printf '%s\n' "${server_private_key}" > "${SPHINX_SERVER_PRIVATE_KEY_FILE}" )
    chmod 0600 "${SPHINX_SERVER_PRIVATE_KEY_FILE}"
    note_change "generated a new server keypair (${SPHINX_SERVER_PRIVATE_KEY_FILE}, 0600)."
fi
server_public_key="$(printf '%s' "${server_private_key}" | wg pubkey)"
sphinx_valid_key "${server_public_key}" || sphinx_die "could not derive a valid server public key from the private key. Stopping."
existing_public=""
[ -f "${SPHINX_SERVER_PUBLIC_KEY_FILE}" ] && existing_public="$(cat "${SPHINX_SERVER_PUBLIC_KEY_FILE}")"
if [ "${existing_public}" != "${server_public_key}" ]; then
    ( umask 077; printf '%s\n' "${server_public_key}" > "${SPHINX_SERVER_PUBLIC_KEY_FILE}" )
    chmod 0600 "${SPHINX_SERVER_PUBLIC_KEY_FILE}"
    note_change "wrote the server public key to ${SPHINX_SERVER_PUBLIC_KEY_FILE}."
fi

# --- 5. render wg0.conf (only when none exists) ---------------------------------

if [ -f "${SPHINX_WG_CONF}" ]; then
    note_info "existing ${SPHINX_WG_CONF} left completely untouched, including every peer already in it. If you wanted different port/subnet values, edit the file by hand - install.sh will not overwrite a live config."
    conf_port="$(sed -n 's/^ListenPort = //p' "${SPHINX_WG_CONF}" | head -n 1 || true)"
    if [ -n "${conf_port}" ] && [ "${conf_port}" != "${PORT}" ]; then
        sphinx_warn "the existing config listens on port ${conf_port}, not ${PORT}. The existing config wins; --port was ignored."
        PORT="${conf_port}"
    fi
    conf_addr="$(sed -n 's/^Address = //p' "${SPHINX_WG_CONF}" | head -n 1 || true)"
    if [ -n "${conf_addr}" ]; then
        existing_subnet_ip="${conf_addr%/*}"
        existing_prefix="${conf_addr#*/}"
        if sphinx_valid_ipv4 "${existing_subnet_ip}" && [[ "${existing_prefix}" =~ ^[0-9]+$ ]]; then
            base_int="$(sphinx_ipv4_to_int "${existing_subnet_ip}")"
            subnet_base="$(sphinx_int_to_ipv4 $(( base_int - 1 )))/${existing_prefix}"
            if sphinx_valid_subnet "${subnet_base}"; then
                SUBNET="${subnet_base}"
            fi
        fi
    fi
else
    rendered="$(mktemp "${SPHINX_WG_DIR}/wg0.conf.rendered.XXXXXX")"
    sed -e "s|__SERVER_PRIVATE_KEY__|${server_private_key}|g" \
        -e "s|__SERVER_ADDRESS__|${SERVER_ADDRESS}/${SPHINX_SUBNET_PREFIX}|g" \
        -e "s|__LISTEN_PORT__|${PORT}|g" \
        -e "s|__TUNNEL_SUBNET__|${SUBNET}|g" \
        -e "s|__EGRESS_IF__|${EGRESS_IF}|g" \
        "${TEMPLATE}" > "${rendered}"
    if grep -q '__[A-Z_]*__' "${rendered}"; then
        rm -f "${rendered}"
        sphinx_die "the rendered config still contains an unreplaced placeholder, so it was NOT installed. This is a bug in the package or the template; please report it."
    fi
    chmod 0600 "${rendered}"
    mv "${rendered}" "${SPHINX_WG_CONF}"
    note_change "rendered ${SPHINX_WG_CONF} from the template (0600): address ${SERVER_ADDRESS}/${SPHINX_SUBNET_PREFIX}, UDP port ${PORT}, tunnel subnet ${SUBNET}, NAT out via ${EGRESS_IF}."
fi

# Settings for add-client.sh: no secrets - the server's PUBLIC key,
# subnet, listen port and (when given) the public endpoint.
if [ ! -f "${SPHINX_SETTINGS_FILE}" ]; then
    ( umask 077; : > "${SPHINX_SETTINGS_FILE}" )
fi
settings_tmp="$(mktemp "${SPHINX_WG_DIR}/settings.XXXXXX")"
{
    printf '# Sphinx server settings - written by install.sh, read by\n'
    printf '# add-client.sh. No secrets in this file: the server PUBLIC\n'
    printf '# key is meant to be shared; the private key is not here.\n'
    printf 'SUBNET=%s\n' "${SUBNET}"
    printf 'LISTEN_PORT=%s\n' "${PORT}"
    printf 'EGRESS_IF=%s\n' "${EGRESS_IF}"
    printf 'SERVER_PUBLIC_KEY=%s\n' "${server_public_key}"
    if [ -n "${ENDPOINT}" ]; then
        printf 'ENDPOINT=%s\n' "${ENDPOINT}"
    else
        old_endpoint="$(sphinx_setting ENDPOINT || true)"
        [ -n "${old_endpoint}" ] && printf 'ENDPOINT=%s\n' "${old_endpoint}"
    fi
} > "${settings_tmp}"
if [ -f "${SPHINX_SETTINGS_FILE}" ] && cmp -s "${settings_tmp}" "${SPHINX_SETTINGS_FILE}"; then
    note_info "settings file already current (${SPHINX_SETTINGS_FILE}); unchanged."
else
    chmod 0600 "${settings_tmp}"
    mv "${settings_tmp}" "${SPHINX_SETTINGS_FILE}"
    note_change "wrote ${SPHINX_SETTINGS_FILE} (subnet, port, egress interface, server public key - no secrets)."
fi
rm -f "${settings_tmp}"

# Registry exists (sphinx_ensure_registry above) and starts empty; its
# header explains the format to anyone who opens it.
if [ ! -s "${SPHINX_CLIENTS_FILE}" ]; then
    ( umask 077; printf '# Sphinx clients registry - managed by add-client.sh and\n# remove-client.sh. One line per client, tab-separated:\n# name, tunnel address, public key, date added, key source\n# (device = key made on the client, server = key made here).\n' > "${SPHINX_CLIENTS_FILE}" )
    chmod 0600 "${SPHINX_CLIENTS_FILE}" 2>/dev/null || true
    note_change "created the empty clients registry ${SPHINX_CLIENTS_FILE} (0600)."
fi

# --- 6. enable + start ------------------------------------------------------------

if [ "${SPHINX_TEST_MODE}" = "1" ]; then
    note_info "test mode: systemd step skipped."
elif command -v systemctl >/dev/null 2>&1; then
    if [ "${ENABLE_ONLY}" -eq 1 ]; then
        systemctl enable "wg-quick@${SPHINX_WG_IFACE}" || sphinx_die "systemctl could not enable wg-quick@${SPHINX_WG_IFACE}. The files above are in place; try: systemctl enable wg-quick@${SPHINX_WG_IFACE}"
        note_change "enabled wg-quick@${SPHINX_WG_IFACE} at boot (not started now, per --enable-only)."
    else
        systemctl enable --now "wg-quick@${SPHINX_WG_IFACE}" || sphinx_die "systemctl could not enable and start wg-quick@${SPHINX_WG_IFACE}. The files above are in place; check: systemctl status wg-quick@${SPHINX_WG_IFACE} and journalctl -u wg-quick@${SPHINX_WG_IFACE}"
        systemctl is-active --quiet "wg-quick@${SPHINX_WG_IFACE}" || sphinx_die "wg-quick@${SPHINX_WG_IFACE} was enabled but is not active. Check: systemctl status wg-quick@${SPHINX_WG_IFACE} and journalctl -u wg-quick@${SPHINX_WG_IFACE}. The config and keys are in place; nothing is claimed to be running."
        note_change "enabled and started wg-quick@${SPHINX_WG_IFACE}, and verified it is active."
    fi
else
    sphinx_warn "systemctl is not available on this system, so the service was NOT enabled or started. On a stock Debian VPS systemd is present; if this is a container, start the tunnel with: wg-quick up ${SPHINX_WG_IFACE}"
fi

# --- summary ------------------------------------------------------------------------

printf '\n=== Sphinx WireGuard server: install summary ===\n\n'
printf 'Server public key (share this freely - it is how clients pin\n'
printf 'this server; the private key never leaves this machine):\n  %s\n\n' "${server_public_key}"
if [ "${#CHANGES[@]}" -gt 0 ]; then
    printf 'Changed:\n'
    for item in "${CHANGES[@]}"; do printf '  - %s\n' "${item}"; done
    printf '\n'
fi
if [ "${#NOTES[@]}" -gt 0 ]; then
    printf 'Already as it should be / notes:\n'
    for item in "${NOTES[@]}"; do printf '  - %s\n' "${item}"; done
    printf '\n'
fi
cat <<EOF
Firewall: NOT changed by this script - no silent actions, ever.
Only two inbound openings are your concern: SSH (already how you got
in) and UDP ${PORT} for WireGuard. If this machine runs a firewall,
open the WireGuard port yourself, for example:

  ufw:  ufw allow ${PORT}/udp
  nft:  nft add rule inet filter input udp dport ${PORT} accept
        (adjust the table/chain names to your own ruleset)

If the machine sits behind a provider firewall or security group,
allow UDP ${PORT} there too. Without that, clients cannot reach the
server, and no error on the client will say why.

What to do next:
  1. Add a client:
       sudo bash add-client.sh PHONE --public-key <key the phone shows you>
     or, accepting that the private key will exist on this server:
       sudo bash add-client.sh PHONE --generate
  2. Hand the printed config file to that device and import it in
     Sphinx (or any WireGuard app). See README.md, "Adding a client".

What running this makes you: the operator. All client traffic exits
this machine with this machine's address, and you can see where that
traffic goes. Only offer this server to people who trust you with
that - because that is what a VPN is. README.md says it in full.
EOF
if [ -z "${ENDPOINT}" ]; then
    printf '\nNote: no --endpoint was given, so add-client.sh will ask for\n'
    printf 'one (--endpoint host:%s) when you add each client, until you\n' "${PORT}"
    printf 're-run install with --endpoint or set SPHINX_ENDPOINT.\n'
fi
