#!/usr/bin/env bash
# add-client.sh - enroll one client on this Sphinx WireGuard server.
#
# Two ways to enroll, and the difference matters:
#
#   --public-key <KEY>   The Sphinx way. The keypair was made ON the
#                        client's own device; only the public key is
#                        given to the server. The private key has never
#                        existed here and never will. The file this
#                        writes is a profile completion sheet: a full,
#                        valid-shaped config whose PrivateKey line is
#                        the placeholder YOUR-PRIVATE-KEY-HERE, to be
#                        replaced with the device's own private key.
#                        That placeholder cannot connect - on purpose -
#                        so an unfinished sheet can never half-work
#                        with a wrong key.
#
#   --generate           The server makes the keypair. Convenient, and
#                        the printed warning is real: the client's
#                        private key now exists on this server, and
#                        the exported config is a SECRET - anyone who
#                        reads it can be that client until the client
#                        is removed. The file is written 0600.
#
# One of the two must be chosen. With neither, this script refuses:
# silently generating a private key on the server, when the operator
# never asked for that custody, would be the wrong default.
#
# What it does, in order, all under the clients lock so two runs at
# once cannot collide:
#   1. validates the name, the key, the endpoint and every other value
#      that will land in a config file,
#   2. assigns the next free tunnel address from the registry,
#   3. appends the peer to wg0.conf and the line to the registry,
#   4. applies the peer to the RUNNING interface (see below),
#   5. writes the client config file (0600) into the clients
#      directory and prints it (plus a QR code when qrencode is
#      available and the config is complete).
#
# Live apply: the peer is added with a single
#   wg set wg0 peer <key> allowed-ips <address>/32
# NOT with wg syncconf. syncconf would re-apply the entire config
# file to the interface; this script only means to add one peer, so
# it touches exactly that one peer. Existing peers are not re-read,
# not re-set and not dropped - their handshakes are undisturbed.
# If the interface is not up, the peer is still enrolled in the
# config and registry and will connect when wg0 next starts; the
# script says so plainly instead of pretending otherwise.
#
# Usage:
#   sudo bash add-client.sh NAME --public-key <KEY> [options]
#   sudo bash add-client.sh NAME --generate [options]
#
# Options:
#   --endpoint HOST:PORT   the server address clients use (default:
#                          SPHINX_ENDPOINT, else the endpoint stored
#                          by install.sh; there is no default guess -
#                          a VPS's public address is often not any
#                          address the machine itself can see)
#   --dns IP[,IP]          DNS servers for the client config. Default:
#                          none - this package runs no resolver, and
#                          a config naming one that does not exist
#                          would break the client's lookups. If you
#                          run a resolver on the server, pass it,
#                          usually --dns <server tunnel address>.
#   --allowed-ips LIST     traffic the client sends into the tunnel
#                          (default 0.0.0.0/0 - all traffic). Anything
#                          narrower is a split tunnel and is reported
#                          as one: some traffic, not all.
#   --keepalive SECONDS    PersistentKeepalive for NATed clients
#                          (default 25; 0 omits the line)

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/clients.sh
. "${SCRIPT_DIR}/lib/clients.sh"

usage() {
    sed -n '2,58p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} \{0,1\}//'
}

NAME=""
CLIENT_PUBKEY=""
GENERATE=0
ENDPOINT="${SPHINX_ENDPOINT:-}"
DNS_LIST=""
ALLOWED_IPS="0.0.0.0/0"
KEEPALIVE=25

while [ "$#" -gt 0 ]; do
    case "$1" in
        --public-key)  [ "$#" -ge 2 ] || sphinx_die "--public-key needs a value."; CLIENT_PUBKEY="$2"; shift 2 ;;
        --generate)    GENERATE=1; shift ;;
        --endpoint)    [ "$#" -ge 2 ] || sphinx_die "--endpoint needs a value."; ENDPOINT="$2"; shift 2 ;;
        --dns)         [ "$#" -ge 2 ] || sphinx_die "--dns needs a value."; DNS_LIST="$2"; shift 2 ;;
        --allowed-ips) [ "$#" -ge 2 ] || sphinx_die "--allowed-ips needs a value."; ALLOWED_IPS="$2"; shift 2 ;;
        --keepalive)   [ "$#" -ge 2 ] || sphinx_die "--keepalive needs a value."; KEEPALIVE="$2"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        -*)            sphinx_die "unknown option: $1 (see --help). Nothing was changed." ;;
        *)
            [ -z "${NAME}" ] || sphinx_die "only one client name may be given (got '${NAME}' and '$1'). Nothing was changed."
            NAME="$1"; shift ;;
    esac
done

[ -n "${NAME}" ] || { usage >&2; sphinx_die "a client name is required. Nothing was changed."; }
sphinx_require_root_or_test

# --- validate everything before changing anything -----------------------------

sphinx_valid_name "${NAME}" || sphinx_die "client name '${NAME}' is not usable. Names are 1-64 characters of letters, digits, dot, underscore or dash, starting with a letter or digit - the name becomes a file name and a config comment, so spaces and slashes are not allowed. Nothing was changed."

if [ "${GENERATE}" -eq 1 ] && [ -n "${CLIENT_PUBKEY}" ]; then
    sphinx_die "choose one: --public-key OR --generate, not both. Nothing was changed."
fi
if [ "${GENERATE}" -eq 0 ] && [ -z "${CLIENT_PUBKEY}" ]; then
    sphinx_die "choose how this client's key is made: --public-key <KEY> (the keypair was made on the client's device - preferred) or --generate (this server makes the keypair, and the private key then exists on this server). Nothing was changed."
fi
if [ -n "${CLIENT_PUBKEY}" ]; then
    sphinx_valid_key "${CLIENT_PUBKEY}" || sphinx_die "the public key given is not a valid WireGuard key (32 bytes as 44 base64 characters ending in =). Check it was copied whole. Nothing was changed."
fi
if ! [[ "${KEEPALIVE}" =~ ^[0-9]+$ ]] || [ "${KEEPALIVE}" -gt 65535 ]; then
    sphinx_die "--keepalive '${KEEPALIVE}' is not a number of seconds (0-65535). Nothing was changed."
fi
sphinx_valid_cidr_list "${ALLOWED_IPS}" || sphinx_die "--allowed-ips '${ALLOWED_IPS}' is not a comma-separated list of CIDRs (e.g. 0.0.0.0/0). Nothing was changed."
if [ -n "${DNS_LIST}" ]; then
    sphinx_valid_dns_list "${DNS_LIST}" || sphinx_die "--dns '${DNS_LIST}' is not a comma-separated list of IP addresses. Nothing was changed."
fi

[ -f "${SPHINX_WG_CONF}" ] || sphinx_die "no server config at ${SPHINX_WG_CONF}. Run install.sh first. Nothing was changed."
command -v wg >/dev/null 2>&1 || sphinx_die "the wg tool is not available. Run install.sh first (it installs wireguard-tools). Nothing was changed."

# Server facts: from the settings file install.sh wrote, falling back
# to the key file and the config itself for hand-built setups.
SUBNET="$(sphinx_setting SUBNET || true)"
if [ -z "${SUBNET}" ]; then
    conf_addr="$(sed -n 's/^Address = //p' "${SPHINX_WG_CONF}" | head -n 1 || true)"
    addr_ip="${conf_addr%/*}"; addr_prefix="${conf_addr#*/}"
    if sphinx_valid_ipv4 "${addr_ip}" && [[ "${addr_prefix}" =~ ^[0-9]+$ ]]; then
        base_int="$(sphinx_ipv4_to_int "${addr_ip}")"
        SUBNET="$(sphinx_int_to_ipv4 $(( base_int - 1 )))/${addr_prefix}"
    fi
fi
if [ -z "${SUBNET}" ] || ! sphinx_valid_subnet "${SUBNET}"; then
    sphinx_die "the tunnel subnet could not be determined (no SUBNET in ${SPHINX_SETTINGS_FILE} and no usable Address line in ${SPHINX_WG_CONF}). Fix the settings file or re-run install.sh. Nothing was changed."
fi

SERVER_PUBLIC_KEY="$(sphinx_setting SERVER_PUBLIC_KEY || true)"
if [ -z "${SERVER_PUBLIC_KEY}" ] && [ -s "${SPHINX_SERVER_PUBLIC_KEY_FILE}" ]; then
    SERVER_PUBLIC_KEY="$(cat "${SPHINX_SERVER_PUBLIC_KEY_FILE}")"
fi
if [ -z "${SERVER_PUBLIC_KEY}" ] && [ -s "${SPHINX_SERVER_PRIVATE_KEY_FILE}" ]; then
    SERVER_PUBLIC_KEY="$(wg pubkey < "${SPHINX_SERVER_PRIVATE_KEY_FILE}")"
fi
if [ -z "${SERVER_PUBLIC_KEY}" ] || ! sphinx_valid_key "${SERVER_PUBLIC_KEY}"; then
    sphinx_die "the server public key could not be determined or is not valid. Re-run install.sh. Nothing was changed."
fi

if [ -z "${ENDPOINT}" ]; then
    ENDPOINT="$(sphinx_setting ENDPOINT || true)"
fi
[ -n "${ENDPOINT}" ] || sphinx_die "no endpoint is known for this server, and the public address of a VPS usually cannot be guessed from inside it. Pass one: --endpoint vpn.example.com:51820 (or the server's public IP and the listen port). Nothing was changed."
sphinx_valid_endpoint "${ENDPOINT}" || sphinx_die "endpoint '${ENDPOINT}' is not HOST:PORT. Nothing was changed."

split_note=0
[ "${ALLOWED_IPS}" != "0.0.0.0/0" ] && [ "${ALLOWED_IPS}" != "0.0.0.0/0, ::/0" ] && [ "${ALLOWED_IPS}" != "::/0, 0.0.0.0/0" ] && split_note=1

# --- enroll, under the lock ------------------------------------------------------

sphinx_ensure_registry
OUT_FILE="${SPHINX_CLIENTS_DIR}/${NAME}.conf"
client_private_key=""
source="device"

cleanup_lock() { sphinx_release_lock; }
trap cleanup_lock EXIT

sphinx_acquire_lock

if sphinx_registry_lookup "${NAME}" >/dev/null; then
    sphinx_die "a client named '${NAME}' is already enrolled. Remove it first (remove-client.sh ${NAME}) or choose another name. Nothing was changed."
fi
if [ -e "${OUT_FILE}" ]; then
    sphinx_die "a client config file already exists at ${OUT_FILE} for a client not in the registry. It was left untouched; move it aside or choose another name. Nothing was changed."
fi

if [ "${GENERATE}" -eq 1 ]; then
    printf 'WARNING: generating this client'\''s keypair ON THE SERVER.\n' >&2
    printf 'The client'\''s private key will exist on this server, and the\n' >&2
    printf 'exported config below is a SECRET: anyone who reads it can\n' >&2
    printf 'connect as this client until the client is removed.\n' >&2
    printf 'Prefer --public-key with a key made on the device itself\n' >&2
    printf 'whenever the device can make one (Sphinx can).\n\n' >&2
    client_private_key="$(wg genkey)"
    sphinx_valid_key "${client_private_key}" || sphinx_die "wg genkey produced output that is not a valid WireGuard key. Nothing was enrolled."
    CLIENT_PUBKEY="$(printf '%s' "${client_private_key}" | wg pubkey)"
    source="server"
fi

if sphinx_registry_lookup_by_key "${CLIENT_PUBKEY}" >/dev/null; then
    other="$(sphinx_registry_lookup_by_key "${CLIENT_PUBKEY}" | cut -f1)"
    sphinx_die "that public key is already enrolled as client '${other}'. One key, one client. Nothing was changed."
fi

address="$(sphinx_next_free_address "${SUBNET}")" || sphinx_die "the tunnel subnet ${SUBNET} has no free address left. Remove a client or re-install with a larger subnet. Nothing was changed."

# Config + registry first, then the live interface. If the live step
# fails, the enrollment still stands on disk and takes effect at the
# next interface start - and the operator is told exactly that,
# loudly, with a non-zero exit.
sphinx_append_peer_to_config "${NAME}" "${CLIENT_PUBKEY}" "${address}"
sphinx_registry_add "${NAME}" "${address}" "${CLIENT_PUBKEY}" "${source}"

live_state="not-up"
if wg show "${SPHINX_WG_IFACE}" >/dev/null 2>&1; then
    if wg set "${SPHINX_WG_IFACE}" peer "${CLIENT_PUBKEY}" allowed-ips "${address}/32"; then
        live_state="applied"
    else
        live_state="failed"
    fi
fi

# The client config file, in the exact Sphinx import format: the
# profile-name comment is the first line, then standard WireGuard
# config text any edition (or the official apps) can import.
{
    printf '# Sphinx profile: %s\n' "${NAME}"
    printf '[Interface]\n'
    if [ "${GENERATE}" -eq 1 ]; then
        printf 'PrivateKey = %s\n' "${client_private_key}"
    else
        printf '# This sheet was made from a public key only: the server\n'
        printf '# never had your private key. Replace the placeholder below\n'
        printf '# with the private key from the device where the keypair\n'
        printf '# was made. As written, this config cannot connect - the\n'
        printf '# placeholder is not a key - and that is deliberate.\n'
        printf 'PrivateKey = YOUR-PRIVATE-KEY-HERE\n'
    fi
    printf 'Address = %s/32\n' "${address}"
    if [ -n "${DNS_LIST}" ]; then
        printf 'DNS = %s\n' "${DNS_LIST}"
    fi
    printf '\n'
    printf '[Peer]\n'
    printf 'PublicKey = %s\n' "${SERVER_PUBLIC_KEY}"
    printf 'Endpoint = %s\n' "${ENDPOINT}"
    printf 'AllowedIPs = %s\n' "${ALLOWED_IPS}"
    if [ "${KEEPALIVE}" -gt 0 ]; then
        printf 'PersistentKeepalive = %s\n' "${KEEPALIVE}"
    fi
} > "${OUT_FILE}.tmp"
chmod 0600 "${OUT_FILE}.tmp"
mv "${OUT_FILE}.tmp" "${OUT_FILE}"
if [ "${SPHINX_TEST_MODE}" != "1" ]; then
    chmod 0600 "${OUT_FILE}"
fi

sphinx_release_lock
trap - EXIT

# --- report -----------------------------------------------------------------------

if [ "${live_state}" = "failed" ]; then
    printf 'ERROR: the peer was written to %s and the registry, but applying it to the running %s interface FAILED.\n' "${SPHINX_WG_CONF}" "${SPHINX_WG_IFACE}" >&2
    printf 'The client will connect when the interface next starts (systemctl restart wg-quick@%s), or fix the interface and re-apply. The enrollment was NOT rolled back, so the state is known and named here rather than hidden.\n' "${SPHINX_WG_IFACE}" >&2
    exit 1
fi

printf 'Client enrolled: %s\n' "${NAME}"
printf '  tunnel address: %s (in %s)\n' "${address}" "${SUBNET}"
printf '  key source:     %s\n' "$([ "${source}" = "device" ] && printf 'made on the client device (the server only ever saw the public key)' || printf 'generated on THIS server - the exported config is a secret')"
if [ "${live_state}" = "applied" ]; then
    printf '  live status:    added to the running %s interface now; existing clients were not disturbed.\n' "${SPHINX_WG_IFACE}"
else
    printf '  live status:    the %s interface is not up, so nothing was applied live. The client is enrolled and will connect when the interface starts.\n' "${SPHINX_WG_IFACE}"
fi
if [ "${split_note}" -eq 1 ]; then
    printf '  NOTE: AllowedIPs is %s - this is a SPLIT tunnel. Only that traffic enters the tunnel; the rest of the client'\''s traffic goes direct, with its real address. It is not full-tunnel protection and the client will say so.\n' "${ALLOWED_IPS}"
fi
if [ -z "${DNS_LIST}" ]; then
    printf '  DNS:            no DNS line was written (this package runs no resolver). The client keeps its system resolvers, reached through the tunnel. Pass --dns to set specific resolvers.\n'
fi
printf '\nClient config file (0600): %s\n\n' "${OUT_FILE}"
cat "${OUT_FILE}"

if [ "${GENERATE}" -eq 1 ]; then
    if command -v qrencode >/dev/null 2>&1; then
        printf '\nThe same config as a QR code (for Android import - it\n'
        printf 'contains the private key, so treat this screen like one):\n\n'
        qrencode -t ANSIUTF8 < "${OUT_FILE}" || sphinx_warn "qrencode failed; the config file and text above are complete without it."
    fi
    printf '\nReminder: that config contains a private key. Send it by a\n'
    printf 'channel you trust, and remember a copy exists on this server\n'
    printf 'at %s until you delete it.\n' "${OUT_FILE}"
else
    printf '\nThis is a completion sheet, not a finished config: replace\n'
    printf 'YOUR-PRIVATE-KEY-HERE with the private key from the device\n'
    printf 'that made the keypair, then import it. No QR code was drawn -\n'
    printf 'a code carrying a placeholder key would be a trap, not a help.\n'
fi
