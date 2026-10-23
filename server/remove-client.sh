#!/usr/bin/env bash
# remove-client.sh - remove one client from this Sphinx WireGuard
# server, completely:
#
#   1. the peer is removed from the RUNNING interface first, so the
#      client's access ends immediately, not at the next restart,
#   2. the peer block is removed from wg0.conf, so it does not come
#      back when the interface restarts,
#   3. the client's line is removed from the registry, freeing its
#      tunnel address for a future client,
#   4. the exported config file in the clients directory is deleted:
#      in the --generate route it contains a private key, and a
#      removed client's key should not sit around on the server.
#
# Order is deliberate. If the live removal fails, the script stops
# and leaves the config and registry exactly as they were - the
# client can still connect, the script says so, and the operator can
# fix the problem and run it again. Removing the paperwork first and
# the access second could have left a client connected that every
# file claimed was gone.
#
# Deleting the exported config here does not reach copies already
# handed out - those copies stop working because the peer is gone,
# which is the part that matters. The removal is final for this
# server: to let the same device back in, enroll it again with
# add-client.sh (it may get a different tunnel address).
#
# Usage:
#   sudo bash remove-client.sh NAME

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/clients.sh
. "${SCRIPT_DIR}/lib/clients.sh"

usage() {
    sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^#\{0,1\} \{0,1\}//'
}

NAME=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -*) sphinx_die "unknown option: $1 (see --help). Nothing was changed." ;;
        *)
            [ -z "${NAME}" ] || sphinx_die "only one client name may be given (got '${NAME}' and '$1'). Nothing was changed."
            NAME="$1"; shift ;;
    esac
done

[ -n "${NAME}" ] || { usage >&2; sphinx_die "a client name is required. Nothing was changed."; }
sphinx_require_root_or_test
sphinx_valid_name "${NAME}" || sphinx_die "client name '${NAME}' is not a name this package would have enrolled (letters, digits, dot, underscore, dash). Nothing was changed."
[ -f "${SPHINX_CLIENTS_FILE}" ] || sphinx_die "no clients registry at ${SPHINX_CLIENTS_FILE}. Nothing to remove - and nothing was changed."

cleanup_lock() { sphinx_release_lock; }
trap cleanup_lock EXIT

sphinx_acquire_lock

line="$(sphinx_registry_lookup "${NAME}")" || sphinx_die "no client named '${NAME}' is enrolled. Run add-client.sh to add one, or check the name - the registry is ${SPHINX_CLIENTS_FILE}. Nothing was changed."
address="$(printf '%s' "${line}" | cut -f2)"
pubkey="$(printf '%s' "${line}" | cut -f3)"
sphinx_valid_key "${pubkey}" || sphinx_die "the registry line for '${NAME}' does not carry a valid public key ('${pubkey}'), so the live peer cannot be identified safely. Fix ${SPHINX_CLIENTS_FILE} by hand; nothing was changed."

# 1. live removal first - access ends now.
live_state="not-up"
if command -v wg >/dev/null 2>&1 && wg show "${SPHINX_WG_IFACE}" >/dev/null 2>&1; then
    if wg set "${SPHINX_WG_IFACE}" peer "${pubkey}" remove; then
        live_state="removed"
    else
        sphinx_die "removing the peer from the running ${SPHINX_WG_IFACE} interface FAILED, so nothing else was changed: the client can still connect, and the config and registry still say so. Check the interface (wg show ${SPHINX_WG_IFACE}) and run this again."
    fi
fi

# 2 + 3. config and registry.
[ -f "${SPHINX_WG_CONF}" ] && sphinx_remove_peer_from_config "${SPHINX_WG_CONF}" "${pubkey}" "${NAME}"
sphinx_registry_remove "${NAME}" || sphinx_die "the peer is gone from the live interface and from ${SPHINX_WG_CONF}, but removing the registry line FAILED. The client cannot connect; the registry still lists it with address ${address}. Fix ${SPHINX_CLIENTS_FILE} by hand - delete the line for '${NAME}'."

# 4. the exported config copy on this server.
OUT_FILE="${SPHINX_CLIENTS_DIR}/${NAME}.conf"
out_removed="there was no exported config file on this server to delete"
if [ -e "${OUT_FILE}" ]; then
    rm -f "${OUT_FILE}"
    out_removed="the exported config file on this server was deleted (${OUT_FILE})"
fi

sphinx_release_lock
trap - EXIT

printf 'Client removed: %s\n' "${NAME}"
printf '  tunnel address freed: %s\n' "${address}"
if [ "${live_state}" = "removed" ]; then
    printf '  live status: the peer was removed from the running %s interface - access ended immediately.\n' "${SPHINX_WG_IFACE}"
else
    printf '  live status: the %s interface is not up, so there was no live peer to remove. The peer is out of the config and will not return when the interface starts.\n' "${SPHINX_WG_IFACE}"
fi
printf '  config: the peer block was removed from %s.\n' "${SPHINX_WG_CONF}"
printf '  registry: the line was removed from %s.\n' "${SPHINX_CLIENTS_FILE}"
printf '  exported copy: %s.\n' "${out_removed}"
printf 'Copies of the config already handed to the client still exist\n'
printf 'on their side, but they no longer work: the peer is gone.\n'
