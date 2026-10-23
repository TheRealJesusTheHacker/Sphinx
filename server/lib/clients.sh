# shellcheck shell=bash
# clients.sh - shared logic for the Sphinx WireGuard server package.
#
# This file is SOURCED by add-client.sh, remove-client.sh and the test
# suite. It is not a program; running it directly does nothing useful.
#
# What lives here:
#   * the paths every script agrees on (all overridable by environment,
#     which is how the tests run without root and without a real server)
#   * strict validation for every value that will land in a config file
#     (a name, key, endpoint or CIDR that is not validated here could
#     inject extra config lines - everything is checked, nothing is
#     trusted because "the operator typed it")
#   * the clients registry: a root-only tab-separated file, one line
#     per client:  name <TAB> address <TAB> public-key <TAB> date <TAB> source
#     where source is "device" (key made on the client's device, the
#     Sphinx way) or "server" (key made on the server by add-client.sh)
#   * tunnel-address assignment for an IPv4 subnet
#
# Locking: callers take the registry lock (sphinx_acquire_lock) around
# every read-modify-write of the registry AND of wg0.conf, so two
# add-client.sh runs at the same time cannot hand out the same address
# or interleave a half-written peer block.

# --- paths -----------------------------------------------------------------

# The WireGuard directory. /etc/wireguard on a real server; the tests
# point this at a temporary directory.
SPHINX_WG_DIR="${SPHINX_WG_DIR:-/etc/wireguard}"
SPHINX_WG_IFACE="${SPHINX_WG_IFACE:-wg0}"
SPHINX_WG_CONF="${SPHINX_WG_CONF:-${SPHINX_WG_DIR}/${SPHINX_WG_IFACE}.conf}"
SPHINX_CLIENTS_FILE="${SPHINX_CLIENTS_FILE:-${SPHINX_WG_DIR}/clients}"
SPHINX_CLIENTS_DIR="${SPHINX_CLIENTS_DIR:-${SPHINX_WG_DIR}/clients.d}"
SPHINX_SETTINGS_FILE="${SPHINX_SETTINGS_FILE:-${SPHINX_WG_DIR}/sphinx-settings.conf}"
SPHINX_SERVER_PRIVATE_KEY_FILE="${SPHINX_SERVER_PRIVATE_KEY_FILE:-${SPHINX_WG_DIR}/server-private.key}"
SPHINX_SERVER_PUBLIC_KEY_FILE="${SPHINX_SERVER_PUBLIC_KEY_FILE:-${SPHINX_WG_DIR}/server-public.key}"

# Test mode: set by tests/run.sh only. It relaxes the root check and the
# live-interface actions (the tests supply a fake `wg` on PATH). A real
# operator should never set this.
SPHINX_TEST_MODE="${SPHINX_TEST_MODE:-0}"

# --- small helpers -----------------------------------------------------------

sphinx_die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

sphinx_warn() {
    printf 'WARNING: %s\n' "$*" >&2
}

sphinx_require_root_or_test() {
    if [ "${SPHINX_TEST_MODE}" = "1" ]; then
        return 0
    fi
    if [ "$(id -u)" -ne 0 ]; then
        sphinx_die "this script must be run as root (try: sudo $0 ...). It edits ${SPHINX_WG_DIR} and talks to the running WireGuard interface, and nothing was changed."
    fi
}

# --- validation --------------------------------------------------------------
# Every value written into a WireGuard config passes through one of these.
# WireGuard keys are 32 bytes in canonical base64: 43 characters plus "=".

sphinx_valid_key() {
    local key="$1"
    [[ "${key}" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

sphinx_valid_name() {
    # A client name becomes a file name and a config comment. Letters,
    # digits, dot, underscore and dash only; no spaces, no slashes, no
    # leading dash (so it can never be mistaken for a flag or a path).
    local name="$1"
    [[ "${name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

sphinx_valid_port() {
    local port="$1"
    [[ "${port}" =~ ^[0-9]+$ ]] && [ "${port}" -ge 1 ] && [ "${port}" -le 65535 ]
}

# IPv4 address (no prefix) -> integer, printed. Returns 1 if invalid.
sphinx_ipv4_to_int() {
    local ip="$1" a b c d
    [[ "${ip}" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
    c="${BASH_REMATCH[3]}"; d="${BASH_REMATCH[4]}"
    [ "${a}" -le 255 ] && [ "${b}" -le 255 ] && [ "${c}" -le 255 ] && [ "${d}" -le 255 ] || return 1
    # 10# forces decimal: a plain 010 would otherwise be read as octal.
    printf '%u\n' $(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))
}

sphinx_int_to_ipv4() {
    local n="$1"
    printf '%u.%u.%u.%u\n' $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) $(( (n >> 8) & 255 )) $(( n & 255 ))
}

sphinx_valid_ipv4() {
    sphinx_ipv4_to_int "$1" >/dev/null 2>&1
}

# Split "A.B.C.D/PREFIX" into globals SPHINX_SUBNET_BASE_INT and
# SPHINX_SUBNET_PREFIX. Returns 1 if it is not a usable tunnel subnet:
# the address must be the network address itself and the prefix must
# leave room for a server, at least one client, and a broadcast
# address, so /8 through /30.
sphinx_parse_subnet() {
    local cidr="$1" ip prefix base mask
    [[ "${cidr}" =~ ^([0-9.]+)/([0-9]{1,2})$ ]] || return 1
    ip="${BASH_REMATCH[1]}"; prefix="${BASH_REMATCH[2]}"
    [ "${prefix}" -ge 8 ] && [ "${prefix}" -le 30 ] || return 1
    base="$(sphinx_ipv4_to_int "${ip}")" || return 1
    mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    [ $(( base & ~mask & 0xFFFFFFFF )) -eq 0 ] || return 1
    SPHINX_SUBNET_BASE_INT="${base}"
    SPHINX_SUBNET_PREFIX="${prefix}"
    return 0
}

sphinx_valid_subnet() {
    ( sphinx_parse_subnet "$1" )
}

# The server's own tunnel address: the first usable address in the
# subnet (10.8.0.1 for the default 10.8.0.0/24).
sphinx_server_address() {
    local cidr="$1"
    sphinx_parse_subnet "${cidr}" || return 1
    sphinx_int_to_ipv4 $(( SPHINX_SUBNET_BASE_INT + 1 ))
}

# An endpoint is HOST:PORT. The host may be a DNS name, an IPv4
# address, or a bracketed IPv6 address ([2001:db8::1]:51820). Nothing
# with whitespace or shell/config metacharacters is accepted.
sphinx_valid_endpoint() {
    local endpoint="$1" host port
    if [[ "${endpoint}" =~ ^\[([0-9A-Fa-f:]+)\]:([0-9]+)$ ]]; then
        port="${BASH_REMATCH[2]}"
    elif [[ "${endpoint}" =~ ^([A-Za-z0-9._-]+):([0-9]+)$ ]]; then
        host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
        [ -n "${host}" ] || return 1
    else
        return 1
    fi
    sphinx_valid_port "${port}"
}

# A comma-separated list of CIDRs, each IPv4 (A.B.C.D/P) or a bare
# IPv6 CIDR made only of hex, colons and a prefix (e.g. ::/0,
# fd08::/64). Used for AllowedIPs.
sphinx_valid_cidr_list() {
    local list="$1" item
    local items=()
    IFS=',' read -r -a items <<< "${list}"
    [ "${#items[@]}" -ge 1 ] || return 1
    for item in "${items[@]}"; do
        item="${item//[[:space:]]/}"
        if [[ "${item}" =~ ^([0-9.]+)/([0-9]{1,2})$ ]]; then
            # Save the groups first: the function called next runs its
            # own regex and overwrites BASH_REMATCH.
            local item_ip="${BASH_REMATCH[1]}" item_prefix="${BASH_REMATCH[2]}"
            sphinx_ipv4_to_int "${item_ip}" >/dev/null || return 1
            [ "${item_prefix}" -le 32 ] || return 1
        elif [[ "${item}" =~ ^[0-9A-Fa-f:]+/[0-9]{1,3}$ ]]; then
            [[ "${item}" == *:* ]] || return 1
        else
            return 1
        fi
    done
    return 0
}

# A comma-separated list of DNS server addresses (plain IPs, no prefix).
sphinx_valid_dns_list() {
    local list="$1" item
    local items=()
    IFS=',' read -r -a items <<< "${list}"
    [ "${#items[@]}" -ge 1 ] || return 1
    for item in "${items[@]}"; do
        item="${item//[[:space:]]/}"
        if sphinx_valid_ipv4 "${item}"; then
            continue
        elif [[ "${item}" =~ ^[0-9A-Fa-f:]+$ ]] && [[ "${item}" == *:* ]]; then
            continue
        else
            return 1
        fi
    done
    return 0
}

# --- settings file -----------------------------------------------------------
# install.sh writes sphinx-settings.conf (KEY=VALUE lines, no secrets:
# the server's PUBLIC key is in there, never the private key).
# add-client.sh reads it so the operator does not retype the subnet,
# port and endpoint for every client.

sphinx_setting() {
    local wanted="$1" line key value
    [ -f "${SPHINX_SETTINGS_FILE}" ] || return 1
    while IFS= read -r line; do
        case "${line}" in
            ''|'#'*) continue ;;
        esac
        key="${line%%=*}"
        value="${line#*=}"
        if [ "${key}" = "${wanted}" ]; then
            printf '%s\n' "${value}"
            return 0
        fi
    done < "${SPHINX_SETTINGS_FILE}"
    return 1
}

# --- registry ----------------------------------------------------------------

sphinx_ensure_registry() {
    # The registry lives in the WireGuard directory (0700, root-only on
    # a real server). The file itself is created 0600.
    mkdir -p "${SPHINX_WG_DIR}" "${SPHINX_CLIENTS_DIR}"
    if [ "${SPHINX_TEST_MODE}" != "1" ]; then
        chmod 0700 "${SPHINX_WG_DIR}" "${SPHINX_CLIENTS_DIR}" || return 1
    fi
    if [ ! -e "${SPHINX_CLIENTS_FILE}" ]; then
        ( umask 077; : > "${SPHINX_CLIENTS_FILE}" ) || return 1
    fi
    if [ "${SPHINX_TEST_MODE}" != "1" ]; then
        chmod 0600 "${SPHINX_CLIENTS_FILE}" || return 1
    fi
    return 0
}

# Locking: one lock file next to the registry, held on fd 9 for the
# whole read-modify-write. flock ships with util-linux, which every
# stock Debian has; if it is missing we stop rather than race.
SPHINX_LOCK_FD_HELD=0
sphinx_acquire_lock() {
    command -v flock >/dev/null 2>&1 || sphinx_die "flock is not available (it is part of util-linux on stock Debian). Without it, two client changes at once could hand out the same address, so nothing was changed."
    exec 9>>"${SPHINX_CLIENTS_FILE}.lock"
    flock 9 || sphinx_die "could not take the clients lock (${SPHINX_CLIENTS_FILE}.lock). Nothing was changed."
    SPHINX_LOCK_FD_HELD=1
}

sphinx_release_lock() {
    if [ "${SPHINX_LOCK_FD_HELD}" = "1" ]; then
        flock -u 9 2>/dev/null || true
        exec 9>&-
        SPHINX_LOCK_FD_HELD=0
    fi
}

# Print the registry line for a name. Returns 1 if there is none.
sphinx_registry_lookup() {
    local wanted="$1" name rest
    [ -f "${SPHINX_CLIENTS_FILE}" ] || return 1
    while IFS="$(printf '\t')" read -r name rest; do
        case "${name}" in
            ''|'#'*) continue ;;
        esac
        if [ "${name}" = "${wanted}" ]; then
            printf '%s\t%s\n' "${name}" "${rest}"
            return 0
        fi
    done < "${SPHINX_CLIENTS_FILE}"
    return 1
}

# Print the registry line owning a public key. Returns 1 if none.
sphinx_registry_lookup_by_key() {
    local wanted="$1" name address pubkey rest
    [ -f "${SPHINX_CLIENTS_FILE}" ] || return 1
    while IFS="$(printf '\t')" read -r name address pubkey rest; do
        case "${name}" in
            ''|'#'*) continue ;;
        esac
        if [ "${pubkey}" = "${wanted}" ]; then
            printf '%s\t%s\t%s\t%s\n' "${name}" "${address}" "${pubkey}" "${rest}"
            return 0
        fi
    done < "${SPHINX_CLIENTS_FILE}"
    return 1
}

# Append one line. Caller must hold the lock.
sphinx_registry_add() {
    local name="$1" address="$2" pubkey="$3" source="$4" today
    today="$(date +%Y-%m-%d)"
    printf '%s\t%s\t%s\t%s\t%s\n' "${name}" "${address}" "${pubkey}" "${today}" "${source}" >> "${SPHINX_CLIENTS_FILE}"
}

# Remove one client's line, atomically (temp file in the same
# directory, then rename over the original). Caller must hold the lock.
sphinx_registry_remove() {
    local wanted="$1" tmp name line found=1 tab
    tab="$(printf '\t')"
    tmp="$(mktemp "${SPHINX_CLIENTS_FILE}.tmp.XXXXXX")" || return 1
    chmod 0600 "${tmp}" 2>/dev/null || true
    while IFS= read -r line || [ -n "${line}" ]; do
        name="${line%%"${tab}"*}"
        if [ "${name}" = "${wanted}" ]; then
            found=0
            continue
        fi
        printf '%s\n' "${line}" >> "${tmp}"
    done < "${SPHINX_CLIENTS_FILE}"
    # `line` and the loop above need the variable declared for shellcheck.
    mv "${tmp}" "${SPHINX_CLIENTS_FILE}" || { rm -f "${tmp}"; return 1; }
    if [ "${SPHINX_TEST_MODE}" != "1" ]; then
        chmod 0600 "${SPHINX_CLIENTS_FILE}" || return 1
    fi
    return "${found}"
}

# --- address assignment --------------------------------------------------------
# Clients get addresses from the tunnel subnet, in order, skipping:
# the network address, the server's address (base+1), the broadcast
# address, and every address already in the registry. The first client
# on the default subnet is 10.8.0.2. Prints the address; returns 1
# with nothing printed when the subnet is full.

sphinx_next_free_address() {
    local cidr="$1" size broadcast candidate ip used name address rest
    sphinx_parse_subnet "${cidr}" || return 1
    size=$(( 1 << (32 - SPHINX_SUBNET_PREFIX) ))
    broadcast=$(( SPHINX_SUBNET_BASE_INT + size - 1 ))
    candidate=$(( SPHINX_SUBNET_BASE_INT + 2 ))
    while [ "${candidate}" -lt "${broadcast}" ]; do
        ip="$(sphinx_int_to_ipv4 "${candidate}")"
        used=0
        if [ -f "${SPHINX_CLIENTS_FILE}" ]; then
            while IFS="$(printf '\t')" read -r name address rest; do
                case "${name}" in
                    ''|'#'*) continue ;;
                esac
                if [ "${address}" = "${ip}" ]; then
                    used=1
                    break
                fi
            done < "${SPHINX_CLIENTS_FILE}"
        fi
        if [ "${used}" -eq 0 ]; then
            printf '%s\n' "${ip}"
            return 0
        fi
        candidate=$(( candidate + 1 ))
    done
    return 1
}

# --- wg0.conf peer blocks ------------------------------------------------------
# Peers this package adds are preceded by a marker comment:
#   # Sphinx client: <name>
# so remove-client.sh can find the exact block again. The fallback in
# the remove function matches on the public key, for a block whose
# marker was edited away by hand.

sphinx_append_peer_to_config() {
    local name="$1" pubkey="$2" address="$3"
    {
        printf '\n# Sphinx client: %s\n' "${name}"
        printf '[Peer]\n'
        printf 'PublicKey = %s\n' "${pubkey}"
        printf 'AllowedIPs = %s/32\n' "${address}"
    } >> "${SPHINX_WG_CONF}"
}

# Remove the peer block for a client from wg0.conf, atomically.
# Arguments: config-path public-key name
sphinx_remove_peer_from_config() {
    local conf="$1" pubkey="$2" name="$3" tmp
    [ -f "${conf}" ] || return 0
    tmp="$(mktemp "${conf}.tmp.XXXXXX")" || return 1
    chmod 0600 "${tmp}" 2>/dev/null || true
    # The file is processed in chunks. A chunk starts at a marker
    # comment or a section header and runs until the next chunk starts.
    # A chunk is dropped when it is the peer chunk for this client:
    # either its marker names the client, or it contains the client's
    # PublicKey line (the fallback for a hand-edited marker). Every
    # other chunk is printed back unchanged, in order.
    awk -v pubkey="${pubkey}" -v marker="# Sphinx client: ${name}" '
        function flush(   i) {
            if (have && !target) for (i = 1; i <= n; i++) print buf[i]
            have = 0; n = 0; target = 0; marker_only = 0
        }
        function start(line, is_marker) {
            buf[++n] = line; have = 1
            if (is_marker && line == marker) { target = 1; marker_only = 1 }
        }
        /^# Sphinx client: / { flush(); start($0, 1); next }
        /^\[Peer\][[:space:]]*$/ {
            if (marker_only) { buf[++n] = $0; marker_only = 0 }
            else { flush(); start($0, 0) }
            next
        }
        /^\[/ { flush(); start($0, 0); next }
        {
            if (!have) start($0, 0); else buf[++n] = $0
            marker_only = 0
            if ($0 == "PublicKey = " pubkey) target = 1
        }
        END { flush() }
    ' "${conf}" > "${tmp}" || { rm -f "${tmp}"; return 1; }
    mv "${tmp}" "${conf}" || { rm -f "${tmp}"; return 1; }
    if [ "${SPHINX_TEST_MODE}" != "1" ]; then
        chmod 0600 "${conf}" || return 1
    fi
    return 0
}
