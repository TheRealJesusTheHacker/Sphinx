#!/usr/bin/env bash
# shellcheck disable=SC2031
# (SC2031: the SPHINX_* variables are exported into the environment on
# purpose - the scripts under test are child processes and must see
# them; a few checks also source the library in a subshell and pass
# results back, which shellcheck cannot follow. No state is expected
# to survive those subshells.)
# tests/run.sh - smoke tests for the Sphinx WireGuard server package.
#
# Runs WITHOUT root and WITHOUT a real server: no /etc/wireguard, no
# systemd, no WireGuard interface, no network. The scripts under test
# are pointed at a temporary directory through their environment
# overrides, and a fake `wg` binary (created below, in the temp dir)
# stands in for wireguard-tools so key generation and live peer
# changes can be exercised and their calls checked.
#
# Every key in this file is an EXAMPLE key copied from
# docs/tunnel-corpus.json. They protect nothing and must never be
# replaced with real keys.
#
# Usage:  bash tests/run.sh
# Exit:   0 when everything passes, 1 otherwise. A summary is printed
#         either way; failures name the check that failed.

set -uo pipefail

SERVER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

PASS=0
FAIL=0
FAILED_CHECKS=()

check() { # check <name> <condition...>
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        PASS=$((PASS + 1)); printf 'ok   %s\n' "${name}"
    else
        FAIL=$((FAIL + 1)); FAILED_CHECKS+=("${name}")
        printf 'FAIL %s\n' "${name}"
    fi
}

check_not() { # check_not <name> <condition...> - passes when the command fails
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        FAIL=$((FAIL + 1)); FAILED_CHECKS+=("${name}")
        printf 'FAIL %s\n' "${name}"
    else
        PASS=$((PASS + 1)); printf 'ok   %s\n' "${name}"
    fi
}

contains() { grep -q -- "$2" "$1"; }
contains_fixed() { grep -qF -- "$2" "$1"; }
first_line_is() { [ "$(head -n 1 "$1")" = "$2" ]; }

# EXAMPLE keys (docs/tunnel-corpus.json - not real key material).
EX_CLIENT_PRIV='hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s='   # EXAMPLE
EX_SERVER_PUB='q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU='    # EXAMPLE
EX_PEER2_PUB='ukI3DodjYWN46wnWXHUkkshvzC03Go/6V1V7M7ofwj8='     # EXAMPLE
EX_GEN_PRIV='eWcxOPQk6KDVs8/k4CPoBFDtKreTdr2myBI9h2tW3NU='      # EXAMPLE
EX_DELTA_PUB='p4G/fpNfUSa8CcAQ8Sxkji+c2kewIE93J4M3DIQTrL0='     # EXAMPLE (the corpus's example preshared key, reused here as a distinct example key string)
# Synthetic EXAMPLE keys so every fixture client owns a distinct key:
EX_ALPHA_PUB="$(printf 'A%.0s' {1..43})="                        # EXAMPLE
EX_GAMMA_PUB="$(printf 'B%.0s' {1..43})="                        # EXAMPLE

delta_registered() {
    awk -F '\t' '$1 == "delta" && $2 == "10.8.0.3" && $5 == "device" { f = 1 } END { exit !f }' "${SPHINX_CLIENTS_FILE}"
}
epsilon_registered() {
    awk -F '\t' -v k="${EX_PEER2_PUB}" '$1 == "epsilon" && $2 == "10.8.0.5" && $3 == k && $5 == "server" { f = 1 } END { exit !f }' "${SPHINX_CLIENTS_FILE}"
}

# --- 1. syntax + shellcheck -----------------------------------------------------

for script in install.sh add-client.sh remove-client.sh lib/clients.sh tests/run.sh; do
    check "bash -n ${script}" bash -n "${SERVER_DIR}/${script}"
done

if command -v shellcheck >/dev/null 2>&1; then
    printf 'shellcheck: found (%s) - running it on every script\n' "$(shellcheck --version | sed -n 's/^version: //p')"
    for script in install.sh add-client.sh remove-client.sh lib/clients.sh tests/run.sh; do
        check "shellcheck ${script}" shellcheck -x "${SERVER_DIR}/${script}"
    done
else
    printf 'shellcheck: NOT available in this environment - skipped (install it and re-run to get this check)\n'
fi

# --- fake wg ---------------------------------------------------------------------
# Behaviour: genkey prints the fixed EXAMPLE "generated" key; pubkey
# maps it (and the fixture server key) to EXAMPLE public keys, copying
# TUNNEL-SPEC's pin idea in miniature; `show` succeeds only when the
# "interface up" marker exists; `set` appends its arguments to a log
# the tests can read, and fails when the "set fails" marker exists.

FAKEBIN="${WORK}/bin"
mkdir -p "${FAKEBIN}"
export FAKE_WG_LOG="${WORK}/wg-calls.log"
export FAKE_WG_STATE="${WORK}/wg-state"
mkdir -p "${FAKE_WG_STATE}"
: > "${FAKE_WG_LOG}"
cat > "${FAKEBIN}/wg" <<'EOF'
#!/usr/bin/env bash
# Fake wg for the Sphinx server tests. EXAMPLE keys only.
set -u
printf '%s\n' "$*" >> "${FAKE_WG_LOG:?}"
case "${1:-}" in
    genkey)
        # EXAMPLE key (docs/tunnel-corpus.json) - not real.
        printf '%s\n' 'eWcxOPQk6KDVs8/k4CPoBFDtKreTdr2myBI9h2tW3NU=' ;;
    pubkey)
        key="$(cat)"
        case "${key}" in
            # EXAMPLE mappings (docs/tunnel-corpus.json keys).
            'eWcxOPQk6KDVs8/k4CPoBFDtKreTdr2myBI9h2tW3NU=')
                printf '%s\n' 'ukI3DodjYWN46wnWXHUkkshvzC03Go/6V1V7M7ofwj8=' ;;
            'hI9byVWLK8639iOPJ8Z3ej9sp4rhqOdnHQ3pfp0N35s=')
                printf '%s\n' 'q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=' ;;
            *)
                printf '%s\n' 'q6GQz9IBykkuC3C+kX7l8w7SU9s6yP0Vq8UurgHsiFU=' ;;
        esac ;;
    show)
        [ -e "${FAKE_WG_STATE:?}/up" ] ;;
    set)
        if [ -e "${FAKE_WG_STATE:?}/set-fails" ]; then
            printf 'fake wg: set failed (marker present)\n' >&2
            exit 1
        fi
        printf 'applied: %s\n' "$*" >> "${FAKE_WG_LOG:?}" ;;
    *) printf 'fake wg: unknown command\n' >&2; exit 1 ;;
esac
EOF
chmod +x "${FAKEBIN}/wg"
export PATH="${FAKEBIN}:${PATH}"

# Environment for the scripts under test: everything in the temp dir.
export SPHINX_TEST_MODE=1
export SPHINX_WG_DIR="${WORK}/wireguard"
export SPHINX_WG_CONF="${SPHINX_WG_DIR}/wg0.conf"
export SPHINX_CLIENTS_FILE="${SPHINX_WG_DIR}/clients"
export SPHINX_CLIENTS_DIR="${SPHINX_WG_DIR}/clients.d"
export SPHINX_SETTINGS_FILE="${SPHINX_WG_DIR}/sphinx-settings.conf"
export SPHINX_SERVER_PRIVATE_KEY_FILE="${SPHINX_WG_DIR}/server-private.key"
export SPHINX_SERVER_PUBLIC_KEY_FILE="${SPHINX_WG_DIR}/server-public.key"
mkdir -p "${SPHINX_WG_DIR}" "${SPHINX_CLIENTS_DIR}"

# --- 2. template rendering -----------------------------------------------------------

RENDERED="${WORK}/wg0.rendered.conf"
sed -e "s|__SERVER_PRIVATE_KEY__|${EX_CLIENT_PRIV}|g" \
    -e "s|__SERVER_ADDRESS__|10.8.0.1/24|g" \
    -e "s|__LISTEN_PORT__|51820|g" \
    -e "s|__TUNNEL_SUBNET__|10.8.0.0/24|g" \
    -e "s|__EGRESS_IF__|eth0|g" \
    "${SERVER_DIR}/templates/wg0.conf.tmpl" > "${RENDERED}"

check_not "template render leaves no placeholder" grep -q "__[A-Z_]*__" "${RENDERED}"
check "rendered config has [Interface]" contains_fixed "${RENDERED}" "[Interface]"
check "rendered config carries the example server key" contains_fixed "${RENDERED}" "PrivateKey = ${EX_CLIENT_PRIV}"
check "rendered config listens on 51820" contains_fixed "${RENDERED}" "ListenPort = 51820"
check "rendered config masquerades the tunnel subnet via eth0" contains_fixed "${RENDERED}" "-t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE"
check "rendered PostDown removes the masquerade" contains_fixed "${RENDERED}" "-t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE"
# Owner correction (2026-10-23): the endpoint carries ALL client
# traffic by design; it must not filter or block any of it. The only
# rules allowed anywhere are ACCEPT forwarding + NAT masquerade.
check_not "template has no DROP rule" contains "${RENDERED}" "DROP"
check_not "template has no REJECT rule" contains "${RENDERED}" "REJECT"
# The firewall commands in install.sh are printed recommendation
# text inside its summary (lines like "  ufw:  ufw allow ..."), never
# executed. This pattern only matches a line that would RUN one.
check_not "install.sh never executes a firewall change (printed recommendations only)" grep -Eq "^[[:space:]]*(ufw|nft)[[:space:]]+(allow|add|insert|delete|enable)" "${SERVER_DIR}/install.sh"

# --- 3. address assignment against a fixture registry --------------------------------

# Fixture: .2 and .4 are taken, so the next free address is .3.
printf 'alpha\t10.8.0.2\t%s\t2026-10-23\tdevice\n' "${EX_ALPHA_PUB}" > "${SPHINX_CLIENTS_FILE}"
printf 'gamma\t10.8.0.4\t%s\t2026-10-23\tserver\n' "${EX_GAMMA_PUB}" >> "${SPHINX_CLIENTS_FILE}"
cp "${SPHINX_CLIENTS_FILE}" "${WORK}/fixture-registry"

next_addr="$(
    # shellcheck disable=SC1091
    . "${SERVER_DIR}/lib/clients.sh"
    sphinx_next_free_address "10.8.0.0/24"
)"
check "next free address skips used .2/.4 and the server .1" test "${next_addr}" = "10.8.0.3"

# A /30 has exactly one client address (.2); once it is taken the
# subnet is honestly full.
printf 'only\t10.99.0.2\t%s\t2026-10-23\tdevice\n' "${EX_ALPHA_PUB}" > "${SPHINX_CLIENTS_FILE}"
check_not "full /30 subnet yields no address" bash -c ". '${SERVER_DIR}/lib/clients.sh'; sphinx_next_free_address 10.99.0.0/30"

# Validation helpers refuse the values that must never reach a config.
check_not "a short key is refused" bash -c ". '${SERVER_DIR}/lib/clients.sh'; sphinx_valid_key too-short"
check "an example key validates" bash -c ". '${SERVER_DIR}/lib/clients.sh'; sphinx_valid_key '${EX_SERVER_PUB}'"
check_not "a name with a slash is refused" bash -c ". '${SERVER_DIR}/lib/clients.sh'; sphinx_valid_name 'a/b'"
check_not "a name with a newline is refused" bash -c ". '${SERVER_DIR}/lib/clients.sh'; sphinx_valid_name \"a\$(printf '\\nb')\""
check_not "an endpoint without a port is refused" bash -c ". '${SERVER_DIR}/lib/clients.sh'; sphinx_valid_endpoint vpn.example.com"
check "a bracketed IPv6 endpoint validates" bash -c ". '${SERVER_DIR}/lib/clients.sh'; sphinx_valid_endpoint '[2001:db8::7]:51820'"
check_not "a host-bits-set subnet is refused" bash -c ". '${SERVER_DIR}/lib/clients.sh'; sphinx_valid_subnet 10.8.0.5/24"

cp "${WORK}/fixture-registry" "${SPHINX_CLIENTS_FILE}"

# --- 4. add-client: public-key route (the Sphinx way) ----------------------------------

# Fixture server files: settings + server public key + a wg0.conf
# rendered from the real template.
cp "${RENDERED}" "${SPHINX_WG_CONF}"
printf 'SUBNET=10.8.0.0/24\nLISTEN_PORT=51820\nEGRESS_IF=eth0\nSERVER_PUBLIC_KEY=%s\nENDPOINT=vpn.example.com:51820\n' "${EX_SERVER_PUB}" > "${SPHINX_SETTINGS_FILE}"
touch "${FAKE_WG_STATE}/up"
: > "${FAKE_WG_LOG}"

check "add-client --public-key succeeds" bash "${SERVER_DIR}/add-client.sh" delta --public-key "${EX_DELTA_PUB}"

DELTA_CONF="${SPHINX_CLIENTS_DIR}/delta.conf"
check "completion sheet exists" test -f "${DELTA_CONF}"
check "first line is the Sphinx profile comment" first_line_is "${DELTA_CONF}" "# Sphinx profile: delta"
check "completion sheet carries the placeholder key" contains_fixed "${DELTA_CONF}" "PrivateKey = YOUR-PRIVATE-KEY-HERE"
check "completion sheet got the next free address .3" contains_fixed "${DELTA_CONF}" "Address = 10.8.0.3/32"
check "completion sheet pins the server public key" contains_fixed "${DELTA_CONF}" "PublicKey = ${EX_SERVER_PUB}"
check "completion sheet names the endpoint" contains_fixed "${DELTA_CONF}" "Endpoint = vpn.example.com:51820"
check "completion sheet is full-tunnel by default" contains_fixed "${DELTA_CONF}" "AllowedIPs = 0.0.0.0/0"
check "client config file is 0600" bash -c "[ \"\$(stat -c %a '${DELTA_CONF}')\" = 600 ]"
check "registry records delta as a device key at .3" delta_registered
check "wg0.conf gained delta's peer" contains_fixed "${SPHINX_WG_CONF}" "# Sphinx client: delta"
check "wg0.conf delta peer has the device public key" contains_fixed "${SPHINX_WG_CONF}" "PublicKey = ${EX_DELTA_PUB}"
check "live apply used one targeted wg set" contains_fixed "${FAKE_WG_LOG}" "set wg0 peer ${EX_DELTA_PUB} allowed-ips 10.8.0.3/32"

check_not "a duplicate name is refused" bash "${SERVER_DIR}/add-client.sh" delta --generate
check_not "a duplicate key under a new name is refused" bash "${SERVER_DIR}/add-client.sh" delta2 --public-key "${EX_DELTA_PUB}"
check_not "neither --public-key nor --generate is refused" bash "${SERVER_DIR}/add-client.sh" nobody
check_not "an invalid public key is refused" bash "${SERVER_DIR}/add-client.sh" badkey --public-key not-a-key
check_not "a name with a space is refused" bash "${SERVER_DIR}/add-client.sh" "bad name" --generate

# --- 5. add-client: generated route --------------------------------------------------------

GEN_CONF="${SPHINX_CLIENTS_DIR}/epsilon.conf"
check "add-client --generate succeeds" bash "${SERVER_DIR}/add-client.sh" epsilon --generate
check "generated config exists" test -f "${GEN_CONF}"
check "generated config's first line is the profile comment" first_line_is "${GEN_CONF}" "# Sphinx profile: epsilon"
check "generated config carries the (EXAMPLE) generated private key" contains_fixed "${GEN_CONF}" "PrivateKey = ${EX_GEN_PRIV}"
check "generated config's address continues the sequence (.5 after fixture .4 and delta .3)" contains_fixed "${GEN_CONF}" "Address = 10.8.0.5/32"
check "registry records epsilon as a server-generated key at .5" epsilon_registered
check "split tunnel is accepted as an option value" bash -c ". '${SERVER_DIR}/lib/clients.sh'; sphinx_valid_cidr_list '10.0.0.0/8, 192.168.0.0/16'"

# --- 6. remove-client ------------------------------------------------------------------------

: > "${FAKE_WG_LOG}"
check "remove-client succeeds" bash "${SERVER_DIR}/remove-client.sh" delta
check "delta is out of the registry" bash -c "! grep -q '^delta' '${SPHINX_CLIENTS_FILE}'"
check "delta's peer block is out of wg0.conf" bash -c "! grep -q 'Sphinx client: delta' '${SPHINX_WG_CONF}'"
check "delta's public key is out of wg0.conf" bash -c "! grep -qF '${EX_DELTA_PUB}' '${SPHINX_WG_CONF}'"
check "other peers survive the removal" contains_fixed "${SPHINX_WG_CONF}" "# Sphinx client: epsilon"
check "the exported delta config was deleted" bash -c "[ ! -e '${DELTA_CONF}' ]"
check "live removal used wg set ... remove" contains_fixed "${FAKE_WG_LOG}" "set wg0 peer ${EX_DELTA_PUB} remove"
check_not "removing a client that does not exist is refused" bash "${SERVER_DIR}/remove-client.sh" delta
# Freed address is reused: .3 is free again (registry has .2, .4, .5).
reuse_addr="$(
    # shellcheck disable=SC1091
    . "${SERVER_DIR}/lib/clients.sh"
    sphinx_next_free_address "10.8.0.0/24"
)"
check "a removed client's address is free again" test "${reuse_addr}" = "10.8.0.3"

# When the live removal fails, remove-client must stop and change
# nothing else: the client stays enrolled everywhere.
touch "${FAKE_WG_STATE}/set-fails"
check_not "remove-client refuses when the live removal fails" bash "${SERVER_DIR}/remove-client.sh" epsilon
check "epsilon is still enrolled after the failed live removal" bash -c "grep -q '^epsilon' '${SPHINX_CLIENTS_FILE}'"
check "epsilon's peer block survives the failed live removal" contains_fixed "${SPHINX_WG_CONF}" "# Sphinx client: epsilon"
rm -f "${FAKE_WG_STATE}/set-fails"

# --- 7. interface down, and two adds at once -----------------------------------------------------

# With the interface down, enrollment still succeeds on disk, the
# script says nothing was applied live, and removal works the same.
rm -f "${FAKE_WG_STATE}/up"
check "add-client succeeds with the interface down" bash "${SERVER_DIR}/add-client.sh" zeta --public-key "${EX_CLIENT_PRIV}" --endpoint other.example.com:51821
check "zeta's sheet used the --endpoint override" contains_fixed "${SPHINX_CLIENTS_DIR}/zeta.conf" "Endpoint = other.example.com:51821"
check "remove-client succeeds with the interface down" bash "${SERVER_DIR}/remove-client.sh" zeta
check "zeta is out of the registry" bash -c "! grep -q '^zeta' '${SPHINX_CLIENTS_FILE}'"

# Two adds in parallel must not collide: the lock serializes the
# registry/config changes, and the two clients get different
# addresses (at this point .3 and .6 are the two lowest free ones).
EX_THETA_A="$(printf 'D%.0s' {1..43})="   # EXAMPLE
EX_THETA_B="$(printf 'E%.0s' {1..43})="   # EXAMPLE
bash "${SERVER_DIR}/add-client.sh" theta-a --public-key "${EX_THETA_A}" >/dev/null 2>&1 &
pid_a=$!
bash "${SERVER_DIR}/add-client.sh" theta-b --public-key "${EX_THETA_B}" >/dev/null 2>&1 &
pid_b=$!
rc_a=0; rc_b=0
wait "${pid_a}" || rc_a=$?
wait "${pid_b}" || rc_b=$?
check "both parallel adds succeeded" test "${rc_a}${rc_b}" = "00"
addr_a="$(awk -F '\t' '$1 == "theta-a" { print $2 }' "${SPHINX_CLIENTS_FILE}")"
addr_b="$(awk -F '\t' '$1 == "theta-b" { print $2 }' "${SPHINX_CLIENTS_FILE}")"
check "parallel adds got different addresses" bash -c "[ -n '${addr_a}' ] && [ -n '${addr_b}' ] && [ '${addr_a}' != '${addr_b}' ]"
check "both parallel peer blocks are in wg0.conf" bash -c "grep -q 'Sphinx client: theta-a' '${SPHINX_WG_CONF}' && grep -q 'Sphinx client: theta-b' '${SPHINX_WG_CONF}'"

# --- summary -----------------------------------------------------------------------------------

printf '\n%d passed, %d failed\n' "${PASS}" "${FAIL}"
if [ "${FAIL}" -gt 0 ]; then
    printf 'failed checks:\n'
    for name in "${FAILED_CHECKS[@]}"; do printf '  - %s\n' "${name}"; done
    exit 1
fi
printf 'All smoke tests passed. (No root, no server, no network were used.\n'
printf 'A real install on a real Debian VPS is NOT proven by this suite.)\n'
