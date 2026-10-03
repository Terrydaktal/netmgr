#!/usr/bin/env bash
# Network guards are intentionally unused or reached only through extracted, mocked functions.
# shellcheck disable=SC2329,SC2032
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
# Sourcing only declares functions. Any attempted networking in these tests must fail.
# shellcheck source=netmgr
source "$repo/netmgr"
# These command guards may intentionally remain uncalled.
# shellcheck disable=SC2329
forbidden() {
    printf 'FAIL: live command forbidden: %s\n' "$*" | tee -a "$tmp/forbidden" >&2
    return 99
}
ip() { forbidden ip "$@"; }
nmcli() { forbidden nmcli "$@"; }
tshark() { forbidden tshark "$@"; }
nmap() { forbidden nmap "$@"; }
curl() { forbidden curl "$@"; }
sleep() { forbidden sleep "$@"; }

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}
equal() { [[ "$1" == "$2" ]] || fail "expected '$2', got '$1'"; }

equal "$(normalize_mac 'A0-B1-C2-D3-E4-F5')" 'a0:b1:c2:d3:e4:f5'
normalize_mac 'garbage' && fail 'invalid MAC accepted'
for mac in 00:00:00:00:00:00 ff:ff:ff:ff:ff:ff 01:00:5e:00:00:01 33:33:00:00:00:01; do
    is_device_mac "$mac" && fail "not a device: $mac"
done
printf '001122 Fixture Manufacturer\n000000 Xerox\n' > "$tmp/vendors"
export NETMGR_MAC_PREFIX_DB="$tmp/vendors"
export NETMGR_VENDOR_ONLINE=0
vendor=''
lookup_vendor '00:11:22:33:44:55' vendor
equal "$vendor" 'Fixture Manufacturer'
equal "${VENDOR_CACHE["00:11:22:33:44:55"]}" "$vendor"
rm "$tmp/vendors"
lookup_vendor '00:11:22:33:44:66' vendor
equal "$vendor" 'Fixture Manufacturer'
lookup_vendor '02:11:22:33:44:55' vendor
equal "$vendor" 'Private/randomized MAC'
lookup_vendor '00:00:00:00:00:00' vendor
equal "$vendor" 'Unknown'
lookup_vendor '10:10:10:10:10:10' vendor
equal "$vendor" 'Unknown'
printf 'PASS: MAC validation, local vendor caching, and no default external lookup\n'

MAC_IP_DB="$tmp/hints"
export NETMGR_MAC_IP_TTL=00060
printf '00:11:22:33:44:55\t192.0.2.20\t%s\n' "$((EPOCHSECONDS - 20))" > "$MAC_IP_DB"
{
    printf '00:11:22:33:44:55\t192.0.2.21\t%s\n' "$((EPOCHSECONDS - 10))"
    printf '00:11:22:33:44:66\t192.0.2.30\t%s\n' "$((EPOCHSECONDS - 90))"
    printf '00:11:22:33:44:77\t192.0.2.40\n'
    printf '00:11:22:33:44:88\tbad\033[2J\t%s\n' "$EPOCHSECONDS"
} >> "$MAC_IP_DB"
hint=''
lookup_ip_from_db '00:11:22:33:44:55' hint
equal "$hint" '192.0.2.21 (cached)'
equal "$MAC_IP_HINTS_LOADED" 1
for mac in 00:11:22:33:44:66 00:11:22:33:44:77 00:11:22:33:44:88; do
    lookup_ip_from_db "$mac" hint
    equal "$hint" ''
done
printf 'PASS: cache freshness, latest mapping, unaged hints and control characters\n'

number=0
ipv4_to_int '192.000.002.010' number
equal "$number" 3221225994
ipv4_to_int '256.1.2.3' number && fail 'invalid IPv4 accepted'
ipv4_in_cidr '192.0.3.254' '192.0.2.1/23' || fail 'incorrect /23 membership'
ipv4_in_cidr '192.0.4.1' '192.0.2.1/23' && fail 'out-of-subnet IPv4 accepted'
ipv4_in_cidr '192.0.2.1' '0.0.0.0/0' || fail '/0 membership'
equal "$(range_to_suffix '192.0.2.255 - 192.0.3.0')" /23
equal "$(range_to_suffix '192.0.2.0 - 192.0.2.255')" /24
equal "$(range_to_suffix '192.0.2.1 - 192.0.2.1')" /32
range_to_suffix '192.0.2.9 - 192.0.2.8' && fail 'reversed range accepted'
ip() { printf '1: test inet 10.20.0.1/16\n2: test inet 10.20.30.1/24\n'; }
equal "$(get_local_cidr 10.20.31.5)" /16
equal "$(get_local_cidr 10.20.30.5)" /24
equal "$(get_local_cidr 10.90.0.1)" ''
printf 'PASS: exact subnet masks, range boundaries and longest-prefix selection\n'

# Replace the privilege token before invoking any connection code; never execute sudo.
# shellcheck source=/dev/null disable=SC2016
source /dev/stdin < <(sed -n '/^connect_wifi_bssid() {/,/^}/p' "$repo/netmgr" | sed 's/\[\[ "$EUID" -eq 0 \]\] || privilege=(sudo)/privilege=(fixture_priv)/')
# shellcheck source=/dev/null
source /dev/stdin < <(sed -n '/^    connect_selected_active_bssid() {/,/^    }/p' "$repo/netmgr")
ensure_sudo_session() { return 0; }
find_wifi_connection_for_ssid() { printf '%s\n' 'saved-profile'; }
sleep() { :; }
# Dynamic scope consumed by the extracted connection function.
# shellcheck disable=SC2034
INTERFACE='test-wifi'
# shellcheck disable=SC2034
PRIV_CMD=(fixture_priv)
fixture_priv() {
    printf '%s\n' "$*" >> "$tmp/commands"
    case "$*" in
        'nmcli -g connection.interface-name '*) printf '\n' ;;
        *'connection add '*) return 0 ;;
        *'connection delete uuid '*) return 0 ;;
        *'connection modify '*) return 0 ;;
        *'connection up '* | *'device wifi connect '*)
            printf 'fixture activation failed\n' >&2
            return 10
            ;;
        *) return 0 ;;
    esac
}
rc=0
connect_selected_active_bssid '' 'fixture network' 5975 '' > "$tmp/out" 2> "$tmp/errors" || rc=$?
equal "$rc" 10
rc=0
connect_selected_active_bssid '' 'fixture network' 5975 'fixture\password' > "$tmp/out" 2> "$tmp/errors" || rc=$?
equal "$rc" 10
rg -q 'connection.autoconnect no' "$tmp/commands" || fail 'temporary profile can autoconnect'
if rg 'connection delete ' "$tmp/commands" | rg -qv 'connection delete uuid [0-9a-f-]{36}$'; then
    fail 'attempted to delete a pre-existing named profile'
fi
rc=0
connect_wifi_bssid test-wifi '00:11:22:33:44:55' 'fixture\password' > /dev/null 2>&1 || rc=$?
equal "$rc" 10
rg -Fq 'password fixture\password' "$tmp/commands" || fail 'password was modified'
printf 'PASS: Wi-Fi failure status, privileged dispatch, literal passwords, and safe temporary profiles\n'

# Exercise the managed listener on fixed text, including a failing capture exit code.
# shellcheck source=/dev/null
source /dev/stdin < <(sed -n '/^listen_subnet() {/,/^}/p' "$repo/netmgr" | sed 's/\<sudo\>/fixture_priv/g')
ip() {
    case "$*" in
        '-o -4 address show dev wlfake') printf '1: wlfake inet 192.0.2.10/24\n' ;;
        '-j neigh show dev wlfake') printf '[]\n' ;;
        *) forbidden ip "$@" ;;
    esac
}
fixture_tshark() {
    cat << 'EOF'
00:00:00:00:00:00|192.0.2.90||eth:ip:udp|||68|67|0x0800|DHCP
01:00:5e:00:00:01|192.0.2.91||eth:ip:udp|||68|67|0x0800|DHCP
02:22:33:44:55:66|198.51.100.20||eth:ip:tcp|443|40000|||0x0800|TLS
00:11:22:33:44:20|192.0.2.20||eth:ip:udp|||68|67|0x0800|DHCP
00:11:22:33:44:20|192.0.2.20||eth:ip:udp|||68|67|0x0800|DHCP
EOF
    return 17
}
tshark() { fixture_tshark; }
fixture_priv() {
    case "$1" in
        -v) return 0 ;;
        tshark) fixture_tshark ;;
        *) forbidden "$@" ;;
    esac
}
sleep() { forbidden sleep "$@"; }
rc=0
listen_subnet wlfake managed --dedupe > "$tmp/listener" 2> "$tmp/listener-errors" || rc=$?
equal "$rc" 17
equal "$(rg -c 'NEW HOST DETECTED' "$tmp/listener")" 2
rg -Fq 'source; MAC may be next-hop' "$tmp/listener" || fail 'routed traffic misidentified'
rg -q '00:00:00:00:00:00|01:00:5e:00:00:01' "$tmp/listener" && fail 'bogus MAC was displayed'
[[ ! -s "$tmp/forbidden" ]] || fail 'a test attempted an unmocked live operation'
printf 'PASS: listener dedupe, invalid MAC filtering, routed-source annotation and capture failure status\n'
