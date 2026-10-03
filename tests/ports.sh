#!/usr/bin/env bash
set -euo pipefail

# Keep fixture widths independent of the terminal running this suite.
COLUMNS=200

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

# Extract only these functions; never launch netmgr or run privileged commands.
# shellcheck source=/dev/null
source /dev/stdin < <(sed -n '/^format_port_table() {/,/^}/p' "$repo/netmgr")
# shellcheck source=/dev/null
source /dev/stdin < <(sed -n '/^show_ports() {/,/^}/p; /^socket_snapshot() {/,/^}/p; /^sockets_use_tui() {/,/^}/p' "$repo/netmgr" |
    sed -e 's/ensure_sudo_session/ports_auth/' -e 's/sudo /ports_priv /g')
# shellcheck source=/dev/null
source /dev/stdin < <(sed -n '/^run_command() {/,/^}/p; /^show_help() {/,/^}/p' "$repo/netmgr")

cat > "$tmp/conntrack" << 'EOF'
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.20 sport=40000 dport=443 src=198.51.100.20 dst=192.0.2.10 sport=443 dport=40000 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=198.51.100.20 dst=192.0.2.10 sport=50000 dport=8080 src=192.0.2.10 dst=198.51.100.20 sport=8080 dport=50000 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.20 sport=22 dport=8443 src=198.51.100.20 dst=192.0.2.10 sport=8443 dport=22 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.20 sport=40010 dport=443 src=198.51.100.20 dst=203.0.113.10 sport=443 dport=60010 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=203.0.113.20 dst=198.51.100.10 sport=50010 dport=8443 src=10.0.0.2 dst=203.0.113.20 sport=8080 dport=50010 [ASSURED] mark=0 use=1
ipv6 10 tcp 6 431999 ESTABLISHED src=2001:0db8:0000:0000:0000:0000:0000:0001 dst=2001:0db8:0000:0000:0000:0000:0000:0002 sport=40020 dport=443 src=2001:0db8:0000:0000:0000:0000:0000:0002 dst=2001:0db8:0000:0000:0000:0000:0000:0001 sport=443 dport=40020 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.20 sport=40002 dport=443 src=198.51.100.20 dst=192.0.2.10 sport=443 dport=40002 [ASSURED] mark=0 use=1
ipv6 10 tcp 6 431999 ESTABLISHED src=0000:0000:0000:0000:0000:ffff:c000:020a dst=0000:0000:0000:0000:0000:ffff:c633:6414 sport=40003 dport=443 src=0000:0000:0000:0000:0000:ffff:c633:6414 dst=0000:0000:0000:0000:0000:ffff:c000:020a sport=443 dport=40003 [ASSURED] mark=0 use=1
ipv4 2 udp 17 29 src=192.0.2.10 dst=198.51.100.53 sport=40004 dport=53 src=198.51.100.53 dst=192.0.2.10 sport=53 dport=40004 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=127.0.0.1 dst=127.0.0.1 sport=40030 dport=7777 src=127.0.0.1 dst=127.0.0.1 sport=7777 dport=40030 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.2 dst=192.0.2.10 sport=40031 dport=7778 src=192.0.2.10 dst=10.0.0.2 sport=7778 dport=40031 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 119 ESTABLISHED src=192.0.2.10 dst=198.51.100.20 sport=40005 dport=443 [UNREPLIED] src=198.51.100.20 dst=192.0.2.10 sport=443 dport=40005 mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.20 sport=40006 dport=443 src=198.51.100.20 dst=192.0.2.10 sport=443 dport=40006 [ASSURED] zone=7 mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.20 sport=40007 dport=443 src=198.51.100.20 dst=192.0.2.10 sport=443 dport=40007 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=198.51.100.20 dst=192.0.2.10 sport=443 dport=40007 src=192.0.2.10 dst=198.51.100.20 sport=40007 dport=443 [ASSURED] mark=0 use=1
ipv6 10 tcp 6 431999 ESTABLISHED src=fe80:0000:0000:0000:0000:0000:0000:0001 dst=fe80:0000:0000:0000:0000:0000:0000:0002 sport=40008 dport=443 src=fe80:0000:0000:0000:0000:0000:0000:0002 dst=fe80:0000:0000:0000:0000:0000:0000:0001 sport=443 dport=40008 [ASSURED] mark=0 use=1
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.20 sport=40009 dport=443
ipv4 2 tcp 6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.20 sport=40040 dport=443 src=198.51.100.20 dst=192.0.2.10 sport=443 dport=40040 [ASSURED] mark=0 use=1
ipv4 2 udp 17 29 src=198.51.100.20 dst=192.0.2.10 sport=443 dport=40040 src=192.0.2.10 dst=198.51.100.20 sport=40040 dport=443 [ASSURED] mark=0 use=1
EOF

cat > "$tmp/sockets" << 'EOF'
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("udp-unconnected",pid=1,fd=1))
tcp LISTEN 0 128 127.0.0.10:22 0.0.0.0:* users:(("address-ten",pid=2,fd=1))
tcp ESTAB 0 0 192.0.2.10:8080 198.51.100.20:50000 users:(("incoming-no-listener",pid=3,fd=1))
tcp ESTAB 0 0 192.0.2.10:40000 198.51.100.20:443 users:(("outgoing",pid=4,fd=1)) cubic rto:201 bytes_received:1048576 bytes_acked:2048
tcp ESTAB 0 0 192.0.2.10:22 198.51.100.20:8443 users:(("outgoing-low-port",pid=5,fd=1))
tcp ESTAB 0 0 192.0.2.10:40000 203.0.113.99:443 users:(("different-peer",pid=6,fd=1))
tcp ESTAB 0 0 192.0.2.10:40001 198.51.100.20:443 users:(("missing",pid=7,fd=1))
tcp ESTAB 0 0 192.0.2.10:40010 198.51.100.20:443 users:(("nat-outgoing",pid=8,fd=1))
tcp ESTAB 0 0 203.0.113.10:60010 198.51.100.20:443 users:(("nat-translated",pid=9,fd=1))
tcp ESTAB 0 0 10.0.0.2:8080 203.0.113.20:50010 users:(("nat-incoming",pid=10,fd=1))
tcp ESTAB 0 0 [2001:DB8::1]:40020 [2001:db8::2]:443 users:(("ipv6-compressed",pid=11,fd=1))
tcp ESTAB 0 0 [::ffff:192.0.2.10]:40002 [::ffff:198.51.100.20]:443 users:(("ipv4-mapped",pid=12,fd=1))
tcp ESTAB 0 0 192.0.2.10:40003 198.51.100.20:443 users:(("mapped-tracking",pid=13,fd=1))
udp ESTAB 0 0 192.0.2.10:40004 198.51.100.53:53 users:(("udp-outgoing",pid=14,fd=1))
tcp ESTAB 0 0 127.0.0.1:40030 127.0.0.1:7777 users:(("loopback-client",pid=15,fd=1))
tcp ESTAB 0 0 127.0.0.1:7777 127.0.0.1:40030 users:(("loopback-server",pid=16,fd=1))
tcp ESTAB 0 0 10.0.0.2:40031 192.0.2.10:7778 users:(("local-address-peer",pid=17,fd=1))
tcp ESTAB 0 0 192.0.2.10:40005 198.51.100.20:443 users:(("midstream-unreplied",pid=18,fd=1))
tcp ESTAB 0 0 192.0.2.10:40006 198.51.100.20:443 users:(("nonzero-zone",pid=19,fd=1))
tcp ESTAB 0 0 192.0.2.10:40007 198.51.100.20:443 users:(("conflicting-records",pid=20,fd=1))
tcp ESTAB 0 0 [fe80::1%wlan0]:40008 [fe80::2%wlan0]:443 users:(("scoped-link-local",pid=21,fd=1))
tcp ESTAB 0 0 192.0.2.10:40009 198.51.100.20:443 users:(("malformed-record",pid=22,fd=1))
tcp ESTAB 0 0 192.0.2.10:40040 198.51.100.20:443 users:(("tcp-protocol-key",pid=23,fd=1))
udp ESTAB 0 0 192.0.2.10:40040 198.51.100.20:443 users:(("udp-protocol-key",pid=24,fd=1))
tcp LISTEN 0 128 127.0.0.2:443 0.0.0.0:* users:(("address-two",pid=25,fd=1))
tcp LISTEN 0 128 127.0.0.1:10000 0.0.0.0:* users:(("port-high",pid=26,fd=1))
tcp LISTEN 999 128 127.0.0.1:80 0.0.0.0:* users:(("port-low",pid=27,fd=1))
tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("wildcard-v4",pid=28,fd=1))
tcp LISTEN 0 128 [::]:22 [::]:* users:(("ipv6-listener",pid=28,fd=1))
tcp ESTAB 123456789 9876543210 192.0.2.10:40099 198.51.100.20:443 users:(("worker  name",pid=29,fd=1), ("other worker",pid=30,fd=2))
udp UNCONN 17 4096 [::]:5353 [::]:*
EOF

format_port_table "$tmp/conntrack" "$tmp/sockets" > "$tmp/actual"
assert_origin() {
    local actual pid
    pid=$(awk -v name="\"$1\"" 'index($0, name) && match($0, /pid=([0-9]+)/, owner) {print owner[1]; exit}' "$tmp/sockets")
    actual=$(awk -v pid="$pid" 'NR == 1 {for (i=1; i<=NF; i++) if ($i == "PID") pid_col=i; next} index(";" $pid_col ";", ";" pid ";") {print $3}' "$tmp/actual" | sort -u)
    if [[ "$actual" != "$2" ]]; then
        printf 'FAIL: %s expected %s, got %s\n' "$1" "$2" "$actual" >&2
        exit 1
    fi
}

while read -r name origin; do
    assert_origin "$name" "$origin"
done << 'EOF'
incoming-no-listener INBOUND*
outgoing OUTBOUND*
outgoing-low-port OUTBOUND*
different-peer UNKNOWN
missing UNKNOWN
nat-outgoing OUTBOUND*
nat-translated OUTBOUND*
nat-incoming INBOUND*
ipv6-compressed OUTBOUND*
ipv4-mapped OUTBOUND*
mapped-tracking OUTBOUND*
udp-outgoing OUTBOUND*
loopback-client SAME-HOST*
loopback-server SAME-HOST*
local-address-peer SAME-HOST*
midstream-unreplied UNKNOWN
nonzero-zone UNKNOWN
conflicting-records UNKNOWN
scoped-link-local UNKNOWN
malformed-record UNKNOWN
tcp-protocol-key OUTBOUND*
udp-protocol-key INBOUND*
udp-unconnected -
address-ten -
address-two -
port-high -
port-low -
wildcard-v4 -
ipv6-listener -
EOF
printf '%s\n' 'PASS: origin matching, NAT, IPv4/IPv6, local peers, UDP, and conservative unknowns'

assert_header() {
    [[ $(awk 'NR == 1 {$1=$1; print; exit}' "$tmp/actual") == 'State Net Origin Local Peer Downloaded Uploaded PID App' ]]
}

# Compare socket values after reordering; ownership now has separate columns.
canonical_socket_rows() {
    awk -v reordered="$1" '
        NR == 1 { next }
        {
            if (reordered) {
                proto=$2; state=$1; recv=$8; send=$9; local=$4; peer=$5
            } else {
                proto=$1; state=$2; recv=$3; send=$4; local=$5; peer=$6
            }
            if (proto == "udp" && state == "BOUND") state="UNCONN"
            printf "%s\t%s\t%s\t%s\t%s\t%s\n", proto, state, recv, send, local, peer
        }
    ' "$2" | LC_ALL=C sort
}
assert_header
[[ $(awk '/worker  name/ {print $8}' "$tmp/actual") == '29;30' ]]
format_port_table "$tmp/conntrack" "$tmp/sockets" /dev/null 0 1 > "$tmp/with-queues"
diff -u <(canonical_socket_rows 0 "$tmp/sockets") <(canonical_socket_rows 1 "$tmp/with-queues")
[[ $(awk '/worker  name/ {print $8, $9, $10}' "$tmp/with-queues") == '123456789 9876543210 29;30' ]]
[[ $(awk '$4 == "[::]:5353" {print $10, $8, $9}' "$tmp/with-queues") == '- 17 4096' ]]
printf '%s\n' 'PASS: PID/executable columns, multiple owners, queues hidden by default and retained in verbose'

if command -v script > /dev/null 2>&1; then
    export -f format_port_table
    env -u NO_COLOR script --quiet --command="bash -c 'format_port_table \"$tmp/conntrack\" \"$tmp/sockets\"'" /dev/null > "$tmp/colored"
    color_prefix=$'\033[1;33m'
    [[ $(grep -F -c "$color_prefix" "$tmp/colored") -eq 2 ]]
    grep -F "$color_prefix" "$tmp/colored" | grep -Fq 'wildcard-v4'
    grep -F "$color_prefix" "$tmp/colored" | grep -Fq 'ipv6-listener'
    if grep -F "$color_prefix" "$tmp/colored" | grep -Fq 'address-ten'; then
        printf '%s\n' 'FAIL: specific-address listener was highlighted' >&2
        exit 1
    fi
    printf '%s\n' 'PASS: wildcard IPv4/IPv6 listeners are highlighted only on terminals'
    inbound_prefix=$'\033[1;36m'
    [[ $(grep -F -c "$inbound_prefix" "$tmp/colored") -eq $(awk '$3 == "INBOUND*" {n++} END {print n + 0}' "$tmp/actual") ]]
    if grep -F "$inbound_prefix" "$tmp/colored" | grep -Fv 'INBOUND*'; then
        printf '%s\n' 'FAIL: non-inbound row received the inbound colour' >&2
        exit 1
    fi
    NO_COLOR=1 script --quiet --command="bash -c 'format_port_table \"$tmp/conntrack\" \"$tmp/sockets\"'" /dev/null > "$tmp/uncolored"
    if grep -Fq $'\033[' "$tmp/uncolored"; then
        printf '%s\n' 'FAIL: colour emitted with NO_COLOR' >&2
        exit 1
    fi
    printf '%s\n' 'PASS: inbound sockets use cyan, wildcard listeners retain yellow, and NO_COLOR disables both'
fi

previous_group=''
previous_state_origin=''
previous_address=''
previous_port=0
while read -r state proto origin endpoint _rest; do
    group="$state $origin $proto"
    address=${endpoint%:*}
    port=${endpoint##*:}
    if [[ "$group" == "$previous_group" ]]; then
        if [[ "$address" == "$previous_address" ]]; then
            ((port >= previous_port))
        else
            printf '%s\n' "$previous_address" "$address" | LC_ALL=C sort -CV
        fi
    elif [[ "$state $origin" == "$previous_state_origin" ]]; then
        printf '%s\n' "$previous_group" "$group" | LC_ALL=C sort -C
    fi
    previous_group=$group
    previous_state_origin="$state $origin"
    previous_address=$address
    previous_port=$port
done < <(tail -n +2 "$tmp/actual")
cat > "$tmp/expected-groups" << 'EOF'
ESTAB OUTBOUND*
ESTAB SAME-HOST*
ESTAB INBOUND*
ESTAB UNKNOWN
LISTEN -
BOUND -
EOF
awk 'NR > 1 {group = $1 " " $3; if (group != previous) print group; previous = group}' "$tmp/actual" > "$tmp/actual-groups"
diff -u "$tmp/expected-groups" "$tmp/actual-groups"
printf '%s\n' 'PASS: header and original rows preserved; state/origin groups, then protocol, local address and numeric port order'

: > "$tmp/empty"
head -n 1 "$tmp/sockets" > "$tmp/header"
format_port_table "$tmp/empty" "$tmp/header" > "$tmp/actual"
assert_header
[[ $(wc -l < "$tmp/actual") -eq 1 ]]
format_port_table "$tmp/empty" "$tmp/empty" > "$tmp/actual"
[[ ! -s "$tmp/actual" ]]
format_port_table "$tmp/empty" "$tmp/sockets" > "$tmp/actual"
assert_origin outgoing UNKNOWN
assert_origin ipv6-listener -
printf '%s\n' 'PASS: empty tracking data and header-only sockets'

cat > "$tmp/udp-states" << 'EOF'
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*
udp UNCONN 17 4096 [::]:5353 [::]:*
udp UNCONN 0 0 0.0.0.0:0 0.0.0.0:*
udp UNCONN 0 0 *:* *:*
udp ESTAB 0 0 192.0.2.10:40004 198.51.100.53:53
tcp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*
EOF
format_port_table "$tmp/empty" "$tmp/udp-states" > "$tmp/udp-output"
awk 'NR > 1 {print $2, $4, $1, $3}' "$tmp/udp-output" | LC_ALL=C sort > "$tmp/udp-actual"
cat << 'EOF' | LC_ALL=C sort > "$tmp/udp-expected"
udp 0.0.0.0:53 BOUND -
udp [::]:5353 BOUND -
udp 0.0.0.0:0 UNCONN -
udp *:* UNCONN -
udp 192.0.2.10:40004 ESTAB UNKNOWN
tcp 0.0.0.0:53 UNCONN -
EOF
diff -u "$tmp/udp-expected" "$tmp/udp-actual"
printf '%s\n' 'PASS: BOUND is a display alias only for unconnected UDP sockets with a local port'

cat > "$tmp/traffic" << 'EOF'
Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp ESTAB 3 4 192.0.2.1:1 192.0.2.2:443 users:(("browser bytes_received:999999",pid=101,fd=3)) cubic bytes_sent:999 bytes_acked:2048 bytes_received:1048576
tcp ESTAB 0 0 [2001:db8::1]:2 [2001:db8::2]:443 cubic bytes_received:0 bytes_acked:0
tcp ESTAB 0 0 192.0.2.1:3 192.0.2.2:443 cubic bytes_acked:500
tcp CLOSE-WAIT 12 0 192.0.2.1:4 192.0.2.2:443 cubic bytes_received:8192
tcp ESTAB 0 0 192.0.2.1:5 192.0.2.2:443 cubic rto:201 cwnd:10
tcp TIME-WAIT 0 0 192.0.2.1:6 192.0.2.2:443
tcp LISTEN 0 128 0.0.0.0:7 0.0.0.0:* cubic bytes_received:123 bytes_acked:456
udp ESTAB 0 0 192.0.2.1:8 192.0.2.2:443 bytes_received:123 bytes_acked:456
tcp ESTAB 0 0 192.0.2.1:9 192.0.2.2:443 cubic bytes_received:18446744073709551615 bytes_acked:9007199254740993
tcp ESTAB 0 0 192.0.2.1:10 192.0.2.2:443 cubic bytes_received:-1 bytes_acked:nan
tcp ESTAB 0 0 192.0.2.1:11 192.0.2.2:443 cubic bytes_received:18446744073709551616 bytes_acked:4
tcp ESTAB 0 0 192.0.2.1:12 192.0.2.2:443 cubic bytes_received:42 bytes_received:43 bytes_acked:9
tcp ESTAB 0 0 192.0.2.1:13 192.0.2.2:443 users:(("fake \"quoted\" bytes_received:999 bytes_acked:456",pid=113,fd=4)) cubic rto:201
tcp ESTAB 0 0 192.0.2.1:14 192.0.2.2:443 cubic bytes_sent:1024 bytes_retrans:4
tcp ESTAB 0 0 192.0.2.1:15 192.0.2.2:443 cubic bytes_received:8junk bytes_acked:7:9
tcp ESTAB 0 0 192.0.2.1:16 192.0.2.2:443 cubic bytes_received:1048575 bytes_acked:1
EOF
format_port_table "$tmp/empty" "$tmp/traffic" /dev/null 0 0 1 > "$tmp/traffic-machine"
awk -F '\t' 'NR > 1 {port=$4; sub(/^.*:/, "", port); print port, $6, $7}' "$tmp/traffic-machine" | sort -k1,1n > "$tmp/traffic-actual"
cat > "$tmp/traffic-expected" << 'EOF'
1 1048576 2048
2 0 0
3 0 500
4 8192 0
5 - -
6 - -
7 - -
8 - -
9 18446744073709551615 9007199254740993
10 - -
11 - 4
12 - 9
13 - -
14 - -
15 - -
16 1048575 1
EOF
diff -u "$tmp/traffic-expected" "$tmp/traffic-actual"
[[ $(awk -F '\t' '$4 == "192.0.2.1:1" {print $8, $9, $10, $11}' "$tmp/traffic-machine") == '3 4 101 browser bytes_received:999999' ]]
format_port_table "$tmp/empty" "$tmp/traffic" > "$tmp/traffic-human"
[[ $(awk '$4 == "192.0.2.1:1" {print $6, $7}' "$tmp/traffic-human") == '1.0MiB 2.0KiB' ]]
[[ $(awk '$4 == "[2001:db8::1]:2" {print $6, $7}' "$tmp/traffic-human") == '0B 0B' ]]
[[ $(awk '$4 == "192.0.2.1:9" {print $6, $7}' "$tmp/traffic-human") == '16.0EiB 8.0PiB' ]]
[[ $(awk '$4 == "192.0.2.1:16" {print $6, $7}' "$tmp/traffic-human") == '1.0MiB 1B' ]]
format_port_table "$tmp/empty" "$tmp/traffic" /dev/null 1 > "$tmp/traffic-exact"
rg -Fq '18446744073709551615  9007199254740993' "$tmp/traffic-exact"
printf '%s\n' 'PASS: TCP lifetime counters, suppressed zeros, absent/invalid data, IPv6, UDP/listeners, exact uint64 and compact units'

auth_rc=0
ss_rc=0
ct_rc=0
ports_auth() { return "$auth_rc"; }
ports_details_rc=0
collect_port_details() {
    printf '%s\n' "$*" >> "$tmp/details-calls"
    cat > "$tmp/details-input"
    if [[ "$*" == '--all-details' ]]; then
        printf 'Row\tPID\tUser\tAge\tUID\tEUID\tExecutable\tApp\tCWD\tService\tCommand\tDescription\n'
        printf '4\t4\tfixture\t12m08s\t1000\t1000\t/usr/bin/client-fixture\tclient-fixture<-fish\t/tmp/fixture-project\tclient.service\t/usr/bin/client-fixture --label two words --config /tmp/fixture/settings.json\tFixture description\n'
    elif [[ "$*" == '--verbose' ]]; then
        printf 'Row\tPID\tUser\tAge\tApp\tCWD\tCommand\n'
        printf '4\t4\tfixture\t12m08s\tclient-fixture<-fish\t/tmp/fixture-project\tclient-fixture --label two words --config .../settings.json\n'
    else
        printf 'Row\tPID\tUser\tAge\tApp\tCWD\n'
        printf '4\t4\tfixture\t12m08s\tclient-fixture<-fish\t/tmp/fixture-project\n'
    fi
    return "$ports_details_rc"
}
ports_priv() {
    [[ "$1" == -n ]] || {
        printf 'FAIL: snapshot privilege command may prompt\n' >&2
        return 99
    }
    shift
    printf '%s\n' "$*" >> "$tmp/commands"
    case "$*" in
        'ss -tuanp -i -O')
            if ((ss_rc != 0)); then return "$ss_rc"; fi
            cat "$tmp/sockets"
            ;;
        'cat /proc/net/nf_conntrack')
            if ((ct_rc != 0)); then
                printf '%s\n' 'partial data from failed read'
                return "$ct_rc"
            fi
            cat "$tmp/conntrack"
            ;;
        *) return 99 ;;
    esac
}

show_ports > "$tmp/actual" 2> "$tmp/stderr"
assert_origin outgoing 'OUTBOUND*'
[[ ! -s "$tmp/stderr" ]]
printf 'ss -tuanp -i -O\ncat /proc/net/nf_conntrack\n' > "$tmp/expected-commands"
diff -u "$tmp/expected-commands" "$tmp/commands"
diff -u "$tmp/sockets" "$tmp/details-input"
[[ $(wc -l < "$tmp/details-calls") -eq 1 ]]
rg -q 'Initiation is inferred, not verified' "$tmp/actual"
rg -Fq 'BOUND = UDP socket with a local port and no fixed peer' "$tmp/actual"
[[ $(awk '$9 == "1" {print $1, $3}' "$tmp/actual") == 'BOUND -' ]]
rg -Fq 'OUTBOUND*/INBOUND* = inferred local/remote initiation' "$tmp/actual"
if rg -q '\b(LOCAL|REMOTE)\*' "$tmp/actual"; then
    printf '%s\n' 'FAIL: obsolete origin labels remain' >&2
    exit 1
fi
[[ $(awk 'NR == 1 {$1=$1; print; exit}' "$tmp/actual") == 'State Net Origin Local Peer Downloaded Uploaded Age PID User App CWD' ]]
[[ $(awk '$9 == "4" {print $4, $10, $8, $11, $12}' "$tmp/actual") == '192.0.2.10:40000 fixture 12m08s client-fixture<-fish /tmp/fixture-project' ]]
if rg -q 'users:\(|Listener Details:|Process Details:|\b(Process|Context|Command)\b|--label' "$tmp/actual"; then
    printf '%s\n' 'FAIL: redundant process/context fields or verbose commands in default view' >&2
    exit 1
fi
show_ports --brief > "$tmp/actual"
assert_header
[[ $(wc -l < "$tmp/details-calls") -eq 1 ]]
show_ports --verbose > "$tmp/actual"
[[ $(tail -n 1 "$tmp/details-calls") == '--verbose' ]]
[[ $(awk 'NR == 1 {$1=$1; print; exit}' "$tmp/actual") == 'State Net Origin Local Peer Downloaded Uploaded Age Recv Send PID User App CWD Command' ]]
[[ $(awk '$11 == "4" {print $15}' "$tmp/actual") == client-fixture ]]
rg -Fq 'client-fixture --label two words --config .../settings.json' "$tmp/actual"
show_ports -v > "$tmp/verbose-alias"
diff -u "$tmp/actual" "$tmp/verbose-alias"
show_ports --all-details > "$tmp/actual"
[[ $(tail -n 1 "$tmp/details-calls") == '--all-details' ]]
[[ $(head -n 1 "$tmp/actual") == *'App'*'CWD'*'Command'*'Description' ]]
rg -Fq '/usr/bin/client-fixture --label two words --config /tmp/fixture/settings.json' "$tmp/actual"
show_ports --verbose --all-details > "$tmp/combined"
diff -u "$tmp/actual" "$tmp/combined"
show_ports --all-details --verbose > "$tmp/combined"
diff -u "$tmp/actual" "$tmp/combined"
COLUMNS=180 show_ports > "$tmp/actual"
awk 'NF == 0 {exit} length($0) > 180 {exit 1}' "$tmp/actual"
[[ $(awk '$9 == "4" {print $4, $5}' "$tmp/actual") == '192.0.2.10:40000 198.51.100.20:443' ]]
[[ $(awk '$9 == "4" {print $10, $8}' "$tmp/actual") == 'fixture 12m08s' ]]
printf '%s\n' 'PASS: compact width, shortened commands, complete endpoints, and unabridged all-details'
printf '%s\n' 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process' \
    'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=300,fd=3))' > "$tmp/chain-sockets"
printf 'Row\tPID\tUser\tAge\tApp\tCWD\n1\t300\tfixture\t3d04h\tpython3.14<-fish<-xfce4-terminal<-systemd\t/home/fixture/a-very-long-directory/path/to/project\n' > "$tmp/chain-details"
COLUMNS=200 format_port_table "$tmp/empty" "$tmp/chain-sockets" "$tmp/chain-details" > "$tmp/actual"
rg -Fq 'python3.14<-fish<-xfce4-terminal<-systemd' "$tmp/actual"
rg -Fq '/home/fixture/a-very-long-directory/path/to/project' "$tmp/actual"
printf '%s\n' 'PASS: process chains and working directories that fit are preserved in full'
long_chain='python3.14<-uv-bin<-fish<-xfce4-terminal<-systemd-user-session<-systemd'
long_cwd='/home/fixture/projects/a very long workspace/services/transcription/working-directory'
long_command="python3 whisper_service.py --label 'two words' --config .../settings.json --log-level debug --bind 0.0.0.0 --port 8080"
printf 'Row\tPID\tUser\tAge\tApp\tCWD\tCommand\n1\t300\tfixture\t3d04h\t%s\t%s\t%s\n' \
    "$long_chain" "$long_cwd" "$long_command" > "$tmp/verbose-details"
for width in 80 180 360; do
    COLUMNS=$width format_port_table "$tmp/empty" "$tmp/chain-sockets" "$tmp/verbose-details" 0 1 > "$tmp/verbose-$width"
    for value in "$long_chain" "$long_cwd" "$long_command"; do
        rg -Fq -- "$value" "$tmp/verbose-$width"
    done
    [[ $(awk 'NR == 1 {$1=$1; print; exit}' "$tmp/verbose-$width") == 'State Net Origin Local Peer Downloaded Uploaded Age Recv Send PID User App CWD Command' ]]
    [[ $(awk 'NR == 2 {print $4, $5, $9, $10, $11, $12, $8}' "$tmp/verbose-$width") == '0.0.0.0:8080 0.0.0.0:* 0 128 300 fixture 3d04h' ]]
done
diff -u "$tmp/verbose-80" "$tmp/verbose-180"
diff -u "$tmp/verbose-180" "$tmp/verbose-360"
# Default mode still clips the same metadata and omits Command.
cut -f1-6 "$tmp/verbose-details" > "$tmp/compact-details"
COLUMNS=180 format_port_table "$tmp/empty" "$tmp/chain-sockets" "$tmp/compact-details" > "$tmp/actual"
awk 'length($0) > 180 {exit 1}' "$tmp/actual"
[[ $(awk 'NR == 2 {print $11}' "$tmp/actual") == *... ]]
rg -q '\.\.\..*/working-directory$' "$tmp/actual"
printf '%s\n' 'PASS: verbose preserves long App, CWD and Command values at all widths; default stays compact'
wide_chain="${long_chain}<-${long_chain}"
wide_cwd="/home/fixture/$(printf 'nested-directory/%.0s' {1..6})path/to/project"
printf 'Row\tPID\tUser\tAge\tApp\tCWD\n1\t300\tfixture\t3d04h\t%s\t%s\n' \
    "$wide_chain" "$wide_cwd" > "$tmp/wide-details"
for width in 268 360; do
    COLUMNS=$width format_port_table "$tmp/empty" "$tmp/chain-sockets" "$tmp/wide-details" > "$tmp/wide-$width"
    shown_app=$(awk 'NR == 2 {print $11}' "$tmp/wide-$width")
    shown_cwd=$(awk 'NR == 2 {print $12}' "$tmp/wide-$width")
    [[ ${#shown_app} -le 112 && ${#shown_app} -gt 56 && "$shown_app" == "${wide_chain:0:${#shown_app}-3}..." ]]
    [[ ${#shown_cwd} -le 64 && ${#shown_cwd} -gt 32 && "$shown_cwd" == "...${wide_cwd: -${#shown_cwd}+3}" ]]
    awk 'length($0) > 268 {exit 1} NR == 2 && length($0) <= 180 {exit 1}' "$tmp/wide-$width"
done
diff -u "$tmp/wide-268" "$tmp/wide-360"
(
    unset COLUMNS
    format_port_table "$tmp/empty" "$tmp/chain-sockets" "$tmp/wide-details" > "$tmp/wide-default"
)
diff -u "$tmp/wide-268" "$tmp/wide-default"
printf '%s\n' 'PASS: default App/CWD limits doubled to 112/64 with a matching wider table budget'
COLUMNS=20 format_port_table "$tmp/empty" "$tmp/chain-sockets" "$tmp/wide-details" 0 0 1 > "$tmp/machine"
[[ $(awk -F '\t' 'NR == 1 {print NF}' "$tmp/machine") == 14 ]]
[[ $(awk -F '\t' 'NR == 2 {print $13}' "$tmp/machine") == "$wide_chain" ]]
[[ $(awk -F '\t' 'NR == 2 {print $14}' "$tmp/machine") == "$wide_cwd" ]]
socket_snapshot 0 0 0 1 > "$tmp/machine"
[[ $(head -n 1 "$tmp/machine") == $'State\tNet\tOrigin\tLocal\tPeer\tDownloaded\tUploaded\tRecv\tSend\tPID\tUser\tAge\tApp\tCWD' ]]
if rg -q 'Snapshot only|Origin:|\x1b' "$tmp/machine"; then
    printf 'FAIL: live snapshot contains prose or terminal controls\n' >&2
    exit 1
fi
[[ $(awk -F '\t' '$10 == "4" {print $3}' "$tmp/machine") == 'OUTBOUND*' ]]
[[ $(awk -F '\t' '$10 == "4" {print $6, $7, $8, $9}' "$tmp/machine") == '1048576 2048 0 0' ]]
printf '%s\n' 'PASS: live snapshots are sorted, untruncated TSV without legends or ANSI'
ports_details_rc=1
show_ports > "$tmp/actual" 2> "$tmp/stderr"
assert_header
rg -q 'process detail collection failed' "$tmp/stderr"
ports_details_rc=130
rc=0
show_ports > "$tmp/actual" || rc=$?
[[ "$rc" -eq 130 ]]
ports_details_rc=0
command_count=$(wc -l < "$tmp/commands")
for option in '--bad-option' '--brief --all-details' '--brief --verbose' '-v --brief'; do
    read -r -a options <<< "$option"
    rc=0
    show_ports "${options[@]}" > "$tmp/actual" 2> "$tmp/stderr" || rc=$?
    [[ "$rc" -eq 2 && ! -s "$tmp/actual" ]]
done
show_ports --help > "$tmp/actual"
rg -Fq 'netmgr sockets [--once] [--brief | --verbose | --all-details]' "$tmp/actual"
rg -Fq 'Alias: netmgr ports (same options).' "$tmp/actual"
run_command help > "$tmp/help"
rg -q '^  sockets \[--once\] \[--brief\|--verbose\|--all-details\]' "$tmp/help"
rg -q '^  ports + - Compatibility alias for sockets\.' "$tmp/help"
for name in sockets ports; do
    run_command "$name" --help > "$tmp/$name-help"
    diff -u "$tmp/actual" "$tmp/$name-help"
    rc=0
    run_command "$name" --bad-option > "$tmp/output" 2> "$tmp/stderr" || rc=$?
    [[ "$rc" -eq 2 && ! -s "$tmp/output" ]]
    rg -Fq 'Error: unknown sockets option: --bad-option' "$tmp/stderr"
done
[[ $(wc -l < "$tmp/commands") -eq "$command_count" ]]
for option in '' --brief --verbose -v --all-details; do
    options=()
    if [[ -n "$option" ]]; then options+=("$option"); fi
    run_command sockets "${options[@]}" > "$tmp/sockets-output"
    run_command ports "${options[@]}" > "$tmp/ports-output"
    diff -u "$tmp/sockets-output" "$tmp/ports-output"
done
printf '%s\n' 'PASS: sockets primary command and ports alias share help, options, and output'
# Called by the extracted show_ports function.
# shellcheck disable=SC2329
sockets_use_tui() { return 0; }
show_sockets_live() { printf 'LIVE %s\n' "$*"; }
[[ $(show_ports) == 'LIVE ' ]]
[[ $(show_ports --verbose) == 'LIVE --verbose' ]]
[[ $(show_ports --brief) == 'LIVE --brief' ]]
[[ $(run_command ports --all-details) == 'LIVE --all-details' ]]
show_ports --once > "$tmp/once"
rg -q '^State +Net +Origin' "$tmp/once"
if rg -q '^LIVE' "$tmp/once"; then exit 1; fi
sockets_use_tui() { return 1; }
printf '%s\n' 'PASS: terminal defaults to live, --once bypasses live, ports shares dispatch'
printf '%s\n' 'PASS: process details default, brief/all-details options, validation, and partial failure'
ct_rc=1
show_ports > "$tmp/actual" 2> "$tmp/stderr"
assert_origin outgoing UNKNOWN
assert_origin ipv6-listener -
rg -q 'conntrack snapshot unavailable' "$tmp/stderr"
ss_rc=42
rc=0
show_ports > "$tmp/actual" || rc=$?
[[ "$rc" -eq 42 && ! -s "$tmp/actual" ]]
for name in sockets ports; do
    rc=0
    run_command "$name" --brief > "$tmp/actual" || rc=$?
    [[ "$rc" -eq 42 && ! -s "$tmp/actual" ]]
done
auth_rc=1
rc=0
show_ports > "$tmp/actual" || rc=$?
[[ "$rc" -eq 1 && ! -s "$tmp/actual" ]]
printf '%s\n' 'PASS: one read per snapshot, unavailable tracking fallback, and authentication/ss failures'
