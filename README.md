# netmgr

Single-file Bash network toolkit with interactive shell support (`NETMGR>`).

## Project Structure
```text
/home/lewis/Dev/netmgr
├── netmgr      # Main executable CLI script
└── README.md   # Documentation
```

## Commands

`netmgr` supports direct command mode and interactive mode.

Implemented commands:
- `interfaces`
- `scan [intf] [target] [--ports] [--resolve-hostnames]`
- `ports`
- `listen [intf] [managed|monitor] [--channel n] [--bssid mac] [--dedupe]`
- `bssid-scan [intf] [seconds]`
- `fingerprint <ip> [--fast]`
- `traceroute [intf] [target]`
- `help`
- `exit` / `quit`

## Dependencies

Core tools used by the script:
- `bash`, `sudo`
- `ip`, `jq`, `awk`, `sed`, `grep`, `sort`, `column`, `xargs`, `timeout`
- `curl`, `nmap`, `ss`, `nmcli`, `tcpdump`, `tshark`, `mtr`, `whois`, `dig`

Optional/fallback:
- `iw` (used by `interfaces` and monitor mode)
- `/usr/share/nmap/nmap-mac-prefixes` (local MAC vendor DB)

## Data Files and Environment

### MAC/IP cache
- Path: `~/.local/share/netmgr/mac_ip_map.tsv`
- Override: `NETMGR_MAC_IP_DB`
- Format: `mac<TAB>ip` (lowercase MAC)

Behavior:
- `scan` continuously upserts this file while streaming discoveries.
- `listen` uses this file to fill `IP_Address` where available.

### MAC vendor DB
- Default local DB: `/usr/share/nmap/nmap-mac-prefixes`
- Override: `NETMGR_MAC_PREFIX_DB`
- Fallback when local prefix miss: `https://api.macvendors.com/<mac>`

### Other env knobs
- `NETMGR_SCAN_NMAP_DELAY` (seconds between nmap loops, default `2`)
- `AVAHI_JOBS` (parallelism for `scan --resolve-hostnames`, default `16`)
- `NETMGR_AIRMON_KILL=1` (optional `airmon-ng check kill` pre-step in monitor mode)
- `NETMGR_TRACE_DISCOVERY_ROUNDS` (traceroute hop-discovery rounds, default `3`)

## Command Details

### `interfaces`
Prints a table:
- `Interface`, `Status`, `IP_Address`, `MAC_Address`, `MTU`, `DHCP`, `Gateway`

Then appends raw diagnostics:
- `sudo iw dev` (with path fallback for `iw`)
- `lspci -knn | grep -iA2 net`
- `ip route show`
- `sudo ethtool <detected ethernet interfaces>`
- `ip -s addr`

### `scan [intf] [target] [--ports] [--resolve-hostnames]`
Continuous streaming discovery using nmap + tshark in parallel.

Interface/target resolution:
- If `intf` omitted and `target` provided, route lookup picks the interface for that target.
- If both omitted, first UP interface is selected.
- Target defaults to interface subnet.

Primary streaming loop:
```bash
sudo nmap -sn -PS22,80,443 -PA21,23,3389 -PU40125 --max-retries 5 --stats-every 10s -e <intf> <target>
```

Parallel packet stream:
- Runs `tshark` on the same interface.
- Parses both `src` and `dst` IPv4/MAC pairs.
- Dedupes streamed lines by MAC for console output.
- Ignores unknown MAC, broadcast, and multicast MAC rows.

Live output columns:
- `Time`, `SRC` (`NMAP` or `TSHARK`), `IP_Address`, `MAC_Address`, `Hostname`, `Vendor`

Optional `--ports`:
1. Collect discovered IPs
2. Run:
```bash
sudo nmap -Pn --top-ports 200 -sS -n --min-parallelism 64 -iL - -oG -
```
3. Parse open ports into final `Ports` column

Optional `--resolve-hostnames`:
- Uses `getent hosts <ip>` with `timeout 0.3s` in parallel.

End of run:
- Press `Ctrl+C` to stop streaming loops.
- Prints final table:
  - `IP_Address`, `Hostname/Identity`, `MAC_Address`, `Manufacturer`, `Ports`

### `ports`
Runs:
```bash
sudo ss -tuanp | sort -k 1,1
```

### `listen [intf] [managed|monitor] [--channel n] [--bssid mac] [--dedupe]`
Default interface: `wlp8s0`
Default mode: `managed`

`--dedupe` behavior:
- With `--dedupe`: one output line per MAC
- Without `--dedupe`: prints all parsed traffic rows

#### Managed mode
- Captures all traffic on the interface.
- Uses `tshark` when available for full protocol stack decoding.
- Falls back to `tcpdump` basic parser if `tshark` is unavailable.

Output (non-dedupe):
- `Time`, `MAC_Address`, `IP_Address`, `Vendor`, `Protocol_Stack`

Notes:
- On Wi-Fi interfaces named `wlp*`, `Ethernet` in the stack is relabeled to `Synthetic Eth`.
- Vendor output is truncated to 31 chars for table alignment.
- Uses `[OK]`/`[ERR]` status labels.

#### Monitor mode
- Requires sudo-capable flow.
- Builds/uses monitor interface `mon0`.
- Cleans stale monitor and dummy hotspot resources (`mon0`, `Netmgr_Awake`, `netmgr_dummy`) before start.
- Optional `--bssid` filter and `--channel` lock.
- If `--bssid` is supplied without channel, attempts to discover the channel via `nmcli` then `iw` scan fallback.
- If no fixed channel can be resolved, enables channel hopping.

MediaTek wake-up path (when channel is known):
- Creates temporary hotspot with `nmcli` to wake/lock radio state.
- Keeps capture on `mon0`.

Monitor output columns:
- `Time`, `BSSID`, `SSID`, `CH`, `MAC_Address`, `IP_Address`, `Vendor`, `Protocol`

Decryption attempt:
- Reads saved Wi-Fi credentials from NetworkManager and passes WPA key to tshark decode options when available.
- If not available, logs warning and protocol may remain `802.11`.

Exit behavior:
- `Ctrl+C` triggers cleanup, deletes monitor/hotspot resources, and attempts reconnect to previous Wi-Fi connection.

### `bssid-scan [intf] [seconds]`
Managed-mode Wi-Fi survey using `nmcli`.

Defaults:
- Interface: `wlp8s0`
- Duration: `12` seconds

Output columns:
- `BSSID`, `SSID`, `Channel`, `Freq_MHz`, `Band` (`2.4GHz`/`5GHz`/`6GHz`), `Signal_pct`, `Seen`

### `fingerprint <ip> [--fast]`
Host fingerprinting:
- Default:
```bash
sudo nmap -A -p- -T4 <ip>
```
- Fast mode:
```bash
sudo nmap -A --top-ports 100 -T4 <ip>
```

### `traceroute [intf] [target]`
Deep traceroute with enrichment.

Defaults:
- Target: `8.8.8.8`
- Interface: auto-selected from route if not provided

Behavior:
- Accepts IPv4, IPv6, or hostname targets.
- For hostnames, performs a Happy Eyeballs probe with:
```bash
curl --happy-eyeballs-timeout-ms 200
```
- Prints:
  - AAAA candidates
  - A candidates
  - winner family/IP
  - winner reason (including interface route/address constraints when relevant)
- Uses family-specific route lookup (`ip -4/-6 route get ...`)
- Discovers hops by running `traceroute` in three modes (`UDP`, `ICMP`, `TCP:443`) across multiple rounds, writes merged hop list to `/tmp/route-hops.txt`, then pings each hop 20 times.
- Enriches hops with ASN/netname/location via `ipinfo.io` + Team Cymru whois.

Output columns:
- `Hop`, `IP_Address`, `Loss`, `Avg`, `Lowest`, `Netname`, `ASN`, `Location`

## Usage

### Direct mode
```bash
./netmgr interfaces
./netmgr scan wlp8s0 192.168.1.0/24
./netmgr scan wlp8s0 192.168.1.0/24 --ports --resolve-hostnames
./netmgr listen wlp8s0 managed
./netmgr listen wlp8s0 managed --dedupe
./netmgr listen wlp8s0 monitor --bssid D4:86:60:6B:80:89 --channel 6
./netmgr bssid-scan wlp8s0 15
./netmgr fingerprint 192.168.1.254 --fast
./netmgr traceroute wlp8s0 www.google.com
```

### Interactive mode
```bash
./netmgr
NETMGR> interfaces
NETMGR> scan wlp8s0 192.168.1.0/24 --ports
NETMGR> listen wlp8s0 monitor --bssid D4:86:60:6B:80:89 --channel 6
NETMGR> traceroute enp9s0 www.google.com
NETMGR> exit
```

## Author
Terrydaktal
