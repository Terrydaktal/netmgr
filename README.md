# netmgr

Interactive network management and discovery CLI written as a single Bash script.

## Project Structure
```text
/home/lewis/Dev/netmgr
├── netmgr      # Main executable CLI script
└── README.md   # Documentation
```

## What `netmgr` Does

`netmgr` supports both single-command mode and an interactive shell (`NETMGR>` prompt).

Implemented commands:
- `interfaces`
- `scan [intf] [target] [--ports] [--resolve-hostnames]`
- `ports`
- `listen [intf] [managed|monitor] [bssid] [--channel n] [--bssid mac]`
- `bssid-scan [intf] [seconds]`
- `fingerprint <ip> [--fast]`
- `traceroute [target]`
- `help`
- `exit` / `quit`

## Dependencies

Required for core features:
- `bash`
- `sudo`
- `iproute2` (`ip`)
- `jq`
- `awk`, `sed`, `grep`, `sort`, `column`, `xargs`, `timeout`
- `curl`
- `nmap`
- `ss`
- `nmcli`
- `iw`
- `tcpdump`
- `tshark`
- `mtr`
- `whois`
- `dig` (from `dnsutils`)

Optional/conditional:
- `avahi-resolve` (only used when `scan --resolve-hostnames` is set)
- `/usr/share/nmap/nmap-mac-prefixes` (preferred local vendor DB source)

## Data Files

### MAC/IP Mapping Cache
- Default path: `~/.local/share/netmgr/mac_ip_map.tsv`
- Override with: `NETMGR_MAC_IP_DB`
- Format: `mac<TAB>ip` (lowercase MAC)

How it is maintained:
- Every `scan` run updates this file.
- If a MAC is new: add a new row.
- If a MAC exists: update the stored IP to the latest observed value.

Where it is used:
- `listen` (managed + monitor) reads IPs from this file for the `IP` column.

### Vendor Prefix Database
- Default path: `/usr/share/nmap/nmap-mac-prefixes`
- Override with: `NETMGR_MAC_PREFIX_DB`
- Fallback: `https://api.macvendors.com/<mac>` when local DB has no match.

## Command Behavior

### `interfaces`
Shows a table with:
- Interface
- Status
- IPv4/CIDR
- MAC
- MTU
- DHCP (Yes/No/N/A)
- Gateway

### `scan [intf] [target] [--ports] [--resolve-hostnames]`
Host discovery and optional enrichment.

Input behavior:
- `intf` optional.
- `target` optional (CIDR/IP range).
- If no interface is provided and a target is provided, route lookup chooses the best interface for that target.
- If neither is provided, first active interface is selected.

Primary discovery command:
```bash
sudo nmap -sn -PS22,80,443 -PA21,23,3389 -PU40125 --max-retries 5 --stats-every 10s -e <interface> <target>
```

Optional port enrichment (`--ports`):
1. Collect discovered host IPs.
2. Run:
```bash
sudo nmap -Pn --top-ports 200 -sS -n --min-parallelism 64 -iL - -oG -
```
3. Parse open ports into `Ports` column.

Optional hostname enrichment (`--resolve-hostnames`):
- Runs `avahi-resolve -a <ip>` with `300ms` timeout in parallel.
- Concurrency controlled by `AVAHI_JOBS` (default `16`).

Output columns:
- `IP_Address`
- `Hostname/Identity`
- `MAC_Address`
- `Manufacturer`
- `Ports`

Pipeline order:
1. Nmap host discovery
2. Parse report into rows
3. Optional top-ports scan merge
4. MAC→IP DB upsert
5. Optional Avahi hostname resolution
6. Final table output

### `ports`
Runs:
```bash
sudo ss -tulpn | column -t
```

### `bssid-scan [intf] [seconds]`
Managed-mode Wi-Fi scan summary via `nmcli`.

Defaults:
- Interface: `wlp8s0`
- Duration: `12` seconds

Output columns:
- `BSSID`
- `SSID`
- `Channel`
- `Band` (`2.4GHz` or `5GHz`)
- `Signal_pct`
- `Seen` (number of observations during scan window)

### `listen [intf] [managed|monitor] [bssid] [--channel n] [--bssid mac]`
Live listener with two modes.

Defaults:
- Interface: `wlp8s0`
- Mode: `managed`

#### Managed mode
Captures local ARP and IoT-related UDP broadcast traffic:
- DHCP (67)
- SSDP (1900)
- WS-Discovery (3702)
- mDNS (5353)
- UniFi (10001)
- Sonos (15600)
- LIFX (56700)
- Spotify Connect (57621)

Prints unique MACs seen:
- Time
- MAC
- IP (from MAC/IP DB)
- Vendor

#### Monitor mode
Monitor pipeline:
1. Validate/normalize BSSID args (if provided)
2. Resolve channel from `--channel`, BSSID lookup, current Wi-Fi channel, or fall back to hopping
3. Preflight cleanup of stale `mon0` and hotspot profiles (`Netmgr_Awake`/`netmgr_dummy`)
4. Create `mon0` monitor interface on the interface PHY
5. Disconnect managed interface
6. Optional MediaTek wakeup sequence via temporary hotspot lock on target channel
7. Optional channel hopping if no fixed channel resolved
8. Capture frames with `tshark` and print unique MACs per `BSSID|MAC`
9. On exit, cleanup and reconnect managed Wi-Fi

Monitor output columns:
- Time
- BSSID
- SSID
- CH
- MAC
- IP (from MAC/IP DB)
- Vendor

Notes:
- IPs in `listen` are cache-based (from `scan` DB), not decrypted from monitor traffic.
- Ctrl+C triggers cleanup and reconnection logic.

Environment flags affecting listen:
- `NETMGR_AIRMON_KILL=1` enables `airmon-ng check kill` pre-step.

### `fingerprint <ip> [--fast]`
Aggressive service fingerprinting.

Default:
```bash
sudo nmap -A -p- -T4 <ip>
```

Fast mode:
```bash
sudo nmap -A --top-ports 100 -T4 <ip>
```

### `traceroute [target]`
Deep path inspection.

Behavior:
- Default target: `8.8.8.8`
- If hostname is passed, resolve to IP first (`getent`)
- Runs `mtr -r -c 3 -n`
- Enriches hops with ASN/netname/location using `ipinfo.io` + Team Cymru whois
- If target is `8.8.8.8`, attempts Google edge-node identification via DNS TXT query

Output columns:
- `Hop`
- `IP_Address` (with local/private prefix handling)
- `Latency`
- `Netname`
- `ASN`
- `Location`

## Usage

### Single Command Mode
```bash
./netmgr interfaces
./netmgr scan wlp8s0 192.168.1.0/24
./netmgr scan wlp8s0 192.168.1.0/24 --ports
./netmgr scan 192.168.1.0/24 --resolve-hostnames
./netmgr listen wlp8s0 managed
./netmgr listen wlp8s0 monitor --bssid D4:86:60:6B:80:89 --channel 6
./netmgr bssid-scan wlp8s0 15
./netmgr fingerprint 192.168.1.254 --fast
./netmgr traceroute www.google.com
```

### Interactive Mode
```bash
./netmgr
NETMGR> interfaces
NETMGR> scan wlp8s0 192.168.1.0/24 --ports
NETMGR> listen monitor --channel 6
NETMGR> exit
```

## Inputs and Outputs Summary

Inputs:
- CLI args/flags per command
- Local system interfaces/routes
- Local Wi-Fi scan state via `nmcli`
- Packet capture via `tcpdump`/`tshark`
- External metadata APIs for vendor/trace enrichment

Outputs:
- Tabular terminal reports
- Live event lines for `listen`
- Persistent MAC/IP mapping file at `~/.local/share/netmgr/mac_ip_map.tsv`

## Author
Created by Terrydaktal.
