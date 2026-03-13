# netmgr

A high-performance, interactive network management and discovery tool designed to provide deep visibility into local and external network paths.

## Project Structure
```
/home/lewis/Dev/netmgr/
└── netmgr          # The primary interactive shell and execution script
```

## Features

### 1. Interactive Shell
Run `./netmgr` to enter a persistent, `diskpart`-style environment where you can execute multiple commands without restarting the script.

### 2. Network Interfaces (`interfaces`)
Lists all local network interfaces with their current status, IP addresses, MAC addresses, MTU, and system flags in an easy-to-read table.

### 3. Network Scanning (`scan [subnet]`)
A multi-layered discovery engine that runs the following tools in parallel:
- **Nmap (SYN Scan):** Fast port discovery and DNS hostname resolution.
- **ARP-Scan:** Retrieves Layer 2 MAC addresses and hardware manufacturer data (Local Subnet only).
- **NBTscan:** Discovers NetBIOS names for Windows and Samba-enabled devices.
- **Identity Merging:** Intelligently merges names from all three sources into a single "best-guess" identity.
- **Self-Awareness:** Automatically identifies and labels your own computer in the scan results.

### 3. Deep Traceroute (`traceroute [target]`)
Provides a highly detailed analysis of the path to any IP or hostname (defaults to 8.8.8.8):
- **Latency Counters:** Shows real-time RTT (Round Trip Time) for every hop.
- **Geolocation & ASN:** Uses `ipinfo.io` to provide city, country, postal code, and Autonomous System details.
- **CIDR Resolution:** Integrates Team Cymru WHOIS to provide precise BGP prefixes for each hop.
- **Google Edge Node Discovery:** When tracing to 8.8.8.8, it automatically identifies and pings the specific physical server responding to your request.
- **Private IP Handling:** Dynamically detects local CIDR suffixes for internal hops without performing unnecessary external lookups.

### 4. Port Analysis (`ports`)
Quickly lists all active listening TCP and UDP ports on your local machine using `ss`, presented in a clean, tabular format.

## Dependencies
- `nmap`
- `arp-scan`
- `nbtscan`
- `mtr`
- `whois`
- `jq`
- `curl`
- `dig` (dnsutils)

## Usage

### Single Command Mode
```bash
./netmgr scan 192.168.1.0/24
./netmgr traceroute google.com
./netmgr ports
```

### Interactive Mode
```bash
./netmgr
NETMGR> scan
NETMGR> traceroute 1.1.1.1
NETMGR> exit
```

## Authors
Created by Terrydaktal with assistance from Gemini CLI.
