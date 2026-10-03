# netmgr

Bash network toolkit with interactive shell support (`NETMGR>`) and standard-library Python helpers for device discovery and process details.

## Project Structure
```text
/home/lewis/Dev/netmgr
├── netmgr                  # CLI, Wi-Fi tools, listeners, socket listing and traceroute
├── lib/
│   ├── discovery.py        # scan: IP scope, Nmap XML, passive discovery, identity/cache merging
│   ├── ports.py            # sockets: process metadata, systemd descriptions, container identification
│   └── sockets_tui.py      # sockets: timed snapshots, terminal layout, scrolling/filtering/row details
├── tests/
│   ├── test_discovery.py   # Synthetic packet/XML fixtures and mocked worker lifecycle
│   ├── test_ports.py       # Synthetic proc files and mocked service/container lookups
│   ├── test_sockets_tui.py # Synthetic terminal, resize, input and collector lifecycle fixtures
│   ├── test_socket_mouse_terminal.py # Native curses mouse decoding in an isolated PTY, with fake rows
│   ├── helpers.sh          # Offline MAC, CIDR, cache and Wi-Fi connection regression tests
│   └── ports.sh            # Offline socket/conntrack fixtures
└── README.md               # Usage and implementation notes
```

## Commands

`netmgr` supports direct command mode and interactive mode.

Implemented commands:
- `interfaces`
- `scan [intf] [target] [--once|--duration seconds] [--ports|--services] [--no-resolve-hostnames]`
- `sockets [--once] [--brief|--verbose|--all-details]` (compatibility alias: `ports`)
- `listen [intf] [managed|monitor] [--channel n] [--bssid mac] [--dedupe]`
- `bssid-scan [intf] [seconds]`
- `fingerprint <ip> [--fast]`
- `traceroute [intf] [target]`
- `help`
- `exit` / `quit`

## Dependencies

Core tools used by the script:
- `bash` 5 or newer, `sudo`
- `python3` 3.11 or newer for `scan` and socket process details, with the standard-library `curses` module for live sockets; no third-party Python packages or virtual environment required
- `ip`, `jq`, `awk`, `sed`, `grep`, `sort`, `column`, `xargs`, `timeout`
- `curl`, `nmap`, `ss`, `nmcli`, `tcpdump`, `tshark`, `mtr`, `whois`, `dig`

Optional/fallback:
- `iw` (used by `interfaces` and monitor mode)
- `/usr/share/nmap/nmap-mac-prefixes` (local MAC vendor DB)
- `systemctl`, `podman`, `docker` (optional service descriptions and container details for `sockets`)

## Data Files and Environment

### MAC/IP cache
- Path: `~/.local/share/netmgr/mac_ip_map.tsv`
- Override: `NETMGR_MAC_IP_DB`
- Format: `mac<TAB>ip<TAB>last_seen_epoch_seconds` (lowercase MAC)

Behavior:
- `scan` checkpoints accumulated observations at most every 15 seconds and on exit, not for every packet.
- Writes merge under a lock and replace the file atomically with mode `0600`. Invalid, expired, and superseded IP/MAC associations are removed.
- Cached neighbour records, name lookups and all-filtered port scans do not refresh evidence of presence.
- `listen` uses fresh hints when a packet has no usable IP, explicitly labelled `(cached)`; it reloads at most every 30 seconds.
- Default retention is 24 hours. `NETMGR_MAC_IP_TTL` controls how long `listen` trusts a hint, in seconds.
- Old two-column records have no age and are not trusted. A subsequent scan replaces them with timestamped observations.
- Hints are historical, not proof of current membership. They are not network-scoped and a device can roam; use packet/active evidence to confirm an address.

### MAC vendor DB
- Default local DB: `/usr/share/nmap/nmap-mac-prefixes`
- Override: `NETMGR_MAC_PREFIX_DB`
- Prefixes are loaded once, rather than running a lookup process per packet.
- Zero/multicast MACs are rejected. Locally administered addresses are labelled `Private/randomized MAC`, not attributed to a hardware manufacturer.
- Discovery uses local data only. `listen` can opt into the external fallback with `NETMGR_VENDOR_ONLINE=1`; this discloses queried MACs to `api.macvendors.com` and is disabled by default.

### Other env knobs
- `NETMGR_SCAN_NMAP_DELAY` (seconds between completed discovery sweeps, default `1`; also `scan --delay`)
- `AVAHI_JOBS` (legacy name for hostname-lookup concurrency, default `8`; also `scan --jobs`, maximum `32`)
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

### `scan [intf] [target] [options]`
Continuous discovery by default. Existing interface, route and neighbour information appears immediately; Nmap and optional Tshark workers add observations concurrently.

Interface/target resolution:
- If `intf` omitted and `target` provided, route lookup picks the interface for that target.
- If both omitted, the lowest-metric default-route interface is preferred, with an UP-interface fallback.
- Target defaults to the interface's actual IPv4 subnet; private-address masks are never guessed.
- Explicit targets accept an IP, CIDR, or IPv4 range (`192.168.1.20-40` or full endpoints). Range bounds are not widened.
- IPv6 neighbour/passive observations are included for the default LAN scan. Explicit IPv6 targets are supported, with a maximum of 4096 target addresses; a `/64` is not swept.
- IPv4 targets over 65536 addresses require an explicit target and `--allow-large`, preventing accidental enormous scans.

Discovery pipeline, in execution order:
1. Validate arguments and read interface/routing/neighbor metadata with `ip -j`.
2. Authenticate once, then print local addresses, the gateway and valid cached neighbours. `NEIGH-CACHED`/`ROUTE` are not fresh reachability results.
3. Run `nmap -sn -n` in bounded address batches (default 64, configurable with `--batch-size`). Parse completed XML host records incrementally, including hosts without a MAC. Nmap handles local ARP/ND discovery and routed-host probes; every fourth continuous sweep uses gentler timing and an extra retry.
4. In parallel, capture ARP, IPv6 control traffic, DHCP, mDNS and LLMNR announcements. Parse sender evidence, never unanswered ARP targets or arbitrary destination IPs as devices.
5. Merge by IP and print new or enriched records. A changed MAC clears the previous identity/port data. Do local vendor lookup in memory and resolve names by default in a bounded worker pool without blocking discovery.
6. With `--ports` or `--services`, probe discovered hosts concurrently with discovery and hostname lookups, with at most four host probes active. `--services` first makes a short independent IPv4 NetBIOS name query, even if no TCP ports are open. Scan the top 200 TCP ports and display those results; then, for `--services`, identify only the open ports. Slow version detection cannot discard the earlier port results; NetBIOS failures do not prevent TCP probes.
7. On normal completion, finish requested probes, print an IP-sorted final table and atomically checkpoint the cache. On Ctrl+C, cancel active probes, preserve completed results and do not start further probes.

Identification and accuracy:
- Passive name learning uses DHCP acknowledgements/client announcements and matching mDNS/LLMNR A/AAAA records, including multi-record responses.
- Names are unauthenticated hints, not verified device identities. DNS queries and names for unrelated advertised IPs are not used as the sender's identity.
- `--services` displays service names/products/versions, service-reported hostnames, OS and device-type hints. Targeted `smb-os-discovery` and `rdp-ntlm-info` queries can add computer names, workgroups/domains, an SMB-reported OS or an RDP build when those services respond. An open port alone is not classified as Windows. These are identification probes, not vulnerability scans or password guessing.
- IPv4 NetBIOS node-status queries (`nbstat`, UDP 137) run independently of TCP/SMB availability. A returned computer name can fill `Hostname/Identity`; a self-reported MAC is shown only as an identity hint, never an observed MAC/vendor mapping. Empty or failed queries do not count as fresh evidence. Legacy NetBIOS queries are skipped for IPv6.
- `http-title` and `ssl-cert` add port-labelled page titles, certificate subject common names and DNS/IP subject alternative names. These remain `Identity hints`, not canonical hostnames: a certificate or web page may describe a virtual service rather than the device. Up to eight SAN entries per certificate are considered, with at most 16 identity hints retained per device.
- An Ethernet MAC for an off-link IP is a next hop, not that remote device's MAC. Routed hosts remain visible with an unknown MAC; known gateway MACs are not attached to other IPs.
- Failed/incomplete neighbours, broadcast/multicast/zero MACs and out-of-scope packet addresses are excluded.
- Multiple IPs can belong to one device; proxy ARP can also produce shared MACs. Address count is not physical-device count.

Live output columns:
- `Time`, `Evidence`, `IP_Address`, `MAC_Address`, `Hostname`, `Vendor`
- `--ports` adds `Ports/Services` and per-host scan status; `--services` also adds `Identity hints`. New port and identity results appear immediately, without waiting for the final table. Queued, scanning, identifying, interrupted and incomplete states are explicit. A progress line appears every five seconds while probes remain active.
- Evidence includes `SELF`, `NEIGH-CACHED`, `ROUTE`, `NMAP`, `ARP`, `PACKET`, `DHCP`, `mDNS`, `LLMNR`, `NAME`, `NETBIOS`, `PORTS`, and `SERVICES`.

Run controls:
- `--once`: one discovery sweep; wait for requested background probes, then print a final table.
- `--duration 30`: discover for 30 seconds while requested probes run concurrently. Authentication/setup and finishing pending probes are outside that duration.
- `--ports`: top 200 TCP ports on discovered addresses, with up to four concurrent host probes and a 30-second per-host port-scan timeout. Defaults to one discovery sweep unless `--duration` is supplied.
- `--services`: first query IPv4 NetBIOS names with a four-second script timeout and six-second host timeout. Also perform light service/version detection and SMB/RDP, HTTP-title and TLS-certificate queries on open ports, with a separate 60-second per-host timeout and eight-second script timeouts. HTTP response bodies are capped at 64 KiB; a title beyond that limit may be missed. More active traffic and time than discovery alone; shares the same finite-run default as `--ports`.
- Hostname resolution is enabled by default: parallel `getent hosts` lookups with one-second per-query timeouts and a bounded final wait. Results depend on the system's DNS/mDNS/NSS configuration.
- `--no-resolve-hostnames`: disable active hostname lookups; passive name learning remains enabled. The existing `--resolve-hostnames` flag is still accepted to explicitly enable lookups.
- `--no-passive`: omit Tshark, retaining active and cached-neighbour discovery.
- `scan --help`: all options, limits and controls.

The final table includes `IP_Address`, `Hostname/Identity`, `MAC_Address`, `Manufacturer`, `Ports/Services`, and `Evidence`, plus `Identity hints` with `--services`. It distinguishes pending/unscanned hosts, no open ports found in the tested set, closed/filtered port counts, timeouts and probe failures. Missing or timed-out XML port results are not reported as a successful scan with no open ports. A failed service probe never removes earlier port results or discovered hosts. Worker failures are visible instead of silently leaving a stale stream. Exit status is `0` for normal completion, `1` for failed active discovery/setup, and `130` on interruption; passive or enrichment failures warn or show incomplete status but preserve the active scan results.

Sleeping devices and hotspot/client isolation can prevent responses. This tool cannot bypass isolation, infer a manufacturer's identity from a randomized MAC, or guarantee discovery of every connected device.

Implementation references: [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html), [Nmap host discovery](https://nmap.org/book/man-host-discovery.html), [NetBIOS names](https://nmap.org/nsedoc/scripts/nbstat.html), [SMB identity](https://nmap.org/nsedoc/scripts/smb-os-discovery.html), [RDP identity](https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html), [HTTP titles](https://nmap.org/nsedoc/scripts/http-title.html), [TLS certificates](https://nmap.org/nsedoc/scripts/ssl-cert.html), and [Wireshark DNS fields](https://www.wireshark.org/docs/dfref/d/dns.html).

### `sockets [--once] [--brief|--verbose|--all-details]`
`ports` remains a compatibility alias with identical options and output,
in both direct and interactive mode.

On an interactive terminal this opens a full-screen, read-only monitor with
one-second refreshes. `--once` prints the previous one-shot table. Redirected
output, non-interactive input and `TERM=dumb` also select one-shot mode, so
pipes and scripts do not receive a stream of ANSI refreshes.

The live view retains connected TCP and UDP rows for 60 seconds after they
disappear. `CLOSED` means `ss -E` reported socket destruction; `GONE*` means
a successful snapshot no longer contained the socket, which does not prove
why it disappeared. Recent rows are dimmed; their `Age` counts seconds since
the monitor read the destruction event (`CLOSED`) or completed the first
successful absent snapshot (`GONE*`). Neither is an exact disconnect time.
The table keeps `Age` after `Uploaded`, before the process columns, for both
live and recently closed sockets. Recent
rows retain the last useful process details, origin and transfer totals across
sparse snapshots; missing fields no longer erase earlier observations. A
snapshot that started before a close event but finishes afterwards can enrich
the closed row without resetting its age or reducing its known byte totals.
Cached detail columns remain accessible even if metadata collection falls back
to a basic table. Live rows and their queues still show the actual snapshot;
retained details are historical, not a new measurement. `Process age` preserves
the last known process uptime when available.

This cache uses the existing one-second snapshots and adds no system queries.
It retains only currently observed connections plus the existing recent history.
An observed absence/closure, changed owner, restarted TCP state or falling TCP
byte counter prevents old cached details from carrying into a new connection.
Matching uses protocol and local/peer endpoints; reuse entirely between samples
without a distinguishing event or field cannot be reliably identified.
Event-only rows can still have unknown process and origin details if these were
never sampled. Listeners and unconnected UDP bindings are excluded from recent
connection history. The table keeps at most 512 recent rows and discards them
after 60 seconds. `--once` has no history.

Live controls:
- Up/Down or `j`/`k`: select a socket one row at a time; PgUp/PgDn/Home/End navigate larger tables.
- Mouse wheel: scroll five rows per notch, moving the viewport immediately. Also works in row details and help. Terminals without mouse reporting retain keyboard navigation.
- Click a column header to sort descending; click it again to sort ascending, then keep clicking to alternate. Clicking a different header starts descending again. `r` also reverses the selected key. Age, Downloaded and Uploaded sort globally; other columns stay within fixed `State[1]` and `Origin[2]` groups. The selected header shows `^` (ascending) or `v` (descending).
- Click State to restore the startup ordering: State, Origin, protocol, local address, then local port. This clears the selected sort column and direction, like F6 > Default; repeated State clicks keep that default order.
- Global sorts use the selected column first, then State and Origin for ties, marked `State[2]` and `Origin[3]`. Missing values stay last in either direction. Selecting a grouped column restores State/Origin-first ordering.
- Header clicks accept left-button press, click or release reports; a press/release pair sorts only once. Mouse setup/decoding failures appear above the table rather than being silently ignored; no terminal preferences are changed.
- F6: choose any sort column, including hidden columns; Enter applies and Esc cancels. Choose Default to restore protocol, local address, then local port ordering within each group. Sorting uses full values, numeric addresses/ports/counts and process-age durations; missing values stay last in either direction. Equal values retain the default tie order.
- `/` or F3: type a case-insensitive, literal search across all column values, including hidden columns and text clipped from the table. Results filter as you type (for example, `inbound` matches the `INBOUND*` origin). Enter applies and keeps the search visible; Esc cancels or clears it. Ctrl+U clears the search input.
- Space: freeze/resume the display; background collection continues with only the newest result retained.
- Enter: inspect the selected row, frozen while viewing; arrows scroll fields and long text without wrapping. Enter/Esc returns to the table.
- `?`: show controls and field meanings; `q`, F10 or Ctrl+C exits and restores the terminal.

The bottom bar separates actions from navigation, with bracketed key names
and plain-English labels. Search and row-details views show their own
controls; Pause changes to Resume while frozen. The bar fits the terminal
without wrapping and reserves space above it for the table.

The renderer fits both terminal width and height. Columns shrink or hide on
narrow screens and expand up to their full contents on wider screens, with
no fixed App/CWD width cap in the live view. Hidden-column counts are shown;
the selected-row view includes all collected fields. CWD clipping retains
the directory suffix; clipped endpoints retain the port. Row selection is
preserved across refreshes where the socket can still be matched.

Collection pipeline:
1. Authenticate once before entering the terminal UI.
2. A background worker calls the existing `socket_snapshot` helper, reading `ss` and conntrack and collecting process metadata in a batch. It produces sorted, untruncated TSV instead of a preformatted screen.
3. A separate `sudo -n ss -E -H -a -t -u -n -p -i -O` process streams TCP/UDP socket destruction events. It starts with the live view, retries after an error and reports its status above the table. The bounded event queue also covers connections that open and close between snapshots.
4. The curses UI combines complete snapshots with destruction events, retains recent rows, fits columns and draws one screen update. Keyboard handling and terminal resizing do not wait for collection.
5. Schedule snapshots on a one-second cadence. Slow collectors never overlap; the snapshot age remains visible. A 15-second collection timeout or command error retains the last good table with a `STALE` warning and never infers closure from a failed snapshot.
6. On exit, stop both process groups and restore terminal settings. No packet capture, connection-tracking rules or active network probes are started.

Lists TCP and UDP sockets using `sudo -n ss -tuanp -i -O`, grouped first by state
(`ESTAB`, `LISTEN`, etc.), then by origin (`OUTBOUND*`, `SAME-HOST*`, `INBOUND*`,
`UNKNOWN`; `-` when no attribution applies). Within each state/origin group,
rows are sorted by protocol, local address, then numeric local port by default.
Live header/F6 sorting normally replaces this with a selected third key, without
changing either state or origin group order, including when sorting descending.
Age, Downloaded and Uploaded are exceptions: they are global primary sort keys,
followed by State and Origin for ties. Reversing the selected key does not
reverse those tie-breakers.
UDP sockets with a nonzero local port and no fixed peer display `BOUND`
instead of the kernel/`ss` label `UNCONN`. This can describe either a UDP
client or server, not a TCP-style listener. It is a display alias only;
grouping and origin matching still use the original state. Connected UDP
sockets and TCP states are unchanged.

The default table has 12 compact columns: `State`, `Net`, `Origin`, `Local`,
`Peer`, `Downloaded`, `Uploaded`, `Age`, `PID`, `User`, `App`, and `CWD`.
`Recv` and `Send` queues are hidden by default to leave more room for process
details. They remain available in `--verbose`, `--all-details`, and the live
view's Enter details. Totals and queue values are right-aligned.

`Downloaded` is TCP's cumulative `bytes_received`; `Uploaded` is cumulative
`bytes_acked` (data acknowledged by the peer, not queued or retransmitted bytes).
These are connection-lifetime counters, including traffic before netmgr started,
not per-refresh changes or exact downloaded-file sizes. Totals use binary units
such as `1.0MiB`; Enter in the live view shows exact bytes, as does `--all-details`
in the one-shot view. Machine snapshots preserve the decimal byte counts exactly,
and sorting uses those counts rather than rounded display units. Search accepts
both raw byte counts and the displayed units. Sorting by either total ranks all
states and origins globally; rows without a total remain last.

The existing `ss` call requests TCP information on one line per socket; no extra
capture, tracking rules or flow-accounting settings are added. UDP (including
QUIC), listeners, TIME-WAIT and sockets without reported counters show `-`.
`ss` suppresses zero counters: when one of the received/acknowledged pair is
reported, its omitted counterpart is zero; if neither is reported, netmgr keeps
`-` rather than guessing. Recent rows preserve the last available counters,
and `ss -E` can supply counters for a connection missed by polling when the
kernel includes them in its event. `Recv`/`Send` are unchanged queue
values, not transfer totals or rates.

`User` is the owning process's effective account name, falling
back to its numeric effective UID if account lookup fails. For live rows,
`Age` is how long the process has been running, not the connection age, shown
as `45s`, `12m08s`, `2h15m`, or `3d04h`. For recent `CLOSED` and `GONE*`
rows in the live view, `Age` instead counts from the observed close event or
first detected absence; the previous process uptime is retained in `Process age`.
Unavailable process ages are `-`, not zero. One-shot mode keeps process age
in `Age` and does not include recent rows.
`App` shows the current process followed by its parent processes, for example
`python3.14<-fish<-xfce4-terminal<-systemd`. Names use executable basenames,
falling back to process names when the executable is inaccessible. This is
current ancestry, not a historical record of launches or `exec` calls; a
reparented process cannot reveal its original launcher. `CWD`, immediately
after `App`, is the process's working directory, not a project or service label.

In the one-shot default view, `App` and `CWD` are capped at 112 and 64 characters,
respectively. `...` marks display clipping; long CWD paths retain their directory suffix. These columns
shrink further to fit the terminal where possible, targeting at most 268
columns. Addresses, ports, states, origins, queue values, and PIDs are never
truncated, nor are user names or ages, so narrow terminals may still wrap.
The old raw `Process` and `Context` columns and separate detail blocks are absent.
When output is a terminal, `LISTEN` rows bound to all interfaces (`0.0.0.0` or
`[::]`) are highlighted in bold yellow. Rows with origin `INBOUND*` are bold
cyan in both live and one-shot terminal views. Selection keeps the row colour;
set `NO_COLOR` to disable colours. Redirected output contains no ANSI colour codes.

Process information appears directly in the table for listeners, bound UDP
sockets, and established connections. IPv4/IPv6 bindings keep their own rows.
Shared sockets list PIDs separated by semicolons and their values in the same
order across columns, separated by ` | ` (subject to compact display limits).
Missing values use `-`. An incomplete parent chain ends in `<-?`, with the
reason available in the detailed `Metadata` column. Missing or changed process
metadata is also explained there. Available information includes:

- PID, effective user, process age, real/effective UIDs, executable path, full command arguments, and working directory.
- The owning systemd service or scope, with its configured description.
- Python runtime and script/module, including recognition of `python -m http.server`.
- Node.js/Next.js identity, an observed Next.js version, and project name/description from `package.json` or `pyproject.toml`.
- Podman/Docker container name, ID, image, and matching host-to-container port mappings.

`--verbose` (or `-v`) adds `Recv`/`Send` after `Age` and `Command` after `CWD`.
Live mode still fits the screen;
the selected-row view exposes the full collected value. With `--once` (or
redirected output), verbose removes column-width clipping:
parent chains, working directories and command arguments are no longer cut off
to fit the terminal or the default 268-column limit. Commands still use
executable/script basenames and abbreviate other file paths. Long rows may wrap
on narrow terminals. This keeps the same small set of columns rather than adding
all the metadata from `--all-details`. Commands are not shown by default.

`--brief` omits process enrichment and shows the socket columns followed by
`PID` and the short executable name in `App` from the socket snapshot, without
user/age lookups, parent traversal or CWD. It cannot be combined with the other
detail flags.
`--all-details` collects the full table; live mode fits/hides columns and Enter
shows every collected field. One-shot mode has no display clipping of parent chains,
commands or paths: socket columns followed by `PID`, `User`, `Age`, `UID`,
`EUID`, `Executable`, `App`, `CWD`, `Service`, `Runtime`, `Application`,
`Script/Module`, `Project`, `Container`, `Image`, `Forwarding`, `Metadata`,
`Command`, and `Description`.

The details helper consumes the same `ss` snapshot as the table. It reads
each socket-owning PID once in a single batch using the existing sudo
authorization and checks process start times, parent PIDs and socket
descriptors during collection. Ancestor metadata is cached within the batch,
so shared parents are not repeatedly read. Parent walks reject detected PID
reuse or changes and stop on missing metadata, cycles or a 64-process limit.
They read proc files without starting another monitor or running `ps` per row.
Age uses one uptime read per batch and the system's clock-tick rate to convert
process start times. Account names are resolved once per distinct effective
UID per listing; `UID` in the full table remains the real UID and `EUID` is
the effective UID used for `User`.
Systemd description queries are grouped by manager in `--all-details` mode.
Only that mode queries container inventories, once per needed
engine/owner context, using local Podman and Docker endpoints. Rootless Podman
lookups run as the invoking user, since root has a separate container store.
Root-owned containers are queried in the privileged batch. Containers belonging
to other users may remain unresolved.

Container IDs from process cgroups take precedence. For recognized forwarding
processes such as `rootlessport`, a unique match on owner, protocol, local
address, and published port is labelled `published-port match`. Ambiguous
matches remain unresolved. Descriptions come from systemd, project metadata,
or a recognized command; the tool cannot infer a custom script's purpose from
its name alone. Metadata lookup failures and processes that exit are reported
without removing the socket table. Command lookups have timeouts and share a
12-second budget. Missing Python leaves the basic one-shot table available;
the live view requires Python with curses.

Process commands can contain credentials supplied as arguments. Details are
printed locally and are not cached or sent to an external service. Project
metadata is read as data; scripts and application executables are not run.
Socket and metadata collection are separate snapshots, so rapid process or
descriptor reuse can still prevent reliable attribution.

Container format references: [Podman ps](https://docs.podman.io/en/latest/markdown/podman-ps.1.html)
and [Docker container ls](https://docs.docker.com/reference/cli/docker/container/ls/).

The `Origin` column joins a single read-only `/proc/net/nf_conntrack` snapshot
to each socket using its protocol and complete local/peer IP and port pairs:
- `OUTBOUND*`: inferred initiation by this machine; the socket matches conntrack's original direction.
- `INBOUND*`: inferred initiation by another machine; the socket matches conntrack's reply direction.
- `SAME-HOST*`: a matched connection has both endpoints on this machine.
- `UNKNOWN`: no unique usable match, including unavailable tracking data,
  conflicting entries/zones, or ambiguous scoped link-local addresses.
- `-`: a listener or socket without a connected peer; no connection to attribute.

The `*` labels are inferences, not verified initiators. TCP connections can
be picked up midstream, and UDP direction means first-observed traffic rather
than a TCP-style handshake. Even `[ASSURED]` does not prove the handshake was
observed. Obvious unreplied midstream TCP entries are left `UNKNOWN`.
Original and reply tuples are matched to account for NAT, and IPv4-mapped
IPv6 addresses are normalized. The socket and tracking snapshots are not
atomic, so connections changing during collection may have no match.

The existing sudo session reads the proc table. If the kernel does not expose
it or reading fails, a warning is printed and the socket list remains usable.
This does not enable tracking, change firewall settings, load modules, start
a monitor, or install a dependency. Origin attribution adds one table read and
an in-memory join when `sockets` runs. Process enrichment also reads the local
metadata described above. Only sockets
and conntrack entries in the current network namespace are inspected.

Run the unprivileged regression tests with `bash tests/ports.sh`.
Run the process-detail fixtures with
`UV_CACHE_DIR=/data/.cache/uv uv run --offline --no-project python -m unittest discover -s tests -p test_ports.py`.

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
- On Wi-Fi interfaces named `wl*`, `Ethernet` in the stack is relabeled to `Synthetic Eth`.
- Dedupe occurs before vendor/protocol work, without a one-second sleep per host.
- IPs not established as on-link are labelled as source traffic whose MAC may be the next hop.
- Vendor output is truncated to 31 chars for table alignment.
- Uses `[OK]`/`[ERR]` status labels.

#### Monitor mode
- Requires sudo-capable flow.
- Builds/uses monitor interface `mon0`.
- Cleans stale monitor and dummy hotspot resources (`mon0`, `Netmgr_Awake`, `netmgr_dummy`) before start.
- Optional `--bssid` filter and `--channel` lock.
- If `--bssid` is supplied without channel, attempts to discover the channel via `nmcli` then `iw` scan fallback.
- If no fixed channel can be resolved, hops by supported frequency, avoiding ambiguous channel numbers across bands.
- Counts observed source/transmitter MACs, not arbitrary unicast destinations; zero/multicast addresses are excluded.

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
- Failed restoration no longer restarts NetworkManager globally, avoiding disruption to unrelated interfaces.

### `bssid-scan [intf] [seconds]`
Managed-mode Wi-Fi survey using `nmcli`.

Defaults:
- Interface: `wlp8s0`
- Duration: `12` seconds

Output columns:
- `BSSID`, `SSID`, `Channel`, `Freq_MHz`, `Band` (`2.4GHz`/`5GHz`/`6GHz`), `Signal_pct`, `Seen`

The existing interactive connection action remains available. Password input preserves backslashes, connection failures return a failing status, and the connection helper uses the authenticated privilege path when invoked over SSH. Active-scan fallback profiles use unique UUIDs with autoconnect disabled; a failed fallback deletes only the profile it just created, never a pre-existing profile with the same SSID/name.

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
- Uses the installed `dublin-traceroute` flow, writes the merged hop list to a unique temporary file, then samples each hop. Concurrent runs cannot overwrite a shared `/tmp/route-hops.txt`.
- Enriches hops with ASN/netname/location via `ipinfo.io` + Team Cymru whois.
- Enrichment calls have timeouts; local CIDRs use actual configured prefixes, and range-derived prefixes account for boundaries rather than just range size.

Output columns:
- `Hop`, `IP_Address`, `Loss`, `Avg`, `Lowest`, `Netname`, `ASN`, `Location`

## Usage

### Direct mode
```bash
./netmgr interfaces
./netmgr sockets
./netmgr sockets --verbose
./netmgr sockets --all-details
./netmgr sockets --once
./netmgr scan wlp8s0 192.168.1.0/24
./netmgr scan wlp8s0 192.168.1.0/24 --once --ports
./netmgr scan wlp8s0 --duration 30 --services
./netmgr scan wlp8s0 --no-resolve-hostnames
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
NETMGR> sockets
NETMGR> scan wlp8s0 192.168.1.0/24 --once --ports
NETMGR> listen wlp8s0 monitor --bssid D4:86:60:6B:80:89 --channel 6
NETMGR> traceroute enp9s0 www.google.com
NETMGR> exit
```

## Offline Validation

These tests use synthetic packets/XML, mocked command execution and static analysis. They do not scan, capture traffic, connect to Wi-Fi or require privileges.

```bash
UV_CACHE_DIR=/data/.cache/uv uv run --no-project --offline --python /usr/bin/python3 python -m unittest discover -s tests -p 'test_*.py' -v
bash tests/helpers.sh
bash tests/ports.sh
shellcheck -x netmgr tests/helpers.sh tests/ports.sh
shfmt -d -i 4 -ci -sr netmgr tests/helpers.sh tests/ports.sh
```

The unit fixtures forbid real subprocess creation, socket creation/DNS and process signalling. Command/lifecycle tests explicitly substitute fake implementations. The live socket tests use a fake terminal to check bounded drawing, Unicode cell widths, resizing, selection, filtering, one-second scheduling and cancellation without inspecting live sockets. The native mouse regression additionally launches an isolated curses process in a private PTY and injects terminal mouse sequences; its collector uses only synthetic rows and real collection/network calls are blocked. Hardware/driver behaviour and actual network discovery performance still require separate live validation; none is performed by this suite.

Keep the `lib/` directory beside the repository script. If exposing the command in `~/.local/bin`, symlink `netmgr` rather than copying it so its helpers remain locatable.

## Author
Terrydaktal
