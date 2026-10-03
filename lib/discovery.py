"""Bounded, evidence-based discovery. Parsers and state are independent of I/O."""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import fcntl
import html
import ipaddress
import itertools
import json
import os
import queue
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path


def clean(value: str, limit: int = 120) -> str:
    return " ".join("".join(c if c.isprintable() else " " for c in value).split())[
        :limit
    ]


def address(value: str):
    try:
        result = ipaddress.ip_address(value.split("%", 1)[0])
        if (
            result.is_unspecified
            or result.is_multicast
            or str(result) == "255.255.255.255"
        ):
            return None
        return result
    except ValueError:
        return None


def mac_address(value: str) -> str | None:
    value = value.lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
        return None
    if value == "00:00:00:00:00:00" or int(value[:2], 16) & 1:
        return None
    return value


@dataclasses.dataclass(frozen=True)
class Targets:
    first: object
    last: object

    @classmethod
    def parse(cls, text: str):
        if "-" in text:
            start, end = text.split("-", 1)
            if "." not in end and ":" not in start:
                end = start.rsplit(".", 1)[0] + "." + end
            first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
        else:
            network = ipaddress.ip_network(text, strict=False)
            first, last = network.network_address, network.broadcast_address
            if network.version == 4 and network.num_addresses > 2:
                first, last = first + 1, last - 1
        if first.version != last.version or int(first) > int(last):
            raise ValueError("invalid target range")
        if first.is_multicast or last.is_multicast or first.is_unspecified:
            raise ValueError("target must be a unicast host or subnet")
        return cls(first, last)

    def contains(self, ip):
        return ip.version == self.first.version and int(self.first) <= int(ip) <= int(
            self.last
        )

    @property
    def count(self):
        return int(self.last) - int(self.first) + 1

    def __len__(self):
        return self.count

    def batches(self, size):
        values = (
            str(type(self.first)(i)) for i in range(int(self.first), int(self.last) + 1)
        )
        while batch := list(itertools.islice(values, size)):
            yield batch


@dataclasses.dataclass
class Context:
    interface: str
    targets: Targets
    networks: list
    own_addresses: set[str]
    own_mac: str | None
    neighbours: list
    gateways: set[str]
    include_ipv6_neighbours: bool = False

    def on_link(self, ip):
        return any(ip.version == net.version and ip in net for net in self.networks)

    def allows(self, ip):
        return self.targets.contains(ip) or (
            self.include_ipv6_neighbours and ip.version == 6 and self.on_link(ip)
        )

    def target_arg(self, value):
        ip = address(value)
        return (
            value + "%" + self.interface
            if ip and ip.version == 6 and ip.is_link_local
            else value
        )


@dataclasses.dataclass
class Observation:
    ip: str
    source: str
    mac: str | None = None
    name: str = ""
    name_rank: int = 0
    vendor: str = ""
    ports: tuple[str, ...] | None = None
    seen: float = dataclasses.field(default_factory=time.time)
    identity: tuple[str, ...] = ()
    port_summary: str = ""


def netbios_identity(script):
    name = ""
    for key in ("server_name", "workstation_name"):
        value = clean(script.findtext(f"elem[@key='{key}']", ""))
        if value and value.lower() not in {"unknown", "<unknown>"}:
            name = value
            break
    output = script.get("output", "")
    if not name:
        match = re.search(
            r"(?:^|[,\n])\s*NetBIOS name:\s*([^,\r\n]+)", output, re.IGNORECASE
        )
        if match and (value := clean(match[1])).lower() not in {"unknown", "<unknown>"}:
            name = value
    reported_mac = script.findtext("table[@key='mac']/elem[@key='address']", "")
    if not reported_mac:
        match = re.search(
            r"\bNetBIOS MAC:\s*([0-9a-f:]{17})(?=\s|$|,)", output, re.IGNORECASE
        )
        reported_mac = match[1] if match else ""
    reported_mac = mac_address(reported_mac)
    # This is self-reported identity, never an observed on-link MAC/vendor mapping.
    hints = (f"NetBIOS-reported MAC: {reported_mac}",) if reported_mac else ()
    return name, hints


def web_identity(port):
    hints = []
    endpoint = f"{port.get('portid', '?')}/{port.get('protocol', '?')}"
    for script in port.findall("script"):
        output = script.get("output", "")
        if script.get("id") == "http-title":
            title = script.findtext("elem[@key='title']")
            if title is None and not script.findall("*"):
                title = output.split("\n", 1)[0]
                if title.lower().startswith(
                    ("error", "did not follow redirect", "site doesn't have a title")
                ):
                    title = ""
            if title and (title := clean(html.unescape(title))):
                hints.append(f"HTTP {endpoint} title: {title}")
        elif script.get("id") == "ssl-cert":
            common_name = script.findtext(
                "table[@key='subject']/elem[@key='commonName']", ""
            )
            alternatives = []
            for extension in script.findall("table[@key='extensions']/table"):
                if (
                    extension.findtext("elem[@key='name']")
                    == "X509v3 Subject Alternative Name"
                ):
                    alternatives.append(extension.findtext("elem[@key='value']", ""))
            for line in output.splitlines():
                if not common_name and line.startswith("Subject:"):
                    match = re.search(r"(?:Subject:\s*|/)commonName=([^/\r\n]+)", line)
                    if match:
                        common_name = match[1]
                elif not alternatives and line.startswith("Subject Alternative Name:"):
                    alternatives.append(line.split(":", 1)[1])
            if common_name and (common_name := clean(common_name)):
                hints.append(f"TLS {endpoint} CN: {common_name}")
            for value in ",".join(alternatives).split(",")[:8]:
                value = clean(value)
                if value.startswith(("DNS:", "IP Address:")):
                    hints.append(f"TLS {endpoint} SAN: {value}")
    return hints


def service_identity(host):
    name, rank, hints = "", 0, []
    for port in host.findall("ports/port"):
        state, service = port.find("state"), port.find("service")
        if state is None or state.get("state") != "open":
            continue
        hints.extend(web_identity(port))
        if service is None:
            continue
        if service.get("hostname"):
            name, rank = clean(service.get("hostname")), 2
        for attribute, label in (("ostype", "Service OS"), ("devicetype", "Device")):
            if service.get(attribute):
                hints.append(f"{label}: {clean(service.get(attribute))}")
    for script in host.findall("hostscript/script") + host.findall("ports/port/script"):
        script_id = script.get("id")
        if script_id == "nbstat":
            netbios_name, netbios_hints = netbios_identity(script)
            if netbios_name and rank < 3:
                name, rank = netbios_name, 2
            hints.extend(netbios_hints)
            continue
        if script_id not in {"smb-os-discovery", "rdp-ntlm-info"}:
            continue
        # Prefer structured NSE fields; older versions may only supply output text.
        fields = {}
        for line in script.get("output", "").splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[re.sub(r"[^a-z0-9]", "", key.lower())] = clean(value)
        for item in script.findall("elem"):
            key = re.sub(r"[^a-z0-9]", "", item.get("key", "").lower())
            fields[key] = clean(item.text or "")
        if script_id == "smb-os-discovery":
            names = ("fqdn", "server", "netbioscomputername", "computername")
            labels = (
                ("os", "SMB OS"),
                ("workgroup", "Workgroup"),
                ("domain", "Domain"),
            )
        else:
            names = ("dnscomputername", "netbioscomputername")
            labels = (("productversion", "RDP build"), ("dnsdomainname", "Domain"))
        for key in names:
            if fields.get(key) and fields[key].lower() not in {"unknown", "<unknown>"}:
                name, rank = fields[key], 3
                break
        for key, label in labels:
            if fields.get(key) and fields[key].lower() not in {"unknown", "<unknown>"}:
                hints.append(f"{label}: {fields[key]}")
    return name, rank, tuple(dict.fromkeys(hints))[:16]


class NmapXML:
    def __init__(self, ports=False, source=None):
        self.parser = ET.XMLPullParser(events=("end",))
        self.ports = ports
        self.source = source or ("PORTS" if ports else "NMAP")

    def feed(self, data):
        self.parser.feed(data)
        return self.observations()

    def observations(self, interrupted=False):
        observations = []
        events = self.parser.read_events()
        while True:
            try:
                _, element = next(events)
            except StopIteration:
                break
            except ET.ParseError:
                if not interrupted:
                    raise
                break
            if element.tag != "host":
                continue
            status = element.find("status")
            if status is None or status.get("state") != "up":
                element.clear()
                continue
            addresses = element.findall("address")
            ips = [
                a.get("addr", "")
                for a in addresses
                if a.get("addrtype") in ("ipv4", "ipv6")
            ]
            mac = next((a for a in addresses if a.get("addrtype") == "mac"), None)
            name = element.find("hostnames/hostname")
            ports = []
            counts = {}
            for state in element.findall("ports/port/state") + element.findall(
                "ports/extraports"
            ):
                label = clean(state.get("state", "unknown"))
                count = state.get("count", "1")
                if count.isdigit():
                    counts[label] = counts.get(label, 0) + int(count)
            port_summary = ", ".join(
                f"{count} {label}"
                for label, count in sorted(counts.items())
                if label != "open"
            )
            has_ports = element.find("ports") is not None
            if element.get("timedout") == "true":
                has_ports = False
                port_summary = "timed out"
            elif self.ports and not has_ports:
                port_summary = "no port results returned"
            identity_name, identity_rank, identity = service_identity(element)
            if self.source == "NETBIOS" and not (identity_name or identity):
                # -Pn assumes the host is up; absent script results prove nothing.
                element.clear()
                continue
            responded = any(
                p.get("state") in {"open", "closed"}
                for p in element.findall("ports/port/state")
                + element.findall("ports/extraports")
            )
            for port in element.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                number, proto = port.get("portid", ""), port.get("protocol", "")
                if (
                    not number.isdigit()
                    or not 0 < int(number) <= 65535
                    or proto not in ("tcp", "udp")
                ):
                    continue
                service = port.find("service")
                detail = ""
                if service is not None:
                    detail = " ".join(
                        filter(
                            None,
                            (
                                service.get(k, "")
                                for k in ("name", "product", "version", "extrainfo")
                            ),
                        )
                    )
                ports.append(
                    f"{number}/{proto}" + (" " + clean(detail) if detail else "")
                )
            for ip in ips:
                observations.append(
                    Observation(
                        ip,
                        self.source,
                        mac.get("addr") if mac is not None else None,
                        identity_name
                        or (name.get("name", "") if name is not None else ""),
                        identity_rank or 1,
                        mac.get("vendor", "") if mac is not None else "",
                        tuple(sorted(ports, key=lambda p: int(p.split("/", 1)[0])))
                        if self.ports and has_ports
                        else None,
                        seen=time.time() if not self.ports or responded else 0,
                        identity=identity,
                        port_summary=port_summary if self.ports else "",
                    )
                )
            element.clear()
        return observations

    def finish(self, interrupted=False):
        try:
            self.parser.close()
        except ET.ParseError:
            if not interrupted:
                raise
        # Expat can defer incomplete-token reparsing until close, including host events.
        return self.observations(interrupted)


BASE_FIELDS = ["eth.src", "ip.src", "ipv6.src", "arp.src.proto_ipv4", "arp.src.hw_mac"]
DHCP_FIELDS = [
    "dhcp.ip.client",
    "dhcp.ip.your",
    "dhcp.hw.mac_addr",
    "dhcp.option.hostname",
    "dhcp.option.dhcp",
]
DNS_FIELDS = [
    "udp.srcport",
    "dns.flags.response",
    "dns.count.answers",
    "dns.count.add_rr",
    "dns.count.auth_rr",
    "dns.resp.name",
    "dns.resp.type",
    "dns.a",
    "dns.aaaa",
]


def packet_observations(line: str, fields: list[str]):
    # Unlike Bash IFS whitespace splitting, split preserves missing tshark fields.
    values = line.rstrip("\r\n").split("\t")
    if len(values) != len(fields):
        return []
    row = dict(zip(fields, values))
    result = []
    source = row.get("ip.src") or row.get("ipv6.src") or ""
    mac = row.get("eth.src", "")
    if address(source) and (not mac or mac_address(mac)):
        result.append(Observation(source, "PACKET", mac or None))
    # ARP targets are questions, not evidence that a device exists.
    if address(row.get("arp.src.proto_ipv4", "")) and mac_address(
        row.get("arp.src.hw_mac", "")
    ):
        result.append(
            Observation(row["arp.src.proto_ipv4"], "ARP", row["arp.src.hw_mac"])
        )
    client = row.get("dhcp.ip.client", "")
    if row.get("dhcp.option.dhcp") == "5":  # An ACK, not an unaccepted lease offer.
        client = row.get("dhcp.ip.your") or client
    elif client != source:
        client = ""
    if address(client) and mac_address(row.get("dhcp.hw.mac_addr", "")):
        result.append(
            Observation(
                client,
                "DHCP",
                row["dhcp.hw.mac_addr"],
                row.get("dhcp.option.hostname", ""),
                2,
            )
        )
    # Repeated RR names/types stay aligned; A and AAAA values have separate cursors.
    # Learn the sender's name, not every address advertised by an mDNS proxy.
    if (
        result
        and address(source)
        and row.get("dns.flags.response") == "1"
        and row.get("udp.srcport") in {"5353", "5355"}
    ):
        names = row.get("dns.resp.name", "").split("|")
        types = row.get("dns.resp.type", "").split("|")
        counts = [
            row.get(key) or "0"
            for key in ("dns.count.answers", "dns.count.add_rr", "dns.count.auth_rr")
        ]
        v4 = row.get("dns.a", "").split("|") if row.get("dns.a") else []
        v6 = row.get("dns.aaaa", "").split("|") if row.get("dns.aaaa") else []
        if (
            all(c.isdigit() and len(c) <= 5 for c in counts)
            and sum(map(int, counts)) == len(names) == len(types)
            and types.count("1") == len(v4)
            and types.count("28") == len(v6)
        ):
            values = {"1": iter(v4), "28": iter(v6)}
            for name, kind in zip(names, types):
                if kind not in values:
                    continue
                dns_ip, name = next(values[kind]), name.rstrip(".")
                if (
                    address(dns_ip) == address(source)
                    and "_" not in name
                    and (
                        row["udp.srcport"] == "5355" or name.lower().endswith(".local")
                    )
                ):
                    result.append(
                        Observation(
                            source,
                            "mDNS" if row["udp.srcport"] == "5353" else "LLMNR",
                            mac or None,
                            name,
                            3,
                        )
                    )
    return result


class Vendors:
    def __init__(self, path):
        self.prefixes = {}
        try:
            with open(path, encoding="utf-8", errors="replace") as source:
                for line in source:
                    parts = line.split(None, 1)
                    if len(parts) == 2 and re.fullmatch(r"[0-9A-Fa-f]{6}", parts[0]):
                        self.prefixes[parts[0].lower()] = clean(parts[1])
        except OSError:
            pass

    def lookup(self, mac, supplied=""):
        if not mac:
            return "Unknown"
        if int(mac[:2], 16) & 2:
            return "Private/randomized MAC"
        return self.prefixes.get(mac.replace(":", "")[:6], clean(supplied) or "Unknown")


@dataclasses.dataclass
class Device:
    ip: str
    mac: str | None = None
    name: str = ""
    name_rank: int = 0
    vendor: str = "Unknown"
    ports: tuple[str, ...] | None = None
    sources: set[str] = dataclasses.field(default_factory=set)
    last_seen: float = 0
    generation: int = 0
    identity: tuple[str, ...] = ()
    port_summary: str = ""
    probe_status: str = ""

    def signature(self):
        return (
            self.mac,
            self.name,
            self.vendor,
            self.ports,
            self.identity,
            self.port_summary,
            tuple(sorted(self.sources)),
        )


@dataclasses.dataclass
class ProbeUpdate:
    ip: str
    generation: int
    observation: Observation | None = None
    status: str = ""


class Inventory:
    def __init__(self, context, vendors):
        self.context, self.vendors = context, vendors
        self.devices = {}
        self.gateway_macs = {
            mac_address(n.get("lladdr", ""))
            for n in context.neighbours
            if n.get("dst") in context.gateways
        }
        self.gateway_macs.discard(None)

    def merge(self, observation):
        ip = address(observation.ip)
        if ip is None or not self.context.allows(ip):
            return None
        if any(
            ip.version == n.version == 4
            and n.prefixlen < 31
            and ip in (n.network_address, n.broadcast_address)
            for n in self.context.networks
        ):
            return None
        key = str(ip)
        mac = mac_address(observation.mac or "")
        # Ethernet identifies a next hop, never an off-link device.
        if not self.context.on_link(ip) or (
            mac in self.gateway_macs and key not in self.context.gateways
        ):
            mac = None
        device = self.devices.setdefault(key, Device(key))
        before = device.signature()
        if mac and device.mac and mac != device.mac:
            device.name, device.name_rank, device.ports = "", 0, None
            device.identity, device.port_summary, device.probe_status = (), "", ""
            device.sources.clear()
            device.last_seen = 0
            device.generation += 1
        if mac:
            device.mac = mac
            device.vendor = self.vendors.lookup(mac, observation.vendor)
        if observation.name and observation.name_rank >= device.name_rank:
            device.name, device.name_rank = (
                clean(observation.name),
                observation.name_rank,
            )
        if observation.ports is not None:
            if observation.source == "SERVICES" and device.ports is not None:
                # Version detection only revisits open ports; keep the first scan's results.
                ports = {p.split(" ", 1)[0]: p for p in device.ports}
                ports.update({p.split(" ", 1)[0]: p for p in observation.ports})
                device.ports = tuple(
                    sorted(ports.values(), key=lambda p: int(p.split("/", 1)[0]))
                )
            else:
                device.ports = observation.ports
        if observation.port_summary and (
            observation.source != "SERVICES" or not device.port_summary
        ):
            device.port_summary = observation.port_summary
        if observation.identity:
            device.identity = tuple(
                dict.fromkeys(
                    (*device.identity, *(clean(v) for v in observation.identity))
                )
            )[:16]
        device.sources.add(observation.source)
        if observation.source not in {"NEIGH-CACHED", "ROUTE", "NAME"}:
            device.last_seen = max(device.last_seen, observation.seen)
        return device if device.signature() != before else None

    def ordered(self):
        return sorted(
            self.devices.values(),
            key=lambda d: (address(d.ip).version, int(address(d.ip))),
        )


def write_cache(path: Path, devices, ttl=86400, now=None):
    """Merge under a lock, atomically on the same filesystem; never persist routed MACs."""
    now = int(time.time() if now is None else now)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(path) + ".lock", "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        records = {}
        try:
            with path.open(encoding="utf-8") as source:
                for line in source:
                    parts = line.rstrip("\n").split("\t")
                    if (
                        len(parts) >= 3
                        and parts[2].isdigit()
                        and 0 <= now - int(parts[2]) <= ttl
                        and mac_address(parts[0])
                        and address(parts[1])
                    ):
                        records[parts[0], parts[1]] = int(parts[2])
        except FileNotFoundError:
            pass
        fresh = {
            d.ip: d
            for d in devices
            if d.mac
            and d.last_seen
            and 0 <= now - int(d.last_seen) <= ttl
            and d.sources - {"NEIGH-CACHED", "ROUTE", "NAME"}
        }
        records = {
            key: seen
            for key, seen in records.items()
            if key[1] not in fresh or key[0] == fresh[key[1]].mac
        }
        for device in fresh.values():
            records[device.mac, device.ip] = int(device.last_seen)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=path.parent,
                prefix=".netmgr-",
                delete=False,
            ) as output:
                temporary = output.name
                for (mac, ip), seen in sorted(records.items()):
                    output.write(f"{mac}\t{ip}\t{seen}\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)


class CommandError(RuntimeError):
    pass


class Runner:
    def exists(self, command):
        return shutil.which(command) is not None

    def run(self, command, timeout=5):
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
        if result.returncode:
            raise CommandError(
                clean(result.stderr or f"{command[0]} exited {result.returncode}", 400)
            )
        return result.stdout

    def authenticate(self):
        if os.geteuid() == 0:
            return []
        if subprocess.run(["sudo", "-v"], check=False).returncode:
            raise CommandError("sudo authentication failed")
        return ["sudo", "-n", "--"]

    def stream(self, command, stop):
        if stop.is_set():
            return
        # Keep the controlling terminal/sudo ticket while isolating worker signals.
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            process_group=0,
            env={**os.environ, "LC_ALL": "C"},
        )
        errors = b""
        stopping = None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, "out")
                selector.register(proc.stderr, selectors.EVENT_READ, "err")
                while selector.get_map():
                    if stop.is_set() and stopping is None:
                        stopping = time.monotonic()
                        self.signal_group(proc, signal.SIGTERM)
                    if stopping is not None and time.monotonic() - stopping > 2:
                        self.signal_group(proc, signal.SIGKILL)
                    for key, _ in selector.select(0.1):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                        elif key.data == "out":
                            yield data
                        else:
                            errors = (errors + data)[-8192:]
                code = proc.wait(timeout=3)
                if code and not stop.is_set():
                    raise CommandError(
                        clean(
                            errors.decode(errors="replace")
                            or f"{command[0]} exited {code}",
                            400,
                        )
                    )
        finally:
            if proc.poll() is None:
                self.signal_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.signal_group(proc, signal.SIGKILL)
                    proc.wait(timeout=2)
            proc.stdout.close()
            proc.stderr.close()

    @staticmethod
    def signal_group(proc, signum):
        try:
            os.killpg(proc.pid, signum)
        except ProcessLookupError:
            pass


def network_context(options, runner):
    links = json.loads(runner.run(["ip", "-j", "address", "show"]))
    routes = json.loads(runner.run(["ip", "-j", "route", "show", "default"]))
    interface, target = None, None
    for argument in options.targets:
        try:
            parsed = Targets.parse(argument)
        except ValueError:
            if (
                interface is not None
                or not re.fullmatch(r"[A-Za-z0-9_.:-]+", argument)
                or argument[0].isdigit()
            ):
                raise ValueError(
                    f"invalid interface/IPv4 or IPv6 target: {argument}"
                ) from None
            interface = argument
        else:
            if target is not None:
                raise ValueError("specify one target host, CIDR, or IPv4 range")
            target = parsed
    if not interface and target is not None:
        route = json.loads(runner.run(["ip", "-j", "route", "get", str(target.first)]))
        interface = next((r.get("dev") for r in route if r.get("dev")), None)
    if not interface:
        interface = next(
            (
                r.get("dev")
                for r in sorted(routes, key=lambda r: r.get("metric", 0))
                if r.get("dev")
            ),
            None,
        )
    if not interface:
        interface = next(
            (
                n["ifname"]
                for n in links
                if n["ifname"] != "lo"
                and "UP" in n.get("flags", [])
                and n.get("addr_info")
            ),
            None,
        )
    link = next((n for n in links if n["ifname"] == interface), None)
    if link is None:
        raise ValueError(f"no configured interface found: {interface or '(automatic)'}")
    networks = [
        ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False)
        for a in link.get("addr_info", [])
        if a.get("family") in ("inet", "inet6")
    ]
    own = {
        a["local"]
        for a in link.get("addr_info", [])
        if a.get("family") in ("inet", "inet6")
    }
    default_target = target is None
    if target is None:
        network = next((n for n in networks if n.version == 4), None)
        if network is None:
            raise ValueError(
                "no IPv4 subnet; specify an individual IPv6 target (whole IPv6 subnet sweeps are not practical)"
            )
        target = Targets.parse(str(network))
    if target.first.version == 6 and target.count > 4096:
        raise ValueError(
            "IPv6 sweeps are limited to 4096 addresses; specify known IPv6 hosts instead"
        )
    if options.allow_large and default_target:
        raise ValueError("--allow-large requires an explicitly selected target")
    if target.count > 65536 and not options.allow_large:
        raise ValueError(
            f"target contains {target.count} addresses; narrow it or explicitly use --allow-large"
        )
    try:
        neighbours = json.loads(
            runner.run(["ip", "-j", "neigh", "show", "dev", interface])
        )
    except CommandError:
        neighbours = []
    return Context(
        interface,
        target,
        networks,
        own,
        mac_address(link.get("address", "")),
        neighbours,
        {
            r["gateway"]
            for r in routes
            if r.get("dev") == interface and r.get("gateway")
        },
        default_target,
    )


class Discovery:
    def __init__(self, options, runner, context, output=None, errors=None):
        self.options, self.runner, self.context = options, runner, context
        self.output = sys.stdout if output is None else output
        self.errors = sys.stderr if errors is None else errors
        self.inventory = Inventory(
            context,
            Vendors(
                os.environ.get(
                    "NETMGR_MAC_PREFIX_DB", "/usr/share/nmap/nmap-mac-prefixes"
                )
            ),
        )
        self.queue = queue.Queue(maxsize=4096)
        self.stop, self.cancel, self.active_done = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        self.interrupted = False
        self.failed = False
        self.dropped = 0
        self.names = {}
        self.name_attempts = set()
        self.probes = {}
        self.probe_attempts = set()
        self.priv = []
        self.cache_dirty = False

    def warn(self, message):
        print("Warning: " + clean(message, 400), file=self.errors, flush=True)

    def publish(self, observation):
        try:
            self.queue.put(observation, timeout=0.1)
        except queue.Full:
            self.dropped += 1

    def nmap(self):
        round_number = 0
        try:
            while not self.stop.is_set():
                round_number += 1
                for batch in self.context.targets.batches(self.options.batch_size):
                    if self.stop.is_set():
                        break
                    decoder = NmapXML()
                    command = self.priv + [
                        "nmap",
                        "-sn",
                        "-n",
                        "-e",
                        self.context.interface,
                        "-T3" if round_number % 4 == 0 else "-T4",
                        "--max-retries",
                        "3" if round_number % 4 == 0 else "2",
                        "--max-rtt-timeout",
                        "2s",
                        "-oX",
                        "-",
                    ]
                    if self.context.targets.first.version == 6:
                        command.append("-6")
                    for chunk in self.runner.stream(
                        command + [self.context.target_arg(v) for v in batch], self.stop
                    ):
                        for observation in decoder.feed(chunk):
                            self.publish(observation)
                    for observation in decoder.finish(interrupted=self.stop.is_set()):
                        self.publish(observation)
                if self.options.once or self.stop.wait(self.options.delay):
                    break
        except (CommandError, ET.ParseError, OSError, subprocess.TimeoutExpired) as exc:
            self.failed = True
            self.warn(f"active discovery stopped: {exc}")
        finally:
            self.active_done.set()

    def packets(self):
        if self.stop.is_set():
            return
        fields = list(BASE_FIELDS)
        try:
            try:
                available = {
                    p[2]
                    for line in self.runner.run(
                        ["tshark", "-G", "fields"], timeout=10
                    ).splitlines()
                    if len(p := line.split("\t")) > 2 and p[0] == "F"
                }
            except (CommandError, subprocess.TimeoutExpired):
                available = set()
            for group in (DHCP_FIELDS, DNS_FIELDS):
                if set(group) <= available:
                    fields.extend(group)
            if self.stop.is_set():
                return
            # Discovery needs address announcements, not bulk TCP payload dissection.
            command = self.priv + [
                "tshark",
                "-l",
                "-n",
                "-s",
                "2048",
                "-i",
                self.context.interface,
                "-f",
                "arp or icmp6 or (udp and (port 67 or port 68 or port 5353 or port 5355))",
                "-T",
                "fields",
                "-E",
                "separator=\t",
                "-E",
                "occurrence=a",
                "-E",
                "aggregator=|",
            ]
            for field in fields:
                command.extend(["-e", field])
            buffer = b""
            recent = {}
            for chunk in self.runner.stream(command, self.stop):
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    for observation in packet_observations(
                        line.decode("utf-8", errors="replace"), fields
                    ):
                        key = (
                            observation.ip,
                            observation.mac,
                            observation.name,
                            observation.source,
                        )
                        now = time.monotonic()
                        if now - recent.get(key, -10) >= 2:
                            self.publish(observation)
                            recent[key] = now
                        if len(recent) > 8192:
                            recent = {k: v for k, v in recent.items() if now - v < 2}
                            while len(recent) > 8192:
                                del recent[next(iter(recent))]
                if len(buffer) > 65536:
                    raise CommandError("oversized packet-decoder record")
            if not self.stop.is_set():
                raise CommandError("tshark exited unexpectedly")
        except (CommandError, OSError, subprocess.TimeoutExpired) as exc:
            if not self.stop.is_set():
                self.warn(
                    f"passive discovery stopped; active scanning continues: {exc}"
                )

    def print_device(self, device):
        details = ""
        if self.options.ports or self.options.services:
            details = f"  {self.port_text(device)}"
            if self.options.services:
                details += "  | " + (
                    "; ".join(device.identity) or "no identity reported"
                )
        print(
            f"[{time.strftime('%H:%M:%S')}] {','.join(sorted(device.sources)):<18} {device.ip:<39} {device.mac or 'unknown':<17} {device.name or 'unknown':<30} {device.vendor}{details}",
            file=self.output,
            flush=True,
        )

    def accept(self, observation):
        if isinstance(observation, ProbeUpdate):
            device = self.inventory.devices.get(observation.ip)
            if device is None or device.generation != observation.generation:
                return
            if observation.observation is not None:
                self.accept(observation.observation)
            if observation.status and device.probe_status != observation.status:
                device.probe_status = observation.status
                self.print_device(device)
            return
        device = self.inventory.merge(observation)
        if device:
            if (
                self.options.ports or self.options.services
            ) and not device.probe_status:
                device.probe_status = "queued"
            self.print_device(device)
        if (
            address(observation.ip)
            and str(address(observation.ip)) in self.inventory.devices
        ):
            self.cache_dirty = True

    def seed(self):
        for ip in sorted(self.context.own_addresses):
            self.accept(
                Observation(ip, "SELF", self.context.own_mac, socket.gethostname(), 4)
            )
        for item in self.context.neighbours:
            states = item.get("state", [])
            if isinstance(states, str):
                states = [states]
            if (
                states
                and not set(states) & {"FAILED", "INCOMPLETE", "NONE"}
                and mac_address(item.get("lladdr", ""))
            ):
                self.accept(
                    Observation(item.get("dst", ""), "NEIGH-CACHED", item["lladdr"])
                )
        for ip in self.context.gateways:
            self.accept(Observation(ip, "ROUTE"))

    def resolve(self, ip):
        try:
            rows = self.runner.run(
                ["getent", "hosts", self.context.target_arg(ip)], timeout=1
            ).splitlines()
            for row in rows:
                parts = row.split()
                if len(parts) >= 2 and address(parts[0]) == address(ip):
                    return clean(parts[1])
        except (CommandError, OSError, subprocess.TimeoutExpired):
            pass
        return ""

    def collect_names(self, pool, schedule=True):
        for future, (ip, generation) in list(self.names.items()):
            if future.done():
                del self.names[future]
                device = self.inventory.devices[ip]
                name = future.result()
                if name and generation == device.generation and not device.name:
                    self.accept(Observation(ip, "NAME", name=name, name_rank=1, seen=0))
        if schedule and not self.cancel.is_set():
            for device in self.inventory.devices.values():
                key = device.ip, device.generation
                if len(self.names) >= self.options.jobs * 2:
                    break
                if not device.name and key not in self.name_attempts:
                    self.name_attempts.add(key)
                    self.names[pool.submit(self.resolve, device.ip)] = key

    def probe_host(self, ip, generation):
        status, phase = "complete", "ports"
        command = self.priv + [
            "nmap",
            "-Pn",
            "-n",
            "-T3",
            "--max-retries",
            "2",
            "--max-rtt-timeout",
            "2s",
            "-e",
            self.context.interface,
            "-oX",
            "-",
        ]
        if address(ip).version == 6:
            command.append("-6")

        def scan(arguments, source):
            decoder = NmapXML(ports=source != "NETBIOS", source=source)
            result = None

            def publish(rows):
                nonlocal result
                for observation in rows:
                    if address(observation.ip) == address(ip):
                        result = observation
                        self.publish(ProbeUpdate(ip, generation, observation))

            for chunk in self.runner.stream(
                command + arguments + [self.context.target_arg(ip)], self.cancel
            ):
                publish(decoder.feed(chunk))
            publish(decoder.finish(interrupted=self.cancel.is_set()))
            return result

        try:
            if self.cancel.is_set():
                return
            if self.options.services and address(ip).version == 4:
                self.publish(ProbeUpdate(ip, generation, status="querying NetBIOS"))
                try:
                    # Force only nbstat: its default host rule requires prior port results.
                    scan(
                        [
                            "-sn",
                            "--script",
                            "+nbstat",
                            "--script-timeout",
                            "4s",
                            "--host-timeout",
                            "6s",
                        ],
                        "NETBIOS",
                    )
                except (
                    CommandError,
                    ET.ParseError,
                    OSError,
                    subprocess.TimeoutExpired,
                ) as exc:
                    if not self.cancel.is_set():
                        self.warn(
                            f"{ip}: NetBIOS query incomplete; continuing TCP probes: {exc}"
                        )
                if self.cancel.is_set():
                    return
                self.publish(ProbeUpdate(ip, generation, status="scanning ports"))
            result = scan(
                ["-sS", "--top-ports", "200", "--host-timeout", "30s"], "PORTS"
            )
            if result is None or result.ports is None:
                status = "ports incomplete: " + (
                    result.port_summary if result else "no results returned"
                )
            elif self.options.services and result.ports and not self.cancel.is_set():
                phase = "services"
                self.publish(ProbeUpdate(ip, generation, status="identifying services"))
                ports = ",".join(p.split("/", 1)[0] for p in result.ports)
                result = scan(
                    [
                        "-sS",
                        "-p",
                        ports,
                        "-sV",
                        "--version-light",
                        "--host-timeout",
                        "60s",
                        "--script",
                        "smb-os-discovery,rdp-ntlm-info,http-title,ssl-cert",
                        "--script-timeout",
                        "8s",
                        "--script-args",
                        "http.max-body-size=65536,http.truncated-ok=true",
                    ],
                    "SERVICES",
                )
                if result is None or result.ports is None:
                    status = "services incomplete; earlier ports retained"
        except (CommandError, ET.ParseError, OSError, subprocess.TimeoutExpired) as exc:
            status = f"{phase} failed; partial results retained"
            self.warn(f"{ip}: {status}: {exc}")
        finally:
            self.publish(
                ProbeUpdate(
                    ip,
                    generation,
                    status="interrupted" if self.cancel.is_set() else status,
                )
            )

    def collect_probes(self, pool):
        if pool is None:
            return
        for future in list(self.probes):
            if future.done():
                del self.probes[future]
                future.result()
        if self.cancel.is_set() or self.failed:
            return
        for device in self.inventory.devices.values():
            if len(self.probes) >= 4:
                break
            key = device.ip, device.generation
            if key not in self.probe_attempts:
                self.probe_attempts.add(key)
                device.probe_status = "scanning ports"
                self.print_device(device)
                self.probes[pool.submit(self.probe_host, *key)] = key

    def probe_progress(self):
        queued = sum(
            d.probe_status == "queued" for d in self.inventory.devices.values()
        )
        print(
            f"Probing: {len(self.probes)} active, {queued} queued; completed results appear above. Ctrl+C keeps collected details.",
            file=self.output,
            flush=True,
        )

    @staticmethod
    def port_text(device):
        if device.ports is None:
            ports = (
                "no port results"
                if device.probe_status not in {"", "queued", "scanning ports"}
                else "not scanned"
            )
        else:
            ports = "; ".join(device.ports) or "no open ports found"
        if device.port_summary:
            ports += f" ({device.port_summary})"
        if device.probe_status and device.probe_status != "complete":
            ports += f" [{device.probe_status}]"
        return ports

    def final(self):
        print("\nFinal Scan Table:", file=self.output)
        rows = [
            (
                "IP_Address",
                "Hostname/Identity",
                "MAC_Address",
                "Manufacturer",
                "Ports/Services",
                "Evidence",
            )
            + (("Identity hints",) if self.options.services else ())
        ]
        for device in self.inventory.ordered():
            rows.append(
                (
                    device.ip,
                    device.name or "unknown",
                    device.mac or "unknown",
                    device.vendor,
                    self.port_text(device),
                    ",".join(sorted(device.sources)),
                )
                + (
                    ("; ".join(device.identity) or "unknown",)
                    if self.options.services
                    else ()
                )
            )
        widths = [
            max(len(row[column]) for row in rows) for column in range(len(rows[0]))
        ]
        for row in rows:
            print(
                "  ".join(
                    value.ljust(width) for value, width in zip(row, widths)
                ).rstrip(),
                file=self.output,
            )
        print(
            f"\n{len(self.inventory.devices)} addresses recorded. NEIGH-CACHED/ROUTE are existing records, not proof a host is currently reachable.",
            file=self.output,
        )
        if self.dropped:
            self.warn(
                f"{self.dropped} observations dropped because the event queue was full"
            )
        macs = [d.mac for d in self.inventory.devices.values() if d.mac]
        if len(macs) != len(set(macs)):
            print(
                "Multiple addresses share a MAC: this may be one device, virtual networking, or proxy ARP, not separate physical devices.",
                file=self.output,
            )
        print(
            "Sleeping devices and Wi-Fi client isolation can prevent discovery; no response does not prove absence.",
            file=self.output,
        )
        if self.options.ports or self.options.services:
            print(
                "Port results cover the top 200 TCP ports, not every port. Filtered ports and timeouts are inconclusive.",
                file=self.output,
            )
        if self.options.services:
            print(
                "Identity hints are reported by services, not verified OS identification; an open SMB/RDP port alone does not prove Windows.",
                file=self.output,
            )
            print(
                "HTTP titles, TLS names and NetBIOS-reported MACs are hints, not confirmed hostnames or observed MAC mappings.",
                file=self.output,
            )

    def save_cache(self):
        if self.cache_dirty:
            try:
                write_cache(
                    Path(
                        os.environ.get(
                            "NETMGR_MAC_IP_DB", "~/.local/share/netmgr/mac_ip_map.tsv"
                        )
                    ).expanduser(),
                    self.inventory.ordered(),
                )
            except OSError as exc:
                self.warn(f"could not save MAC/IP hints: {exc}")
            self.cache_dirty = False

    def run(self):
        self.priv = self.runner.authenticate()
        mode = (
            "one discovery sweep"
            if self.options.once
            else f"{self.options.duration:g}s discovery window"
            if self.options.duration
            else "continuous discovery"
        )
        print(
            f"Using Interface: {self.context.interface}\nDiscovering {self.context.targets.first} - {self.context.targets.last}\nMode: {mode}; Ctrl+C stops workers and prints collected results.",
            file=self.output,
            flush=True,
        )
        header = "Time       Evidence           IP_Address                              MAC_Address       Hostname                       Vendor"
        if self.options.ports or self.options.services:
            print(
                "Port probes start as devices are found (up to 4 hosts at once); open ports appear before slower service identification.",
                file=self.output,
                flush=True,
            )
            header += "  Ports/Services (scan status)"
            if self.options.services:
                print(
                    "Services: short IPv4 NetBIOS name query before TCP probes; open services may add SMB/RDP, HTTP-title and TLS-name hints.",
                    file=self.output,
                    flush=True,
                )
                header += "  | Identity hints"
            if not self.context.on_link(self.context.targets.first):
                print(
                    "Routed target: remote MAC/vendor and local multicast names may be unavailable; service probes can still reveal identity hints.",
                    file=self.output,
                    flush=True,
                )
        print(header, file=self.output, flush=True)
        self.seed()
        workers = [threading.Thread(target=self.nmap, name="netmgr-nmap")]
        if not self.options.no_passive and self.runner.exists("tshark"):
            workers.append(threading.Thread(target=self.packets, name="netmgr-packets"))
        elif not self.options.no_passive:
            self.warn(
                "tshark not installed; active and neighbour discovery remain available"
            )
        old_handlers = {}

        def interrupt(_signum, _frame):
            self.interrupted = True
            self.stop.set()
            self.cancel.set()

        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGINT, signal.SIGTERM):
                old_handlers[signum] = signal.signal(signum, interrupt)
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.options.jobs)
        probe_pool = (
            concurrent.futures.ThreadPoolExecutor(
                max_workers=4, thread_name_prefix="netmgr-probe"
            )
            if self.options.ports or self.options.services
            else None
        )
        started = time.monotonic()
        next_save = started + 15
        next_progress = started + 5
        names_deadline = None
        try:
            for worker in workers:
                worker.start()
            while True:
                if self.active_done.is_set() or (
                    self.options.duration
                    and time.monotonic() - started >= self.options.duration
                ):
                    self.stop.set()
                try:
                    self.accept(self.queue.get(timeout=0.1))
                except queue.Empty:
                    pass
                discovery_done = (
                    not any(w.is_alive() for w in workers) and self.queue.empty()
                )
                if discovery_done and names_deadline is None:
                    names_deadline = time.monotonic() + 30
                names_open = names_deadline is None or time.monotonic() < names_deadline
                if self.options.resolve_hostnames:
                    self.collect_names(pool, schedule=names_open)
                self.collect_probes(probe_pool)
                if (
                    probe_pool is not None
                    and self.probes
                    and time.monotonic() >= next_progress
                ):
                    self.probe_progress()
                    next_progress = time.monotonic() + 5
                if time.monotonic() >= next_save:
                    self.save_cache()
                    next_save = time.monotonic() + 15
                if (
                    discovery_done
                    and self.queue.empty()
                    and not self.probes
                    and (not self.names or not names_open or self.cancel.is_set())
                ):
                    break
            if self.names and not self.interrupted:
                self.warn(
                    "hostname lookup time budget reached; unresolved devices are retained"
                )
            if probe_pool is not None and self.interrupted:
                self.warn(
                    "probing interrupted; completed port and identity results retained"
                )
        finally:
            self.stop.set()
            self.cancel.set()
            for worker in workers:
                if worker.ident is not None:
                    worker.join()
            if probe_pool is not None:
                probe_pool.shutdown(wait=True, cancel_futures=True)
            pool.shutdown(wait=True, cancel_futures=True)
            while not self.queue.empty():
                self.accept(self.queue.get_nowait())
            if self.interrupted:
                for device in self.inventory.devices.values():
                    if device.probe_status in {
                        "queued",
                        "querying NetBIOS",
                        "scanning ports",
                        "identifying services",
                    }:
                        device.probe_status = "interrupted"
            elif self.failed:
                for device in self.inventory.devices.values():
                    if device.probe_status == "queued":
                        device.probe_status = "skipped: discovery failed"
            for signum, handler in old_handlers.items():
                signal.signal(signum, handler)
            try:
                self.final()
            finally:
                self.save_cache()
        return 130 if self.interrupted else 1 if self.failed else 0


def options_for(argv):
    parser = argparse.ArgumentParser(
        description="Active LAN discovery with passive address/name announcements and optional enrichment."
    )
    parser.add_argument("targets", nargs="*", metavar="INTERFACE_OR_TARGET")
    parser.add_argument(
        "--once",
        action="store_true",
        help="complete one discovery sweep and any requested background probes, then print a final table",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0,
        metavar="SECONDS",
        help="limit discovery time; already-discovered hosts finish requested probes afterward",
    )
    parser.add_argument(
        "--ports",
        action="store_true",
        help="show top-200 TCP port results as hosts are found (one sweep unless --duration is supplied)",
    )
    parser.add_argument(
        "--services",
        action="store_true",
        help="also query IPv4 NetBIOS names and identify open services with SMB/RDP, HTTP-title and TLS-name hints; show results live",
    )
    parser.add_argument(
        "--resolve-hostnames",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="bounded parallel hostname resolution, without blocking discovery (enabled by default)",
    )
    parser.add_argument("--no-passive", action="store_true", help="do not run tshark")
    parser.add_argument(
        "--allow-large",
        action="store_true",
        help="allow an explicitly selected IPv4 target larger than 65536 addresses",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=64,
        help="addresses per discovery batch (1-1024)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=os.environ.get("AVAHI_JOBS", "8"),
        help="parallel name lookups (1-32)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=os.environ.get("NETMGR_SCAN_NMAP_DELAY", "1"),
        help="seconds between continuous sweeps",
    )
    options = parser.parse_intermixed_args(argv)
    if (
        len(options.targets) > 2
        or not 1 <= options.batch_size <= 1024
        or not 1 <= options.jobs <= 32
        or not 0.1 <= options.delay <= 3600
        or not 0 <= options.duration <= 86400
    ):
        parser.error("invalid argument count, batch size, jobs, delay, or duration")
    if options.once and options.duration:
        parser.error("choose --once or --duration, not both")
    if (options.ports or options.services) and not options.duration:
        options.once = True
    return options


def main(argv=None, runner=None):
    if sys.version_info < (3, 11):  # noqa: UP036 - The CLI may use an older system Python.
        print("Error: device discovery requires Python 3.11 or newer.", file=sys.stderr)
        return 1
    options = options_for(sys.argv[1:] if argv is None else argv)
    runner = runner or Runner()
    try:
        for command in ("ip", "nmap"):
            if not runner.exists(command):
                raise CommandError(f"{command} is required for discovery")
        context = network_context(options, runner)
        return Discovery(options, runner, context).run()
    except KeyboardInterrupt:
        print("Interrupted before discovery started.", file=sys.stderr)
        return 130
    except (CommandError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print("Error: " + clean(str(exc), 400), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
