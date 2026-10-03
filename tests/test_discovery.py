"""Offline fixtures only: real command execution is forbidden in every test."""

import dataclasses
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "lib" / "discovery.py"
SPEC = importlib.util.spec_from_file_location("discovery", MODULE)
d = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = d
SPEC.loader.exec_module(d)

LINKS = [
    {
        "ifname": "test-wifi",
        "flags": ["UP"],
        "address": "00:11:22:33:44:55",
        "addr_info": [
            {"family": "inet", "local": "192.0.2.10", "prefixlen": 24},
            {"family": "inet6", "local": "2001:db8::10", "prefixlen": 64},
        ],
    }
]
ROUTES = [{"dev": "test-wifi", "gateway": "192.0.2.1", "metric": 50}]
NEIGHBOURS = [
    {"dst": "192.0.2.1", "lladdr": "02:22:33:44:55:66", "state": ["REACHABLE"]},
    {"dst": "192.0.2.20", "lladdr": "00:11:22:33:44:20", "state": ["STALE"]},
    {"dst": "192.0.2.99", "lladdr": "00:00:00:00:00:00", "state": ["INCOMPLETE"]},
    {"dst": "2001:db8::20", "lladdr": "00:11:22:33:44:20", "state": ["STALE"]},
]


def xml_host(ip="192.0.2.20", mac="00:11:22:33:44:20", name="", ports="", status="up"):
    link = (
        f'<address addr="{mac}" addrtype="mac" vendor="Example &amp; Co"/>'
        if mac
        else ""
    )
    names = (
        f'<hostnames><hostname name="{name}" type="PTR"/></hostnames>' if name else ""
    )
    family = "ipv6" if ":" in ip else "ipv4"
    return f'<host><status state="{status}" reason="arp-response"/><address addr="{ip}" addrtype="{family}"/>{link}{names}{ports}</host>'


class FakeRunner:
    def __init__(self, xml=None, packets=b"", fail_nmap=False):
        self.commands = []
        self.authenticated = False
        self.xml = (
            xml
            or (
                "<nmaprun>" + xml_host() + xml_host("192.0.2.30", "") + "</nmaprun>"
            ).encode()
        )
        self.packets = packets
        self.fail_nmap = fail_nmap

    def exists(self, command):
        return command in {"ip", "nmap", "tshark"}

    def authenticate(self):
        self.authenticated = True
        return []

    def run(self, command, timeout=5):
        self.commands.append(tuple(command))
        if command == ["ip", "-j", "address", "show"]:
            return json.dumps(LINKS)
        if command == ["ip", "-j", "route", "show", "default"]:
            return json.dumps(ROUTES)
        if command[:4] == ["ip", "-j", "route", "get"]:
            return '[{"dev":"test-wifi","prefsrc":"192.0.2.10"}]'
        if command[:4] == ["ip", "-j", "neigh", "show"]:
            return json.dumps(NEIGHBOURS)
        if command == ["tshark", "-G", "fields"]:
            return "\n".join(
                "F\tField\t" + field
                for field in d.BASE_FIELDS + d.DHCP_FIELDS + d.DNS_FIELDS
            )
        if command[:2] == ["getent", "hosts"]:
            return command[2] + " printer.local\n"
        raise AssertionError(f"Unexpected command: {command}")

    def stream(self, command, stop):
        self.commands.append(tuple(command))
        if command[0] == "tshark":
            if self.packets:
                yield self.packets
            return
        if command[0] != "nmap":
            raise AssertionError(f"Unexpected stream: {command}")
        if self.fail_nmap:
            raise d.CommandError("fixture scan failure")
        if "+nbstat" in command:
            yield ("<nmaprun>" + xml_host(command[-1], "") + "</nmaprun>").encode()
            return
        if "-Pn" in command:
            service = ' product="Device UI" version="2"' if "-sV" in command else ""
            body = xml_host(
                command[-1].split("%", 1)[0],
                "",
                ports=f'<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"{service}/></port></ports>',
            )
            yield ("<nmaprun>" + body + "</nmaprun>").encode()
        else:
            for start in range(0, len(self.xml), 17):
                yield self.xml[start : start + 17]


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.vendor_file = self.path / "vendors"
        self.vendor_file.write_text(
            "001122 Fixture Manufacturer\n000000 Xerox\n", encoding="utf-8"
        )
        self.env = mock.patch.dict(
            os.environ,
            {
                "NETMGR_MAC_PREFIX_DB": str(self.vendor_file),
                "NETMGR_MAC_IP_DB": str(self.path / "cache.tsv"),
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        for function in (
            "subprocess.run",
            "subprocess.Popen",
            "socket.socket",
            "socket.create_connection",
            "socket.getaddrinfo",
            "os.killpg",
        ):
            patch = mock.patch(
                function,
                side_effect=AssertionError("LIVE COMMAND EXECUTION IS FORBIDDEN"),
            )
            patch.start()
            self.addCleanup(patch.stop)
        hostname = mock.patch("socket.gethostname", return_value="fixture-self")
        hostname.start()
        self.addCleanup(hostname.stop)

    def context(self, argv=None):
        return d.network_context(
            d.options_for(argv or ["test-wifi", "--once"]), FakeRunner()
        )

    def inventory(self, argv=None):
        return d.Inventory(self.context(argv), d.Vendors(self.vendor_file))

    def packet(self, **values):
        fields = d.BASE_FIELDS + d.DHCP_FIELDS + d.DNS_FIELDS
        return d.packet_observations(
            "\t".join(values.get(f, "") for f in fields), fields
        )

    def test_ip_targets_use_exact_bounds_not_guessed_private_masks(self):
        targets = d.Targets.parse("10.20.16.3/20")
        self.assertEqual(str(targets.first), "10.20.16.1")
        self.assertEqual(str(targets.last), "10.20.31.254")
        self.assertFalse(targets.contains(d.address("10.20.32.1")))
        self.assertEqual(len(d.Targets.parse("192.0.2.0/31")), 2)
        self.assertEqual(len(d.Targets.parse("192.0.2.20-25")), 6)
        self.assertEqual(
            list(d.Targets.parse("192.0.2.20-25").batches(4)),
            [
                ["192.0.2.20", "192.0.2.21", "192.0.2.22", "192.0.2.23"],
                ["192.0.2.24", "192.0.2.25"],
            ],
        )
        for value in (
            "999.0.0.1",
            "192.0.2.0/99",
            "192.0.2.30-20",
            "224.0.0.1",
            "--script=bad",
        ):
            with self.assertRaises(ValueError):
                d.Targets.parse(value)

    def test_route_selection_custom_interface_and_target_limits(self):
        self.assertEqual(self.context(["192.0.2.20", "--once"]).interface, "test-wifi")
        self.assertEqual(self.context(["--once"]).interface, "test-wifi")
        for args in (
            ["test-wifi", "10.0.0.0/8"],
            ["test-wifi", "2001:db8::/64", "--allow-large"],
            ["missing-iface"],
            ["192.0.2.999"],
        ):
            with self.assertRaises(ValueError):
                self.context(args)

    def test_incremental_xml_entities_unknown_mac_and_down_hosts(self):
        decoder = d.NmapXML()
        self.assertEqual(decoder.feed(b"<nmaprun><host>"), [])
        found = decoder.feed(
            b'<status state="up"/><address addrtype="ipv4" addr="192.0.2.4"/><hostnames><hostname name="A&amp;B.local"/></hostnames></host>'
        )
        self.assertEqual(found[0].name, "A&B.local")
        self.assertIsNone(found[0].mac)
        self.assertEqual(decoder.feed(xml_host(status="down").encode()), [])
        decoder.feed(b"</nmaprun>")
        decoder.finish()

    def test_xml_final_events_are_drained_at_every_chunk_boundary(self):
        xml = FakeRunner().xml
        for size in (1, 7, 17, 64, len(xml)):
            decoder, rows = d.NmapXML(), []
            for offset in range(0, len(xml), size):
                rows.extend(decoder.feed(xml[offset : offset + size]))
            rows.extend(decoder.finish())
            self.assertEqual([row.ip for row in rows], ["192.0.2.20", "192.0.2.30"])

    def test_interrupted_xml_retains_completed_hosts_before_partial_record(self):
        xml = (
            "<nmaprun>" + xml_host() + xml_host("192.0.2.30", "") + "<host><sta"
        ).encode()
        decoder, rows = d.NmapXML(), []
        for offset in range(0, len(xml), 7):
            rows.extend(decoder.feed(xml[offset : offset + 7]))
        rows.extend(decoder.finish(interrupted=True))
        self.assertEqual([row.ip for row in rows], ["192.0.2.20", "192.0.2.30"])

    def test_port_service_details_and_empty_results_do_not_delete_hosts(self):
        ports = '<ports><port portid="80" protocol="tcp"><state state="closed"/></port><port portid="443" protocol="tcp"><state state="open"/><service name="https" product="Example &amp; Co" version="1.2"/></port></ports>'
        decoder = d.NmapXML(ports=True)
        found = decoder.feed(
            (
                "<nmaprun>"
                + xml_host(ports=ports)
                + xml_host("192.0.2.30", "")
                + "</nmaprun>"
            ).encode()
        )
        inventory = self.inventory()
        for row in found:
            inventory.merge(row)
        self.assertEqual(
            inventory.devices["192.0.2.20"].ports, ("443/tcp https Example & Co 1.2",)
        )
        self.assertIsNone(inventory.devices["192.0.2.30"].ports)
        self.assertEqual(
            inventory.devices["192.0.2.30"].port_summary, "no port results returned"
        )
        self.assertEqual(len(inventory.devices), 2)

    def test_service_and_structured_smb_rdp_identity_hints(self):
        details = """<ports>
        <port protocol="tcp" portid="135"><state state="open"/>
          <service name="msrpc" product="Microsoft Windows RPC" hostname="DESKTOP" ostype="Windows" devicetype="general purpose"/>
        </port>
        <port protocol="tcp" portid="3389"><state state="open"/>
          <service name="ms-wbt-server" product="Microsoft Terminal Services"/>
          <script id="rdp-ntlm-info" output="DNS_Computer_Name: wrong.local">
            <elem key="DNS_Computer_Name">DESKTOP.example.local</elem>
            <elem key="NetBIOS_Computer_Name">DESKTOP</elem>
            <elem key="Product_Version">10.0.22631</elem>
          </script>
        </port></ports>
        <hostscript><script id="smb-os-discovery" output="">
          <elem key="os">Windows 11</elem><elem key="server">DESKTOP</elem>
          <elem key="workgroup">WORKGROUP</elem>
        </script></hostscript>"""
        decoder = d.NmapXML(ports=True, source="SERVICES")
        rows = decoder.feed(
            ("<nmaprun>" + xml_host(ports=details) + "</nmaprun>").encode()
        )
        decoder.finish()
        row = rows[0]
        self.assertEqual(row.source, "SERVICES")
        self.assertEqual(row.name, "DESKTOP.example.local")
        self.assertEqual(row.name_rank, 3)
        self.assertIn("Service OS: Windows", row.identity)
        self.assertIn("SMB OS: Windows 11", row.identity)
        self.assertIn("Workgroup: WORKGROUP", row.identity)
        self.assertIn("RDP build: 10.0.22631", row.identity)
        self.assertIn("135/tcp msrpc Microsoft Windows RPC", row.ports)

    def test_service_identity_fallback_is_sanitized_and_ports_do_not_prove_windows(
        self,
    ):
        ports = '<ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" method="table"/></port></ports>'
        decoder = d.NmapXML(ports=True)
        plain = decoder.feed(
            ("<nmaprun>" + xml_host(ports=ports) + "</nmaprun>").encode()
        )[0]
        self.assertEqual(plain.identity, ())
        self.assertEqual(plain.name, "")
        script = '<hostscript><script id="smb-os-discovery" output="OS: Linux&#10;Computer name: nas&#9;server&#10;Workgroup: HOME"/></hostscript>'
        decoder = d.NmapXML(ports=True)
        row = decoder.feed(
            ("<nmaprun>" + xml_host(ports=ports + script) + "</nmaprun>").encode()
        )[0]
        self.assertEqual(row.name, "nas server")
        self.assertIn("SMB OS: Linux", row.identity)

    def test_port_timeouts_missing_results_and_filtered_are_not_closed_ports(self):
        for state in ("closed", "filtered", "open|filtered"):
            decoder = d.NmapXML(ports=True)
            ports = f'<ports><extraports state="{state}" count="200"/></ports>'
            row = decoder.feed(
                ("<nmaprun>" + xml_host(ports=ports) + "</nmaprun>").encode()
            )[0]
            self.assertEqual(row.ports, ())
            self.assertEqual(row.port_summary, f"200 {state}")
            self.assertEqual(row.seen > 0, state == "closed")
        decoder = d.NmapXML(ports=True)
        host = xml_host().replace("<host>", '<host timedout="true">')
        row = decoder.feed(("<nmaprun>" + host + "</nmaprun>").encode())[0]
        self.assertIsNone(row.ports)
        self.assertEqual(row.port_summary, "timed out")
        self.assertEqual(row.seen, 0)

    def test_netbios_names_accept_structured_and_actual_text_output(self):
        scripts = [
            '<script id="nbstat" output="NetBIOS name: WRONG, NetBIOS user: ignored"><elem key="server_name">OFFICE-PC</elem><table key="mac"><elem key="address">00:11:22:33:44:55</elem></table></script>',
            '<script id="nbstat" output="NetBIOS name: OFFICE-PC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: 00:11:22:33:44:55 (Example)"/>',
            '<script id="nbstat" output=""><elem key="server_name">&lt;unknown&gt;</elem><elem key="workstation_name">OFFICE-PC</elem><table key="mac"><elem key="address">00:11:22:33:44:55</elem></table></script>',
        ]
        for script in scripts:
            decoder = d.NmapXML(source="NETBIOS")
            host = xml_host(
                "198.51.100.71", "", ports=f"<hostscript>{script}</hostscript>"
            )
            rows = decoder.feed(("<nmaprun>" + host + "</nmaprun>").encode())
            decoder.finish()
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(
                (row.name, row.name_rank, row.source), ("OFFICE-PC", 2, "NETBIOS")
            )
            self.assertIsNone(row.mac)
            self.assertIsNone(row.ports)
            self.assertEqual(row.identity, ("NetBIOS-reported MAC: 00:11:22:33:44:55",))
            self.assertGreater(row.seen, 0)

    def test_netbios_nonresponses_and_bogus_macs_do_not_prove_presence(self):
        for mac in (
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:01",
            "<unknown>",
        ):
            script = d.ET.Element(
                "script",
                id="nbstat",
                output=f"NetBIOS name: <unknown>, NetBIOS user: ignored, NetBIOS MAC: {mac}",
            )
            self.assertEqual(d.netbios_identity(script), ("", ()))
        for script in (
            "",
            '<hostscript><script id="nbstat" output="ERROR: query timed out"/></hostscript>',
        ):
            decoder = d.NmapXML(source="NETBIOS")
            host = xml_host("192.0.2.20", "", name="cached.local", ports=script)
            self.assertEqual(
                decoder.feed(("<nmaprun>" + host + "</nmaprun>").encode()), []
            )
            self.assertEqual(decoder.finish(), [])
        script = d.ET.Element(
            "script",
            id="nbstat",
            output="NetBIOS name: NAS, NetBIOS MAC: 00:00:00:00:00:00",
        )
        self.assertEqual(d.netbios_identity(script), ("NAS", ()))

    def test_web_title_and_tls_names_are_port_labelled_hints_not_hostnames(self):
        ports = """<ports>
        <port protocol="tcp" portid="80"><state state="open"/>
          <script id="http-title" output="WRONG"><elem key="title">Office &amp;amp; Print</elem></script>
        </port>
        <port protocol="tcp" portid="443"><state state="open"/>
          <script id="http-title" output=""><elem key="title">Admin &amp;#x1b;[2J Console</elem></script>
          <script id="ssl-cert" output="Subject: commonName=WRONG">
            <table key="subject"><elem key="commonName">printer.local</elem></table>
            <table key="issuer"><elem key="commonName">Not the device name</elem></table>
            <table key="extensions"><table>
              <elem key="name">X509v3 Subject Alternative Name</elem>
              <elem key="value">DNS:printer.local, DNS:print.office.local, IP Address:192.0.2.30</elem>
            </table></table>
            <elem key="pem">DO NOT DISPLAY</elem>
          </script>
        </port></ports>"""
        decoder = d.NmapXML(ports=True, source="SERVICES")
        row = decoder.feed(
            ("<nmaprun>" + xml_host(ports=ports) + "</nmaprun>").encode()
        )[0]
        self.assertEqual(row.name, "")
        self.assertIn("HTTP 80/tcp title: Office & Print", row.identity)
        self.assertIn("HTTP 443/tcp title: Admin [2J Console", row.identity)
        self.assertIn("TLS 443/tcp CN: printer.local", row.identity)
        self.assertIn("TLS 443/tcp SAN: DNS:print.office.local", row.identity)
        self.assertIn("TLS 443/tcp SAN: IP Address:192.0.2.30", row.identity)
        for unwanted in ("WRONG", "Not the device name", "DO NOT DISPLAY", "\x1b"):
            self.assertNotIn(unwanted, " ".join(row.identity))

    def test_web_hint_fallback_ignores_errors_and_bounds_certificate_names(self):
        port = d.ET.fromstring("""<port protocol="tcp" portid="8443"><state state="open"/>
          <script id="http-title" output="NAS Admin&#10;Requested resource was /"/>
          <script id="ssl-cert" output="Subject: commonName=nas.local/organizationName=Fixture&#10;Subject Alternative Name: DNS:nas.local, DNS:backup.local&#10;Issuer: commonName=Not a hostname"/>
        </port>""")
        hints = d.web_identity(port)
        self.assertIn("HTTP 8443/tcp title: NAS Admin", hints)
        self.assertIn("TLS 8443/tcp CN: nas.local", hints)
        self.assertIn("TLS 8443/tcp SAN: DNS:backup.local", hints)
        for output in (
            "ERROR: Script execution failed",
            "Did not follow redirect to http://outside.example",
            "Site doesn't have a title",
        ):
            port = d.ET.Element("port", protocol="tcp", portid="80")
            d.ET.SubElement(port, "script", id="http-title", output=output)
            self.assertEqual(d.web_identity(port), [])
        port = d.ET.Element("port", protocol="tcp", portid="443")
        d.ET.SubElement(
            port,
            "script",
            id="ssl-cert",
            output="Subject Alternative Name: "
            + ", ".join(f"DNS:name{i}.local" for i in range(30)),
        )
        self.assertEqual(len(d.web_identity(port)), 8)
        host = d.ET.fromstring(
            xml_host(
                ports='<ports><port protocol="tcp" portid="80"><state state="closed"/><script id="http-title" output="unusable"/></port></ports>'
            )
        )
        self.assertEqual(d.service_identity(host), ("", 0, ()))

    def test_arp_requests_zero_mac_and_multicast_never_create_phantom_targets(self):
        rows = self.packet(
            **{
                "arp.src.proto_ipv4": "192.0.2.20",
                "arp.src.hw_mac": "00:11:22:33:44:20",
            }
        )
        self.assertEqual([(r.ip, r.source) for r in rows], [("192.0.2.20", "ARP")])
        for mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01"):
            self.assertEqual(
                self.packet(
                    **{"arp.src.proto_ipv4": "192.0.2.90", "arp.src.hw_mac": mac}
                ),
                [],
            )

    def test_no_gateway_mac_as_external_host_identity(self):
        inventory = self.inventory(["test-wifi", "198.51.100.20", "--once"])
        device = inventory.merge(
            d.Observation("198.51.100.20", "PACKET", "02:22:33:44:55:66")
        )
        self.assertIsNone(device.mac)
        self.assertEqual(device.vendor, "Unknown")
        default = self.inventory()
        self.assertIsNone(
            default.merge(d.Observation("198.51.100.20", "PACKET", "02:22:33:44:55:66"))
        )
        proxy = default.merge(d.Observation("192.0.2.90", "ARP", "02:22:33:44:55:66"))
        self.assertIsNone(proxy.mac)

    def test_empty_fields_do_not_shift_and_dhcp_ack_is_not_an_offer(self):
        values = {
            "dhcp.ip.your": "192.0.2.40",
            "dhcp.hw.mac_addr": "00:11:22:33:44:40",
            "dhcp.option.hostname": "phone",
            "dhcp.option.dhcp": "5",
        }
        rows = self.packet(**values)
        self.assertEqual([(r.ip, r.name) for r in rows], [("192.0.2.40", "phone")])
        values["dhcp.option.dhcp"] = "2"
        self.assertEqual(self.packet(**values), [])
        self.assertEqual(d.packet_observations("too\tfew", d.BASE_FIELDS), [])

    def test_dns_queries_and_unrelated_answers_are_not_device_names(self):
        values = {
            "eth.src": "00:11:22:33:44:20",
            "ip.src": "192.0.2.20",
            "udp.srcport": "5353",
            "dns.flags.response": "1",
            "dns.count.answers": "1",
            "dns.count.add_rr": "0",
            "dns.resp.name": "printer.local",
            "dns.resp.type": "1",
            "dns.a": "192.0.2.20",
        }
        self.assertEqual(self.packet(**values)[-1].name, "printer.local")
        for change in (
            {"dns.flags.response": "0"},
            {"dns.a": "192.0.2.99"},
            {"dns.count.answers": "2"},
            {"dns.resp.name": "_http._tcp.local"},
        ):
            self.assertFalse(any(r.name for r in self.packet(**(values | change))))

    def test_mdns_multiple_answers_and_additional_records_remain_aligned(self):
        values = {
            "eth.src": "00:11:22:33:44:20",
            "ip.src": "192.0.2.20",
            "udp.srcport": "5353",
            "dns.flags.response": "1",
            "dns.count.answers": "1",
            "dns.count.add_rr": "2",
            "dns.resp.name": "_ipp._tcp.local|printer.local|printer-v6.local",
            "dns.resp.type": "12|1|28",
            "dns.a": "192.0.2.20",
            "dns.aaaa": "2001:db8::20",
        }
        names = [(r.ip, r.name) for r in self.packet(**values) if r.name]
        self.assertEqual(names, [("192.0.2.20", "printer.local")])
        values["ip.src"] = ""
        values["ipv6.src"] = "2001:db8::20"
        self.assertEqual(
            [r.name for r in self.packet(**values) if r.name], ["printer-v6.local"]
        )
        values["dns.resp.name"] += "|ambiguous-name"
        self.assertFalse(any(r.name for r in self.packet(**values)))

    def test_filtered_ports_and_name_lookups_do_not_refresh_cached_presence(self):
        inventory = self.inventory()
        inventory.merge(
            d.Observation("192.0.2.20", "NEIGH-CACHED", "00:11:22:33:44:20")
        )
        inventory.merge(
            d.Observation("192.0.2.20", "NAME", name="cached.local", name_rank=1)
        )
        decoder = d.NmapXML(ports=True)
        rows = (
            decoder.feed(
                (
                    "<nmaprun>"
                    + xml_host(
                        ports='<ports><extraports state="filtered" count="200"/></ports>'
                    )
                    + "</nmaprun>"
                ).encode()
            )
            + decoder.finish()
        )
        for row in rows:
            inventory.merge(row)
        self.assertEqual(inventory.devices["192.0.2.20"].last_seen, 0)
        path = self.path / "filtered.tsv"
        d.write_cache(path, inventory.ordered())
        self.assertEqual(path.read_text(), "")

    def test_vendor_private_mac_and_invalid_addresses(self):
        vendors = d.Vendors(self.vendor_file)
        self.assertEqual(vendors.lookup("00:11:22:33:44:55"), "Fixture Manufacturer")
        self.assertEqual(
            vendors.lookup("02:11:22:33:44:55", "Fake vendor"), "Private/randomized MAC"
        )
        self.assertIsNone(d.mac_address("00:00:00:00:00:00"))
        for value in (
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "ff02::1",
            "not-an-ip",
        ):
            self.assertIsNone(d.address(value))

    def test_dedup_enrichment_and_ip_reassignment(self):
        inventory = self.inventory()
        initial = d.Observation("192.0.2.20", "NMAP", name="old-name", name_rank=1)
        self.assertIsNotNone(inventory.merge(initial))
        self.assertIsNone(
            inventory.merge(dataclasses.replace(initial, seen=initial.seen + 2))
        )
        inventory.merge(d.Observation("192.0.2.20", "ARP", "00:11:22:33:44:20"))
        inventory.merge(d.Observation("192.0.2.20", "PORTS", ports=("443/tcp https",)))
        device = inventory.merge(
            d.Observation("192.0.2.20", "ARP", "00:11:22:33:44:21")
        )
        self.assertEqual(device.name, "")
        self.assertIsNone(device.ports)
        self.assertEqual(device.generation, 1)
        self.assertEqual(device.sources, {"ARP"})

    def test_ipv6_neighbours_only_in_default_scope_and_broadcasts_filtered(self):
        self.assertIsNotNone(
            self.inventory().merge(
                d.Observation("2001:db8::20", "NEIGH-CACHED", "00:11:22:33:44:20")
            )
        )
        self.assertIsNone(
            self.inventory(["test-wifi", "192.0.2.20", "--once"]).merge(
                d.Observation("2001:db8::20", "NEIGH-CACHED")
            )
        )
        for ip in ("192.0.2.0", "192.0.2.255", "192.0.3.20"):
            self.assertIsNone(self.inventory().merge(d.Observation(ip, "PACKET")))

    def test_cache_is_atomic_fresh_validated_and_does_not_refresh_cached_evidence(self):
        path = self.path / "cache.tsv"
        path.write_text(
            "00:11:22:33:44:20\t192.0.2.20\t100\n00:11:22:33:44:21\t192.0.2.21\t995\nlegacy\t192.0.2.99\n"
        )
        current = d.Device(
            "192.0.2.30", "00:11:22:33:44:30", sources={"ARP"}, last_seen=999
        )
        cached = d.Device(
            "192.0.2.40",
            "00:11:22:33:44:40",
            sources={"NEIGH-CACHED", "NAME"},
            last_seen=999,
        )
        d.write_cache(path, [current, cached], ttl=20, now=1000)
        self.assertEqual(
            path.read_text().splitlines(),
            [
                "00:11:22:33:44:21\t192.0.2.21\t995",
                "00:11:22:33:44:30\t192.0.2.30\t999",
            ],
        )
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.path.glob(".netmgr-*")), [])

    def test_ip_reassignment_removes_old_mac_hint_and_expired_observations(self):
        path = self.path / "cache.tsv"
        path.write_text("00:11:22:33:44:20\t192.0.2.20\t990\n")
        replacement = d.Device(
            "192.0.2.20", "00:11:22:33:44:30", sources={"ARP"}, last_seen=999
        )
        expired = d.Device(
            "192.0.2.21", "00:11:22:33:44:21", sources={"ARP"}, last_seen=900
        )
        d.write_cache(path, [replacement, expired], ttl=20, now=1000)
        self.assertEqual(path.read_text(), "00:11:22:33:44:30\t192.0.2.20\t999\n")

    def run_discovery(self, args, runner=None):
        runner = runner or FakeRunner()
        options = d.options_for(["test-wifi", *args])
        engine = d.Discovery(
            options,
            runner,
            d.network_context(options, runner),
            output=io.StringIO(),
            errors=io.StringIO(),
        )
        result = engine.run()
        self.assertFalse(
            any(t.name.startswith("netmgr-") for t in threading.enumerate())
        )
        return result, engine, runner

    def test_once_outputs_final_results_unknown_macs_and_services(self):
        code, engine, runner = self.run_discovery(["--once", "--services"])
        self.assertEqual(code, 0)
        self.assertIn("Final Scan Table:", engine.output.getvalue())
        self.assertIn("192.0.2.30", engine.output.getvalue())
        self.assertIn("443/tcp https Device UI 2", engine.output.getvalue())
        self.assertIn("printer.local", engine.output.getvalue())
        self.assertNotIn("192.0.2.99", engine.inventory.devices)
        scans = [c for c in runner.commands if c[0] == "nmap"]
        self.assertEqual(sum("-sn" in c and "-Pn" not in c for c in scans), 4)
        self.assertTrue(all("-n" in c and "--min-parallelism" not in c for c in scans))
        self.assertTrue(any("-sV" in c and "--version-light" in c for c in scans))
        discovery_output, final_output = engine.output.getvalue().split(
            "Final Scan Table:"
        )
        self.assertIn("Ports/Services (scan status)", discovery_output)
        self.assertIn("443/tcp https Device UI 2", discovery_output)
        self.assertIn("[scanning ports]", discovery_output)
        self.assertIn("[identifying services]", discovery_output)
        self.assertIn("443/tcp https Device UI 2", final_output)
        for command in scans:
            if "-sV" in command:
                self.assertNotIn("--top-ports", command)
                self.assertEqual(command[command.index("-p") + 1], "443")
                self.assertEqual(
                    command[command.index("--script") + 1],
                    "smb-os-discovery,rdp-ntlm-info,http-title,ssl-cert",
                )
                self.assertIn("--script-timeout", command)
                self.assertEqual(
                    command[command.index("--script-args") + 1],
                    "http.max-body-size=65536,http.truncated-ok=true",
                )

    def test_ports_are_visible_before_services_discovery_and_names_finish(self):
        visible, services_started = threading.Event(), threading.Event()

        class Output(io.StringIO):
            def write(self, value):
                result = super().write(value)
                if "443/tcp https" in value:
                    visible.set()
                return result

        runner = FakeRunner()
        original_stream, original_run = runner.stream, runner.run
        options = d.options_for(
            ["test-wifi", "192.0.2.30", "--once", "--services", "--no-passive"]
        )
        engine = d.Discovery(
            options, runner, d.network_context(options, runner), Output(), io.StringIO()
        )

        def streaming(command, stop):
            if "-sn" in command and "-Pn" not in command:
                runner.commands.append(tuple(command))
                yield ("<nmaprun>" + xml_host("192.0.2.30", "")).encode()
                if not services_started.wait(2):
                    raise AssertionError(
                        "service probes waited for discovery to finish"
                    )
                yield b"</nmaprun>"
            else:
                if "-sV" in command:
                    if not visible.wait(2):
                        raise AssertionError(
                            "ports were not printed before version detection"
                        )
                    services_started.set()
                yield from original_stream(command, stop)

        def lookup(command, timeout=5):
            if command[:2] == ["getent", "hosts"] and not services_started.wait(2):
                raise AssertionError("port probes waited for name resolution")
            return original_run(command, timeout)

        runner.stream, runner.run = streaming, lookup
        self.assertEqual(engine.run(), 0)
        self.assertTrue(visible.is_set() and services_started.is_set())
        self.assertLess(
            engine.output.getvalue().index("443/tcp https"),
            engine.output.getvalue().index("Final Scan Table:"),
        )

    def test_service_timeout_or_failure_keeps_earlier_open_ports(self):
        for failure in ("timeout", "error"):
            with self.subTest(failure=failure):
                runner = FakeRunner()
                original = runner.stream

                def streaming(command, stop, failure=failure, original=original):
                    if "-sV" in command:
                        if failure == "error":
                            raise d.CommandError("fixture service failure")
                        host = xml_host(command[-1], "").replace(
                            "<host>", '<host timedout="true">'
                        )
                        yield ("<nmaprun>" + host + "</nmaprun>").encode()
                    else:
                        yield from original(command, stop)

                runner.stream = streaming
                code, engine, _ = self.run_discovery(
                    ["192.0.2.30", "--services", "--no-passive"], runner
                )
                self.assertEqual(code, 0)
                device = engine.inventory.devices["192.0.2.30"]
                self.assertEqual(device.ports, ("443/tcp https",))
                self.assertIn("services", device.probe_status)
                self.assertNotEqual(device.probe_status, "complete")
                self.assertIn(
                    "443/tcp https",
                    engine.output.getvalue().split("Final Scan Table:")[1],
                )

    def test_probes_are_bounded_deduplicated_and_late_reassigned_results_are_ignored(
        self,
    ):
        engine = d.Discovery(
            d.options_for(["--services"]),
            FakeRunner(),
            self.context(),
            io.StringIO(),
            io.StringIO(),
        )
        for index in range(20, 40):
            engine.accept(
                d.Observation(f"192.0.2.{index}", "ARP", f"00:11:22:33:44:{index:02x}")
            )

        class PendingPool:
            def submit(self, *_args):
                return d.concurrent.futures.Future()

        pool = PendingPool()
        engine.collect_probes(pool)
        engine.collect_probes(pool)
        self.assertEqual(len(engine.probes), 4)
        self.assertEqual(len(engine.probe_attempts), 4)
        engine.accept(
            d.Observation(
                "192.0.2.20",
                "SERVICES",
                name="old.local",
                name_rank=3,
                ports=("445/tcp microsoft-ds",),
                identity=("SMB OS: Windows",),
            )
        )
        engine.accept(d.Observation("192.0.2.20", "ARP", "00:11:22:33:44:ee"))
        engine.accept(
            d.ProbeUpdate(
                "192.0.2.20",
                0,
                d.Observation(
                    "192.0.2.20",
                    "SERVICES",
                    name="stale.local",
                    ports=("3389/tcp ms-wbt-server",),
                ),
                "complete",
            )
        )
        device = engine.inventory.devices["192.0.2.20"]
        self.assertEqual(device.name, "")
        self.assertEqual(device.identity, ())
        self.assertIsNone(device.ports)
        self.assertEqual(device.probe_status, "queued")
        for future in engine.probes:
            future.set_result(None)
        engine.collect_probes(pool)
        self.assertIn(("192.0.2.20", 1), engine.probe_attempts)
        engine.probe_progress()
        self.assertIn("Probing: 4 active", engine.output.getvalue())

    def test_interrupt_during_service_detection_keeps_ports_and_stops_new_probes(self):
        runner = FakeRunner()
        original = runner.stream
        options = d.options_for(
            ["test-wifi", "192.0.2.30", "--services", "--no-passive"]
        )
        engine = d.Discovery(
            options,
            runner,
            d.network_context(options, runner),
            io.StringIO(),
            io.StringIO(),
        )

        def streaming(command, stop):
            if "-sV" in command:
                runner.commands.append(tuple(command))
                engine.interrupted = True
                engine.stop.set()
                engine.cancel.set()
                yield b"<nmaprun><host>"
            else:
                yield from original(command, stop)

        runner.stream = streaming
        self.assertEqual(engine.run(), 130)
        device = engine.inventory.devices["192.0.2.30"]
        self.assertEqual(device.ports, ("443/tcp https",))
        self.assertEqual(device.probe_status, "interrupted")
        self.assertIn(
            "443/tcp https", engine.output.getvalue().split("Final Scan Table:")[1]
        )
        self.assertIn(
            "completed port and identity results retained", engine.errors.getvalue()
        )

    def test_routed_windows_identity_appears_live_without_inventing_a_mac(self):
        ip = "198.51.100.71"
        runner = FakeRunner(
            xml=("<nmaprun>" + xml_host(ip, "") + "</nmaprun>").encode()
        )
        original = runner.stream

        def streaming(command, stop):
            if "-sV" in command:
                ports = """<ports><port protocol="tcp" portid="443"><state state="open"/>
                  <service name="https" product="Microsoft IIS" version="10.0" ostype="Windows" hostname="OFFICE-PC"/>
                </port></ports>"""
                yield (
                    "<nmaprun>"
                    + xml_host(ip, "00:11:22:33:44:55", ports=ports)
                    + "</nmaprun>"
                ).encode()
            else:
                yield from original(command, stop)

        runner.stream = streaming
        code, engine, _ = self.run_discovery(
            [ip, "--services", "--no-resolve-hostnames", "--no-passive"], runner
        )
        self.assertEqual(code, 0)
        device = engine.inventory.devices[ip]
        self.assertEqual(device.name, "OFFICE-PC")
        self.assertIsNone(device.mac)
        self.assertEqual(device.vendor, "Unknown")
        live, final = engine.output.getvalue().split("Final Scan Table:")
        for section in (live, final):
            self.assertIn("OFFICE-PC", section)
            self.assertIn("443/tcp https Microsoft IIS 10.0", section)
            self.assertIn("Service OS: Windows", section)
        self.assertIn("Routed target", live)

    def test_filtered_hosts_skip_version_probes_and_show_filtering(self):
        runner = FakeRunner()
        original = runner.stream

        def streaming(command, stop):
            if "-Pn" in command:
                runner.commands.append(tuple(command))
                host = xml_host(
                    command[-1],
                    "",
                    ports='<ports><extraports state="filtered" count="200"/></ports>',
                )
                yield ("<nmaprun>" + host + "</nmaprun>").encode()
            else:
                yield from original(command, stop)

        runner.stream = streaming
        code, engine, _ = self.run_discovery(
            ["192.0.2.30", "--services", "--no-passive"], runner
        )
        self.assertEqual(code, 0)
        self.assertFalse(any("-sV" in command for command in runner.commands))
        self.assertIn("no open ports found (200 filtered)", engine.output.getvalue())

    def test_independent_netbios_finds_routed_names_when_tcp_is_filtered_or_fails(self):
        ip = "198.51.100.71"
        for state in ("filtered", "timedout", "error"):
            with self.subTest(state=state):
                runner = FakeRunner(
                    xml=("<nmaprun>" + xml_host(ip, "") + "</nmaprun>").encode()
                )
                original = runner.stream

                def streaming(
                    command, stop, state=state, original=original, runner=runner
                ):
                    if "+nbstat" in command:
                        runner.commands.append(tuple(command))
                        script = '<hostscript><script id="nbstat" output="NetBIOS name: OFFICE-PC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: 00:11:22:33:44:55 (Example)"/></hostscript>'
                        yield (
                            "<nmaprun>" + xml_host(ip, "", ports=script) + "</nmaprun>"
                        ).encode()
                    elif "-sS" in command:
                        runner.commands.append(tuple(command))
                        if state == "error":
                            raise d.CommandError("fixture TCP failure")
                        host = xml_host(
                            ip,
                            "",
                            ports='<ports><extraports state="filtered" count="200"/></ports>',
                        )
                        if state == "timedout":
                            host = xml_host(ip, "").replace(
                                "<host>", '<host timedout="true">'
                            )
                        yield ("<nmaprun>" + host + "</nmaprun>").encode()
                    else:
                        yield from original(command, stop)

                runner.stream = streaming
                code, engine, _ = self.run_discovery(
                    [ip, "--services", "--no-passive", "--no-resolve-hostnames"], runner
                )
                self.assertEqual(code, 0)
                device = engine.inventory.devices[ip]
                self.assertEqual(device.name, "OFFICE-PC")
                self.assertIn("NETBIOS", device.sources)
                self.assertIsNone(device.mac)
                self.assertEqual(device.vendor, "Unknown")
                self.assertIn(
                    "NetBIOS-reported MAC: 00:11:22:33:44:55", device.identity
                )
                self.assertFalse(any("-sV" in command for command in runner.commands))
                queries = [c for c in runner.commands if "+nbstat" in c]
                self.assertEqual(len(queries), 1)
                command = queries[0]
                self.assertIn("-Pn", command)
                self.assertIn("-sn", command)
                self.assertEqual(command[command.index("--script-timeout") + 1], "4s")
                self.assertNotIn("-sS", command)
                for output in engine.output.getvalue().split("Final Scan Table:"):
                    self.assertIn("OFFICE-PC", output)

    def test_netbios_errors_do_not_prevent_tcp_and_web_probes(self):
        runner = FakeRunner()
        original = runner.stream

        def streaming(command, stop):
            if "+nbstat" in command:
                raise d.CommandError("fixture NetBIOS failure")
            yield from original(command, stop)

        runner.stream = streaming
        code, engine, _ = self.run_discovery(
            ["192.0.2.30", "--services", "--no-passive"], runner
        )
        self.assertEqual(code, 0)
        self.assertIn(
            "NetBIOS query incomplete; continuing TCP probes", engine.errors.getvalue()
        )
        self.assertIn("443/tcp https Device UI 2", engine.output.getvalue())
        self.assertTrue(
            any("http-title,ssl-cert" in " ".join(c) for c in runner.commands)
        )

    def test_interrupt_during_netbios_keeps_names_and_starts_no_tcp_probes(self):
        runner = FakeRunner()
        original = runner.stream
        options = d.options_for(
            ["test-wifi", "192.0.2.30", "--services", "--no-passive"]
        )
        engine = d.Discovery(
            options,
            runner,
            d.network_context(options, runner),
            io.StringIO(),
            io.StringIO(),
        )

        def streaming(command, stop):
            if "+nbstat" in command:
                runner.commands.append(tuple(command))
                engine.interrupted = True
                engine.stop.set()
                engine.cancel.set()
                script = '<hostscript><script id="nbstat" output="NetBIOS name: OFFICE-PC, NetBIOS MAC: &lt;unknown&gt;"/></hostscript>'
                yield ("<nmaprun>" + xml_host("192.0.2.30", "", ports=script)).encode()
            else:
                yield from original(command, stop)

        runner.stream = streaming
        self.assertEqual(engine.run(), 130)
        self.assertEqual(engine.inventory.devices["192.0.2.30"].name, "OFFICE-PC")
        self.assertEqual(
            engine.inventory.devices["192.0.2.30"].probe_status, "interrupted"
        )
        self.assertFalse(any("-sS" in c for c in runner.commands))

    def test_web_hints_are_live_and_never_rename_the_device(self):
        runner = FakeRunner()
        original = runner.stream

        def streaming(command, stop):
            if "-sV" in command:
                ports = """<ports><port protocol="tcp" portid="443"><state state="open"/>
                  <service name="https"/>
                  <script id="http-title" output="Device administration"/>
                  <script id="ssl-cert" output="Subject: commonName=web.internal&#10;Subject Alternative Name: DNS:alt.internal"/>
                </port></ports>"""
                yield (
                    "<nmaprun>" + xml_host(command[-1], "", ports=ports) + "</nmaprun>"
                ).encode()
            else:
                yield from original(command, stop)

        runner.stream = streaming
        code, engine, _ = self.run_discovery(
            ["192.0.2.30", "--services", "--no-passive", "--no-resolve-hostnames"],
            runner,
        )
        self.assertEqual(code, 0)
        self.assertEqual(engine.inventory.devices["192.0.2.30"].name, "")
        for output in engine.output.getvalue().split("Final Scan Table:"):
            self.assertIn("HTTP 443/tcp title: Device administration", output)
            self.assertIn("TLS 443/tcp CN: web.internal", output)
            self.assertIn("TLS 443/tcp SAN: DNS:alt.internal", output)

    def test_services_over_ipv6_skip_legacy_netbios(self):
        runner = FakeRunner()
        options = d.options_for(["test-wifi", "fe80::20", "--services"])
        engine = d.Discovery(
            options,
            runner,
            d.network_context(options, runner),
            io.StringIO(),
            io.StringIO(),
        )
        engine.accept(d.Observation("fe80::20", "NMAP"))
        engine.probe_host("fe80::20", 0)
        commands = [c for c in runner.commands if c[0] == "nmap"]
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertIn("-6", command)
            self.assertEqual(command[-1], "fe80::20%test-wifi")
            self.assertNotIn("+nbstat", command)

    def test_ipv6_probes_use_the_scope_and_ports_only_does_not_run_scripts(self):
        runner = FakeRunner()
        options = d.options_for(["test-wifi", "fe80::20", "--ports"])
        engine = d.Discovery(
            options,
            runner,
            d.network_context(options, runner),
            io.StringIO(),
            io.StringIO(),
        )
        engine.accept(d.Observation("fe80::20", "NMAP"))
        engine.probe_host("fe80::20", 0)
        while not engine.queue.empty():
            engine.accept(engine.queue.get_nowait())
        command = next(c for c in runner.commands if c[0] == "nmap")
        self.assertIn("-6", command)
        self.assertEqual(command[-1], "fe80::20%test-wifi")
        self.assertEqual(command[command.index("-e") + 1], "test-wifi")
        self.assertNotIn("-sV", command)
        self.assertNotIn("--script", command)
        self.assertEqual(engine.inventory.devices["fe80::20"].ports, ("443/tcp https",))

    def test_failed_probe_reports_failure_instead_of_claiming_no_ports(self):
        runner = FakeRunner()
        original = runner.stream

        def streaming(command, stop):
            if "-Pn" in command:
                raise d.CommandError("fixture port failure")
            yield from original(command, stop)

        runner.stream = streaming
        code, engine, _ = self.run_discovery(
            ["192.0.2.30", "--ports", "--no-passive"], runner
        )
        self.assertEqual(code, 0)
        self.assertIsNone(engine.inventory.devices["192.0.2.30"].ports)
        self.assertIn("fixture port failure", engine.errors.getvalue())
        self.assertIn(
            "no port results [ports failed; partial results retained]",
            engine.output.getvalue(),
        )
        self.assertNotIn("no open ports found", engine.output.getvalue())

    def test_hostname_resolution_defaults_on_and_accepts_explicit_flags(self):
        self.assertTrue(d.options_for([]).resolve_hostnames)
        self.assertTrue(d.options_for(["--resolve-hostnames"]).resolve_hostnames)
        self.assertFalse(d.options_for(["--no-resolve-hostnames"]).resolve_hostnames)

    def test_default_scan_resolves_names_and_opt_out_skips_active_lookups(self):
        code, engine, runner = self.run_discovery(["--once"])
        self.assertEqual(code, 0)
        self.assertTrue(any(c[:2] == ("getent", "hosts") for c in runner.commands))
        self.assertEqual(engine.inventory.devices["192.0.2.20"].name, "printer.local")

        code, engine, runner = self.run_discovery(["--once", "--no-resolve-hostnames"])
        self.assertEqual(code, 0)
        self.assertFalse(any(c[:2] == ("getent", "hosts") for c in runner.commands))
        self.assertEqual(engine.inventory.devices["192.0.2.20"].name, "")
        self.assertIn("192.0.2.20", engine.output.getvalue())

    def test_failed_active_scan_is_visible_and_keeps_final_table(self):
        code, engine, _ = self.run_discovery(
            ["--once", "--ports"], FakeRunner(fail_nmap=True)
        )
        self.assertEqual(code, 1)
        self.assertIn("fixture scan failure", engine.errors.getvalue())
        self.assertIn("Final Scan Table:", engine.output.getvalue())

    def test_duration_cancels_workers_and_still_runs_requested_enrichment(self):
        runner = FakeRunner()
        original = runner.stream

        def streaming(command, stop):
            yield from original(command, stop)
            if "-Pn" not in command:
                stop.wait(2)

        runner.stream = streaming
        started = time.monotonic()
        code, engine, _ = self.run_discovery(["--duration", "0.05", "--ports"], runner)
        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 1)
        self.assertIn("Final Scan Table:", engine.output.getvalue())
        self.assertTrue(any("-Pn" in c for c in runner.commands))

    def test_no_passive_never_starts_tshark_and_missing_optional_tools_are_visible(
        self,
    ):
        _, _, runner = self.run_discovery(["--once", "--no-passive"])
        self.assertFalse(any(c[0] == "tshark" for c in runner.commands))
        runner = FakeRunner()
        runner.exists = lambda command: command in {"nmap", "ip"}
        code, engine, _ = self.run_discovery(["--once"], runner)
        self.assertEqual(code, 0)
        self.assertIn("tshark not installed", engine.errors.getvalue())

    def test_name_lookups_are_bounded_deduplicated_and_do_not_delay_discovery(self):
        options = d.options_for(["test-wifi", "--once", "--jobs", "2"])
        engine = d.Discovery(
            options, FakeRunner(), self.context(), io.StringIO(), io.StringIO()
        )
        for i in range(20, 40):
            engine.accept(
                d.Observation(f"192.0.2.{i}", "ARP", f"00:11:22:33:44:{i:02x}")
            )

        class PendingPool:
            def submit(self, _function, _ip):
                return d.concurrent.futures.Future()

        pool = PendingPool()
        engine.collect_names(pool)
        engine.collect_names(pool)
        self.assertEqual(len(engine.names), 4)
        self.assertEqual(len(engine.name_attempts), 4)
        self.assertEqual(len(engine.inventory.devices), 20)

    def test_slow_name_result_cannot_rename_reassigned_ip(self):
        engine = d.Discovery(
            d.options_for(["--once"]),
            FakeRunner(),
            self.context(),
            io.StringIO(),
            io.StringIO(),
        )
        engine.accept(d.Observation("192.0.2.20", "ARP", "00:11:22:33:44:20"))
        future = d.concurrent.futures.Future()
        engine.names[future] = ("192.0.2.20", 0)
        engine.accept(d.Observation("192.0.2.20", "ARP", "00:11:22:33:44:30"))
        future.set_result("old-device.local")
        engine.collect_names(None, schedule=False)
        self.assertEqual(engine.inventory.devices["192.0.2.20"].name, "")

    def test_cli_interspersed_options_and_explicit_large_target_requirement(self):
        args = d.options_for(["--once", "test-wifi", "--ports", "192.0.2.20-25"])
        self.assertEqual(args.targets, ["test-wifi", "192.0.2.20-25"])
        self.assertTrue(d.options_for(["--ports"]).once)
        self.assertFalse(d.options_for(["--ports", "--duration", "10"]).once)
        for argv in (
            ["test-wifi", "--allow-large"],
            ["2001:db8::/64"],
            ["2001:db8::/64", "--allow-large"],
        ):
            with self.assertRaises(ValueError):
                self.context(argv)
        for argv in (
            ["--duration", "nan"],
            ["--jobs", "0"],
            ["--batch-size", "99999"],
            ["--once", "--duration", "2"],
            ["--not-an-option"],
        ):
            with (
                mock.patch("sys.stderr", new=io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                d.options_for(argv)

    def test_runner_isolated_group_preserves_session_and_captures_error_without_live_execution(
        self,
    ):
        class FakePipe:
            closed = False

            def __init__(self, number):
                self.number = number

            def fileno(self):
                return self.number

            def close(self):
                self.closed = True

        class FakeSelector:
            def __init__(self):
                self.keys = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def register(self, fileobj, _events, data):
                self.keys[fileobj] = types.SimpleNamespace(fileobj=fileobj, data=data)

            def unregister(self, fileobj):
                del self.keys[fileobj]

            def get_map(self):
                return self.keys

            def select(self, _timeout):
                return [(value, None) for value in list(self.keys.values())]

        proc = mock.Mock(pid=123456789, stdout=FakePipe(10), stderr=FakePipe(11))
        proc.wait.return_value = 7
        proc.poll.return_value = 7
        data = {
            10: iter([b"fixture output", b""]),
            11: iter([b"fixture capture failed", b""]),
        }
        with (
            mock.patch("subprocess.Popen", return_value=proc) as popen,
            mock.patch("selectors.DefaultSelector", FakeSelector),
            mock.patch("os.read", side_effect=lambda fd, _size: next(data[fd])),
        ):
            stream = d.Runner().stream(["fixture-program"], threading.Event())
            self.assertEqual(next(stream), b"fixture output")
            with self.assertRaisesRegex(d.CommandError, "fixture capture failed"):
                list(stream)
        self.assertEqual(popen.call_args.kwargs["process_group"], 0)
        self.assertNotIn("start_new_session", popen.call_args.kwargs)
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(proc.stdout.closed and proc.stderr.closed)

    def test_runner_cleanup_escalates_stuck_child_without_signalling_real_process(self):
        proc = mock.Mock(pid=123456789, stdout=mock.Mock(), stderr=mock.Mock())
        proc.poll.return_value = None
        proc.wait.side_effect = [subprocess.TimeoutExpired("fixture", 2), 0]
        with (
            mock.patch("subprocess.Popen", return_value=proc),
            mock.patch(
                "selectors.DefaultSelector",
                side_effect=RuntimeError("fixture parser failed"),
            ),
            mock.patch("os.killpg") as signal_group,
            self.assertRaisesRegex(RuntimeError, "fixture parser failed"),
        ):
            list(d.Runner().stream(["fixture-program"], threading.Event()))
        self.assertEqual(
            signal_group.call_args_list,
            [
                mock.call(proc.pid, d.signal.SIGTERM),
                mock.call(proc.pid, d.signal.SIGKILL),
            ],
        )
        proc.stdout.close.assert_called_once()
        proc.stderr.close.assert_called_once()

    def test_runner_does_not_spawn_after_cancellation(self):
        cancelled = threading.Event()
        cancelled.set()
        self.assertEqual(list(d.Runner().stream(["fixture-program"], cancelled)), [])

    def test_packet_worker_partial_lines_and_repeat_suppression(self):
        fields = d.BASE_FIELDS + d.DHCP_FIELDS + d.DNS_FIELDS
        values = {
            "arp.src.proto_ipv4": "192.0.2.20",
            "arp.src.hw_mac": "00:11:22:33:44:20",
        }
        row = "\t".join(values.get(field, "") for field in fields) + "\n"
        data = (row * 100).encode()
        runner = FakeRunner()

        def chunks(command, _stop):
            self.assertEqual(command[0], "tshark")
            self.assertIn("occurrence=a", command)
            self.assertNotIn("-I", command)
            for offset in range(0, len(data), 23):
                yield data[offset : offset + 23]

        runner.stream = chunks
        engine = d.Discovery(
            d.options_for(["--once"]),
            runner,
            self.context(),
            io.StringIO(),
            io.StringIO(),
        )
        engine.packets()
        self.assertEqual(engine.queue.qsize(), 1)
        observed = engine.queue.get_nowait()
        self.assertEqual(
            (observed.ip, observed.mac, observed.source),
            ("192.0.2.20", "00:11:22:33:44:20", "ARP"),
        )
        self.assertIn("tshark exited unexpectedly", engine.errors.getvalue())

    def test_interruption_preserves_results_without_starting_port_probes(self):
        runner = FakeRunner()
        original_stream = runner.stream
        options = d.options_for(["test-wifi", "--once", "--ports", "--no-passive"])
        engine = d.Discovery(
            options,
            runner,
            d.network_context(options, runner),
            io.StringIO(),
            io.StringIO(),
        )

        def interrupted_stream(command, stop):
            yield from original_stream(command, stop)
            engine.interrupted = True
            engine.cancel.set()
            stop.set()

        runner.stream = interrupted_stream
        self.assertEqual(engine.run(), 130)
        self.assertIn("192.0.2.20", engine.output.getvalue())
        self.assertIn("Final Scan Table:", engine.output.getvalue())
        self.assertFalse(any("-Pn" in c for c in runner.commands))

    def test_input_validation_before_authentication_and_sanitized_names(self):
        runner = FakeRunner()
        with mock.patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(d.main(["test-wifi", "192.0.2.999"], runner), 1)
        self.assertFalse(runner.authenticated)
        self.assertEqual(d.clean("printer\x1b[2J\n\tname"), "printer [2J name")


if __name__ == "__main__":
    unittest.main()
