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
