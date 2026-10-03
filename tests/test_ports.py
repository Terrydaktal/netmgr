"""Offline process fixtures. Real process inspection and commands are forbidden."""

import csv
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "port_details", Path(__file__).resolve().parents[1] / "lib" / "ports.py"
)
p = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = p
SPEC.loader.exec_module(p)

CID = "abcdef0123456789" * 4
SOCKETS = """Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=2044,fd=6))
tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=2044,fd=7))
tcp LISTEN 0 5 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=300,fd=3))
tcp LISTEN 0 2048 *:3999 *:* users:(("next-server (v1",pid=400,fd=22))
tcp LISTEN 0 128 *:8975 *:* users:(("rootlessport",pid=500,fd=9))
tcp ESTAB 0 0 192.0.2.1:22 192.0.2.2:54000 users:(("sshd-session",pid=2045,fd=3))
udp UNCONN 0 0 0.0.0.0:5355 0.0.0.0:* users:(("systemd-resolve",pid=1649,fd=14))
tcp LISTEN 0 128 127.0.0.1:9000 0.0.0.0:*
tcp LISTEN 0 128 127.0.0.1:9001 0.0.0.0:* users:(("worker name",pid=600,fd=3),("other",pid=601,fd=4))
"""


class FakeRunner:
    def __init__(self, response="", error=None):
        self.response = response
        self.error = error
        self.calls = []

    def run(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if self.error:
            raise p.CommandError(self.error)
        if callable(self.response):
            return self.response(command)
        return self.response


class PortDetailsTests(unittest.TestCase):
    @staticmethod
    def column_rows(text):
        return list(csv.DictReader(io.StringIO(text), delimiter="\t"))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "uptime").write_text("1000.0 2000.0\n")
        patcher = mock.patch.object(p.os, "sysconf", return_value=100)
        self.clock_ticks = patcher.start()
        self.addCleanup(patcher.stop)

        def fixture_user(uid):
            names = {0: "root", 1000: "fixture"}
            return mock.Mock(pw_name=names[uid])

        patcher = mock.patch.object(p.pwd, "getpwuid", side_effect=fixture_user)
        self.user_lookup = patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("run", "Popen"):
            patcher = mock.patch.object(
                subprocess,
                name,
                side_effect=AssertionError("real subprocess forbidden"),
            )
            patcher.start()
            self.addCleanup(patcher.stop)
        original_read = p.read_limited

        def fixture_read(path, *args):
            if not Path(path).is_relative_to(self.root):
                raise AssertionError(f"non-fixture metadata read: {path}")
            return original_read(path, *args)

        patcher = mock.patch.object(p, "read_limited", side_effect=fixture_read)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(
            p.shutil, "which", side_effect=lambda name: f"/fixture/{name}"
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def process(
        self,
        pid,
        comm,
        argv,
        exe,
        cwd="project",
        cgroup="0::/user.slice/user-1000.slice/session-2.scope\n",
        uid=1000,
        euid=None,
        fds=(3,),
        ppid=0,
        started=12345,
    ):
        path = self.root / str(pid)
        path.mkdir()
        (path / "stat").write_text(
            f"{pid} ({comm}) S {ppid} " + "0 " * 17 + f"{started} 0 0\n"
        )
        (path / "status").write_text(
            f"Name:\t{comm}\nUid:\t{uid}\t{uid if euid is None else euid}\t{uid}\t{uid}\n"
        )
        (path / "comm").write_text(comm + "\n")
        (path / "cmdline").write_bytes("\0".join(argv).encode() + b"\0")
        (path / "cgroup").write_text(cgroup)
        (path / "exe").symlink_to(exe)
        project = self.root / cwd
        project.mkdir(exist_ok=True)
        (path / "cwd").symlink_to(project)
        (path / "fd").mkdir()
        for fd in fds:
            (path / "fd" / str(fd)).symlink_to(f"socket:[{pid * 100 + fd}]")
        return path, project

    def collect(self, pid, fds=(3,)):
        return p.collect_processes([{"pid": pid, "fds": list(fds)}], self.root)[
            str(pid)
        ]

    def container_listing(
        self, name="elab-wp-v", ports="0.0.0.0:8975->80/tcp", cid=CID
    ):
        return (
            "\t".join(
                json.dumps(value)
                for value in (
                    cid,
                    name,
                    "docker.io/library/wordpress:php7.4-apache",
                    ports,
                )
            )
            + "\n"
        )

    def test_oneline_tcp_info_does_not_change_socket_rows_or_process_owners(self):
        enriched = "\n".join(
            line + "\t cubic rto:201 bytes_received:1048576 bytes_acked:2048"
            if line.startswith("tcp ")
            else line
            for line in SOCKETS.splitlines()
        )
        for all_details in (False, True):
            self.assertEqual(
                p.parse_sockets(enriched, all_details),
                p.parse_sockets(SOCKETS, all_details),
            )

    def test_snapshot_selection_groups_both_families_and_shared_owners(self):
        selected = p.parse_sockets(SOCKETS)
        requests = {item["pid"]: item["fds"] for item in p.process_requests(selected)}
        self.assertEqual(requests[2044], [6, 7])
        self.assertNotIn(2045, requests)
        self.assertIn(1649, requests)
        self.assertIn(600, requests)
        self.assertIn(601, requests)
        self.assertIn(
            2045,
            {
                item["pid"]
                for item in p.process_requests(p.parse_sockets(SOCKETS, True))
            },
        )
        text = p.format_process_columns(selected, {}, {}, [], all_details=True)
        rows = self.column_rows(text)
        self.assertEqual(len(rows), len(selected))
        self.assertEqual([row["PID"] for row in rows[:2]], ["2044", "2044"])
        self.assertEqual([row["Row"] for row in rows[:2]], ["1", "2"])
        self.assertEqual(rows[-1]["PID"], "600;601")
        self.assertEqual(rows[-1]["Executable"], "worker name | other")
        self.assertNotIn("Process", rows[0])
        self.assertIn("process owner unavailable", text)

    def test_proc_metadata_preserves_command_args_and_directory(self):
        _, cwd = self.process(
            300,
            "python3",
            ["/venv/bin/python3", "whisper_service.py", "--label", "two  words"],
            "/usr/bin/python3.14",
        )
        info = self.collect(300)
        self.assertEqual(info["exe"], "/usr/bin/python3.14")
        self.assertEqual(info["cwd"], str(cwd))
        self.assertEqual(info["argv"][-1], "two  words")
        details = dict(p.application_details(info))
        self.assertEqual(details["Script"], "whisper_service.py")
        self.assertEqual(details["Runtime"], "Python 3.14")
        self.assertNotIn("Description", details)
        self.assertIn(
            "'two  words'",
            p.format_process_columns(
                p.parse_sockets(SOCKETS), {"300": info}, {}, [], verbose=True
            ),
        )
        rows = self.column_rows(
            p.format_process_columns(p.parse_sockets(SOCKETS), {"300": info}, {}, [])
        )
        row = next(row for row in rows if row["PID"] == "300")
        self.assertEqual(list(row), ["Row", "PID", "User", "Age", "App", "CWD"])
        self.assertEqual(row["User"], "fixture")
        self.assertEqual(row["Age"], "14m36s")
        self.assertEqual(row["App"], "python3.14")
        self.assertEqual(row["CWD"], str(cwd))
        verbose_rows = self.column_rows(
            p.format_process_columns(
                p.parse_sockets(SOCKETS), {"300": info}, {}, [], verbose=True
            )
        )
        self.assertEqual(
            next(row for row in verbose_rows if row["PID"] == "300")["Command"],
            "python3 whisper_service.py --label 'two  words'",
        )
        self.assertEqual(
            p.short_command(
                [
                    "/venv/bin/python3",
                    "/project/whisper_service.py",
                    "--config=/tmp/config.json",
                    "https://example.test/a/b",
                ]
            ),
            "python3 whisper_service.py --config=.../config.json https://example.test/a/b",
        )

    def test_parent_chain_uses_executable_names_and_shared_parent_cache(self):
        self.process(1, "systemd", ["systemd"], "/usr/lib/systemd/systemd", started=1)
        self.process(
            100,
            "xfce4-terminal",
            ["terminal"],
            "/usr/bin/xfce4-terminal",
            ppid=1,
            started=10,
        )
        self.process(200, "fish", ["fish"], "/usr/bin/fish", ppid=100, started=20)
        self.process(
            300,
            "python3",
            ["python3", "service.py"],
            "/usr/bin/python3.14",
            ppid=200,
            started=30,
        )
        self.process(
            301, "node", ["node", "server.js"], "/usr/bin/node", ppid=200, started=31
        )
        with mock.patch.object(p, "parent_node", wraps=p.parent_node) as read_parent:
            processes = p.collect_processes(
                [{"pid": 300, "fds": [3]}, {"pid": 301, "fds": [3]}], self.root
            )
        self.assertEqual(
            processes["300"]["chain"], "python3.14<-fish<-xfce4-terminal<-systemd"
        )
        self.assertEqual(
            processes["301"]["chain"], "node<-fish<-xfce4-terminal<-systemd"
        )
        self.assertEqual(read_parent.call_count, 3)
        self.assertEqual(processes["300"]["chain_note"], "")
        with mock.patch.object(p, "parent_node", wraps=p.parent_node) as read_parent:
            p.collect_processes(
                [{"pid": 300, "fds": [3]}, {"pid": 200, "fds": [3]}], self.root
            )
        self.assertEqual(read_parent.call_count, 2)

    def test_parent_chain_is_explicit_when_parents_are_missing_or_reused(self):
        self.process(
            300, "python3", ["python3"], "/usr/bin/python3.14", ppid=200, started=30
        )
        info = self.collect(300)
        self.assertEqual(info["chain"], "python3.14<-?")
        self.assertIn("unavailable", info["chain_note"])
        parent, _ = self.process(
            200, "fish", ["fish"], "/usr/bin/fish", ppid=999, started=20
        )
        (parent / "exe").unlink()
        info = self.collect(300)
        self.assertEqual(info["chain"], "python3.14<-fish<-?")
        self.assertIn("unavailable", info["chain_note"])
        original_stat = p.process_stat
        with mock.patch.object(
            p,
            "process_stat",
            side_effect=lambda path: (40, 0) if path == parent else original_stat(path),
        ):
            info = self.collect(300)
        self.assertEqual(info["chain"], "python3.14<-?")
        self.assertIn("PID changed", info["chain_note"])
        rows = self.column_rows(
            p.format_process_columns(
                p.parse_sockets(SOCKETS), {"300": info}, {}, [], all_details=True
            )
        )
        row = next(row for row in rows if row["PID"] == "300")
        self.assertIn("PID changed", row["Metadata"])
        self.assertEqual(row["App"], "python3.14<-?")

    def test_parent_chain_rejects_changing_parents_and_bounds_cycles(self):
        self.process(300, "python3", ["python3"], "/usr/bin/python3.14", ppid=200)
        parent, _ = self.process(200, "fish", ["fish"], "/usr/bin/fish", ppid=300)
        info = self.collect(300)
        self.assertEqual(info["chain"], "python3.14<-fish<-?")
        self.assertIn("cycle", info["chain_note"])
        chain, note = p.process_chain(info, self.root, {}, max_depth=1)
        self.assertEqual(chain, "python3.14<-?")
        self.assertIn("depth limit", note)
        original_stat = p.process_stat
        identities = iter([(10, 0), (11, 0)])
        with mock.patch.object(
            p,
            "process_stat",
            side_effect=lambda path: (
                next(identities) if path == parent else original_stat(path)
            ),
        ):
            info = self.collect(300)
        self.assertEqual(info["chain"], "python3.14<-?")
        self.assertIn("changed", info["chain_note"])

    def test_python_module_and_options_are_not_confused_with_scripts(self):
        info = {
            "exe": "/usr/bin/python3",
            "argv": [
                "python3",
                "-W",
                "ignore",
                "-X",
                "dev",
                "-m",
                "http.server",
                "8080",
            ],
        }
        details = dict(p.application_details(info))
        self.assertEqual(details["Module"], "http.server")
        self.assertIn("static HTTP", details["Description"])
        info["argv"] = ["python3", "server.py", "-m", "http.server"]
        details = dict(p.application_details(info))
        self.assertEqual(details["Script"], "server.py")
        self.assertNotIn("Module", details)

    def test_next_server_title_and_project_metadata(self):
        _, cwd = self.process(
            400,
            "next-server (v1",
            ["next-server (v14.2.35)"],
            "/usr/bin/node",
            cwd="nextjs_test",
            fds=(22,),
        )
        (cwd / "package.json").write_text(
            json.dumps(
                {
                    "name": "nextjs_test",
                    "description": "Example app",
                    "scripts": {"start": "must never execute"},
                }
            )
        )
        info = self.collect(400, (22,))
        details = dict(p.application_details(info))
        self.assertEqual(details["Application"], "Next.js 14.2.35")
        self.assertEqual(details["Project"], "nextjs_test")
        self.assertEqual(details["Project Description"], "Example app")
        self.assertNotIn("scripts", info["project"])

    def test_project_toml_is_metadata_only(self):
        _, cwd = self.process(300, "python3", ["python3", "app.py"], "/usr/bin/python3")
        (cwd / "pyproject.toml").write_text(
            '[project]\nname="assistant"\ndescription="Local assistant"\n'
        )
        info = self.collect(300)
        self.assertEqual(info["project"]["description"], "Local assistant")
        (cwd / "pyproject.toml").write_text("invalid = [")
        self.assertEqual(self.collect(300)["project"], {})

    def test_missing_cgroup_and_oversized_project_preserve_process_details(self):
        path, cwd = self.process(
            300, "python3", ["python3", "app.py"], "/usr/bin/python3"
        )
        (path / "cgroup").unlink()
        (cwd / "pyproject.toml").write_text("#" * 262145)
        info = self.collect(300)
        self.assertEqual(info["exe"], "/usr/bin/python3")
        self.assertEqual(info["unit"], "")
        self.assertEqual(info["project"], {})

    def test_main_combines_snapshot_services_and_rootless_containers(self):
        self.process(
            2044,
            "sshd",
            ["/usr/bin/sshd", "-D"],
            "/usr/bin/sshd",
            cgroup="0::/system.slice/sshd.service\n",
            uid=0,
            fds=(6, 7),
        )
        self.process(
            300, "python3", ["python3", "-m", "http.server", "8080"], "/usr/bin/python3"
        )
        self.process(500, "rootlessport", ["rootlessport"], "/usr/bin/podman", fds=(9,))
        requests = p.process_requests(p.parse_sockets(SOCKETS))
        processes = p.collect_processes(requests, self.root)

        def response(command):
            if command[0] == "sudo":
                return json.dumps(
                    {"processes": processes, "containers": [], "notes": []}
                )
            if command[0] == "systemctl":
                return "Id=sshd.service\nDescription=OpenSSH Daemon\nLoadState=loaded\n"
            if command[0] == "podman":
                return self.container_listing()
            raise AssertionError(f"unexpected fixture command: {command}")

        for flags in (
            [],
            ["--verbose"],
            ["-v"],
            ["--all-details"],
            ["--verbose", "--all-details"],
        ):
            runner = FakeRunner(response)
            with (
                mock.patch.object(p, "Runner", return_value=runner),
                mock.patch.object(p.os, "geteuid", return_value=1000),
                mock.patch.object(p.sys, "stdin", io.StringIO(SOCKETS)),
                mock.patch.object(p.sys, "stdout", new_callable=io.StringIO) as output,
                mock.patch.object(p.sys, "stderr", new_callable=io.StringIO) as errors,
            ):
                self.assertEqual(p.main(flags), 0)
            rows = self.column_rows(output.getvalue())
            by_pid = {row["PID"]: row for row in rows}
            if "--all-details" in flags:
                self.assertEqual(
                    by_pid["2044"]["Description"], "OpenSSH Daemon (systemd)"
                )
                self.assertEqual(by_pid["300"]["Script/Module"], "module: http.server")
                self.assertIn("elab-wp-v", by_pid["500"]["Container"])
                self.assertEqual(by_pid["500"]["Forwarding"], "*:8975 -> 80/tcp")
                self.assertEqual(list(rows[0])[-2:], ["Command", "Description"])
                expected_commands = ["sudo", "systemctl", "podman"]
            else:
                columns = ["Row", "PID", "User", "Age", "App", "CWD"] + (
                    ["Command"] if flags else []
                )
                self.assertEqual(list(rows[0]), columns)
                if flags:
                    self.assertEqual(
                        by_pid["300"]["Command"], "python3 -m http.server 8080"
                    )
                self.assertEqual(by_pid["500"]["CWD"], str(self.root / "project"))
                expected_commands = ["sudo"]
            self.assertEqual(by_pid["300"]["App"], "python3")
            self.assertEqual(by_pid["300"]["User"], "fixture")
            self.assertEqual(by_pid["2044"]["User"], "root")
            self.assertEqual(by_pid["300"]["Age"], "14m36s")
            self.assertEqual(
                "--all-details" in runner.calls[0][0], "--all-details" in flags
            )
            self.assertEqual(sum(row["PID"] == "2044" for row in rows), 2)
            self.assertIn("2045", by_pid)
            self.assertEqual(
                [command[0] for command, _ in runner.calls], expected_commands
            )
            self.assertEqual(errors.getvalue(), "")

    def test_vanished_and_changed_processes_do_not_get_an_identity(self):
        self.assertIn("unavailable", self.collect(999)["error"])
        path, _ = self.process(
            300, "name ) with spaces", ["python3", "app.py"], "/usr/bin/python3"
        )
        self.assertEqual(p.process_stat(path), (12345, 0))
        with mock.patch.object(p, "process_stat", side_effect=[(1, 0), (2, 0)]):
            info = self.collect(300)
        self.assertIn("changed", info["error"])
        self.assertNotIn("exe", info)
        with mock.patch.object(p, "process_stat", side_effect=[(1, 20), (1, 21)]):
            self.assertIn("changed", self.collect(300)["error"])
        with mock.patch.object(
            p.os, "readlink", side_effect=PermissionError("fixture denial")
        ):
            self.assertIn("inaccessible", self.collect(300)["error"])

    def test_regular_file_fd_is_not_socket_ownership(self):
        path, _ = self.process(
            300, "python3", ["python3", "app.py"], "/usr/bin/python3"
        )
        (path / "fd/3").unlink()
        (path / "fd/3").symlink_to("/tmp/output.txt")
        self.assertIn("ownership changed", self.collect(300)["error"])
        with self.assertRaises(ValueError):
            p.collect_processes([{"pid": "../secret", "fds": [3]}], self.root)

    def test_cgroup_selects_service_and_container_owner(self):
        system = p.cgroup_identity("0::/system.slice/sshd.service\n")
        self.assertEqual(system["unit"], "sshd.service")
        self.assertFalse(system["user_unit"])
        user = p.cgroup_identity(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/whisper.service\n"
        )
        self.assertEqual(user["unit"], "whisper.service")
        self.assertTrue(user["user_unit"])
        identity = p.cgroup_identity(
            f"0::/user.slice/user-1000.slice/user@1000.service/libpod-{CID}.scope/container\n"
        )
        self.assertEqual(
            (identity["container_id"], identity["engine"], identity["container_owner"]),
            (CID, "podman", 1000),
        )
        self.assertEqual(identity["unit"], "")
        self.assertEqual(
            p.cgroup_identity(f"2:cpu:/docker/{CID}\n")["engine"], "docker"
        )
        self.assertEqual(
            p.cgroup_identity(
                f"0::/system.slice/containers.service/libpod-{CID}.scope/system.slice/sshd.service\n"
            )["unit"],
            "containers.service",
        )

    def test_service_descriptions_are_batched_by_manager(self):
        processes = {
            "1": p.cgroup_identity("0::/system.slice/sshd.service\n"),
            "2": p.cgroup_identity("0::/system.slice/sshd.service\n"),
            "3": p.cgroup_identity("0::/system.slice/systemd-resolved.service\n"),
            "4": p.cgroup_identity(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/whisper.service\n"
            ),
            "5": p.cgroup_identity(
                "0::/user.slice/user-2000.slice/user@2000.service/app.slice/private.service\n"
            ),
        }
        runner = FakeRunner(
            lambda command: (
                "Id=whisper.service\nDescription=Transcription service\nLoadState=loaded\n"
                if "--user" in command
                else "Id=sshd.service\nDescription=OpenSSH Daemon\nLoadState=loaded\n\nId=systemd-resolved.service\nDescription=Network Name Resolution\nLoadState=loaded\n"
            )
        )
        descriptions, notes = p.unit_descriptions(processes, runner, 1000)
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(runner.calls[0][0].count("sshd.service"), 1)
        self.assertNotIn("private.service", str(runner.calls))
        self.assertEqual(descriptions[(False, "sshd.service")], "OpenSSH Daemon")
        self.assertEqual(
            descriptions[(True, "whisper.service")], "Transcription service"
        )
        self.assertEqual(notes, [])
        descriptions, notes = p.unit_descriptions(
            processes, FakeRunner(error="timeout"), 1000
        )
        self.assertEqual(descriptions, {})
        self.assertTrue(notes)

    def test_rootless_podman_uses_owner_and_local_runtime_once(self):
        info = {
            "uid": 1000,
            "exe": "/usr/bin/podman",
            "argv": ["rootlessport"],
            "comm": "rootlessport",
        }
        processes = {"500": info, "501": info}
        runner = FakeRunner(self.container_listing())
        self.assertEqual(p.container_inventory(processes, runner, 0), ([], []))
        with mock.patch.dict(
            os.environ,
            {"CONTAINER_HOST": "ssh://remote", "CONTAINER_CONNECTION": "remote"},
        ):
            containers, notes = p.container_inventory(processes, runner, 1000)
        self.assertEqual(len(runner.calls), 1)
        self.assertIn("--remote=false", runner.calls[0][0])
        self.assertNotIn("CONTAINER_HOST", runner.calls[0][1]["env"])
        self.assertEqual(notes, [])
        matches = p.match_containers(info, p.parse_sockets(SOCKETS), containers)
        self.assertEqual(matches[0][0]["name"], "elab-wp-v")
        self.assertEqual(matches[0][1], "published-port match")
        output = p.format_process_columns(
            p.parse_sockets(SOCKETS), {"500": info}, {}, containers, all_details=True
        )
        self.assertIn("wordpress:php7.4-apache", output)
        self.assertIn("*:8975 -> 80/tcp", output)

    def test_container_identity_requires_unique_uid_protocol_address_match(self):
        containers = p.parse_containers(self.container_listing(), "podman", 1000)
        sockets = p.parse_sockets(SOCKETS)
        info = {"uid": 1000, "exe": "/usr/bin/rootlessport", "argv": ["rootlessport"]}
        self.assertEqual(
            p.match_containers(dict(info, uid=2000), sockets, containers), []
        )
        self.assertEqual(
            p.match_containers(
                dict(info, exe="/usr/bin/python3", argv=["python3"]),
                sockets,
                containers,
            ),
            [],
        )
        duplicate = p.parse_containers(
            self.container_listing("second", cid="a" * 64), "podman", 1000
        )
        self.assertEqual(p.match_containers(info, sockets, containers + duplicate), [])
        other_protocol = p.parse_containers(
            self.container_listing(ports="0.0.0.0:8975->80/udp"), "podman", 1000
        )
        self.assertEqual(p.match_containers(info, sockets, other_protocol), [])
        specific = [p.Socket("tcp", "LISTEN", "127.0.0.2:8975", "*:*", ())]
        other_address = p.parse_containers(
            self.container_listing(ports="127.0.0.1:8975->80/tcp"), "podman", 1000
        )
        self.assertEqual(p.match_containers(info, specific, other_address), [])
        cgroup_info = dict(
            info, engine="podman", container_owner=1000, container_id=CID
        )
        self.assertEqual(
            p.match_containers(cgroup_info, sockets, containers + duplicate)[0][1],
            "process cgroup",
        )

    def test_container_port_ranges_ipv6_and_exposed_only_ports(self):
        mappings = p.port_mappings(
            "[::]:8975-8977->80-82/tcp, 0.0.0.0:53->53/udp, 9000/tcp"
        )
        self.assertEqual(len(mappings), 2)
        self.assertEqual(
            mappings[0],
            {
                "host": "::",
                "first": 8975,
                "last": 8977,
                "target": 80,
                "protocol": "tcp",
            },
        )
        self.assertEqual(p.port_mappings("*:70000->80/tcp, *:9000-9010->80/tcp"), [])
        self.assertFalse(p.same_binding("::1", "0.0.0.0"))
        self.assertTrue(p.same_binding("::", "::"))
        self.assertTrue(p.same_binding("*", "0.0.0.0"))

    def test_docker_uses_local_socket_and_decodes_json_names(self):
        runner = FakeRunner(self.container_listing(name=["example"]))
        info = {"uid": 0, "exe": "/usr/bin/docker-proxy", "argv": ["docker-proxy"]}
        with mock.patch.dict(
            os.environ,
            {"DOCKER_CONTEXT": "remote", "DOCKER_HOST": "tcp://example:2376"},
        ):
            containers, _ = p.container_inventory({"10": info}, runner, 0)
        self.assertIn("unix:///var/run/docker.sock", runner.calls[0][0])
        self.assertNotIn("DOCKER_CONTEXT", runner.calls[0][1]["env"])
        self.assertEqual(containers[0]["name"], "example")

    def test_privileged_snapshot_uses_one_noninteractive_request(self):
        requests = p.process_requests(p.parse_sockets(SOCKETS))
        runner = FakeRunner(
            json.dumps(
                {"processes": {"2044": {"comm": "sshd"}}, "containers": [], "notes": []}
            )
        )
        processes, _, _ = p.metadata_snapshot(requests, runner, 1000)
        command, kwargs = runner.calls[0]
        self.assertEqual(command[:2], ["sudo", "-n"])
        self.assertIn("-I", command)
        self.assertEqual(json.loads(kwargs["input_text"]), requests)
        self.assertEqual(processes["2044"]["comm"], "sshd")
        self.assertEqual(len(runner.calls), 1)
        with mock.patch.object(
            p,
            "collect_processes",
            return_value={"2044": {"error": "permission denied"}},
        ):
            processes, _, notes = p.metadata_snapshot(
                requests, FakeRunner(error="not authorized"), 1000
            )
        self.assertIn("permission denied", processes["2044"]["error"])
        self.assertIn("privileged process details unavailable", notes[0])

    def test_runner_timeout_and_stdin_are_bounded(self):
        with mock.patch.object(
            subprocess, "run", return_value=mock.Mock(stdout="fixture")
        ) as run:
            self.assertEqual(p.Runner().run(["fixture"], input_text="input"), "fixture")
            self.assertEqual(run.call_args.kwargs["input"], "input")
            self.assertLessEqual(run.call_args.kwargs["timeout"], 2)
            self.assertNotIn("shell", run.call_args.kwargs)
        with (
            mock.patch.object(
                subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", 2)
            ),
            self.assertRaisesRegex(p.CommandError, "timed out"),
        ):
            p.Runner().run(["fixture"])
        with self.assertRaisesRegex(p.CommandError, "budget"):
            p.Runner(budget=-1).run(["fixture"])

    def test_control_characters_are_removed_and_known_descriptions_are_shown(self):
        info = {
            "comm": "sshd\x1b[31m",
            "exe": "/usr/bin/sshd",
            "argv": ["sshd", "-D", "[listener]"],
            "cwd": "/\nforged row",
            "unit": "sshd.service",
            "user_unit": False,
        }
        text = p.format_process_columns(
            p.parse_sockets(SOCKETS),
            {"2044": info},
            {(False, "sshd.service"): "OpenSSH daemon"},
            [],
            all_details=True,
        )
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\nforged", text)
        self.assertIn("OpenSSH daemon (systemd)", text)
        self.assertIn("sshd.service (system)", text)
        self.assertEqual(self.column_rows(p.format_process_columns([], {}, {}, [])), [])

    def test_empty_snapshot_needs_no_inspection_and_connected_rows_get_columns(self):
        with (
            mock.patch.object(p.sys, "stdin", io.StringIO("")),
            mock.patch.object(p.sys, "stdout", new_callable=io.StringIO) as output,
            mock.patch.object(
                p,
                "metadata_snapshot",
                side_effect=AssertionError("unexpected inspection"),
            ),
            mock.patch.object(p.os, "geteuid", return_value=1000),
        ):
            self.assertEqual(p.main([]), 0)
            self.assertEqual(self.column_rows(output.getvalue()), [])
        text = p.format_process_columns(
            p.parse_sockets(SOCKETS, True),
            {"2045": {"comm": "sshd-session", "argv": ["sshd-session"]}},
            {},
            [],
        )
        row = next(row for row in self.column_rows(text) if row["PID"] == "2045")
        self.assertEqual(row["Row"], "6")
        self.assertEqual(row["App"], "sshd-session<-?")
        self.assertEqual(row["CWD"], "-")
        self.assertEqual(row["User"], "-")
        self.assertEqual(row["Age"], "-")
        self.assertNotIn("Command", row)

    def test_user_is_effective_account_and_numeric_ids_remain_available(self):
        self.process(300, "python3", ["python3"], "/usr/bin/python3", uid=1000, euid=0)
        info = self.collect(300)
        self.assertEqual((info["uid"], info["euid"]), (1000, 0))
        for detailed in (False, True):
            rows = self.column_rows(
                p.format_process_columns(
                    p.parse_sockets(SOCKETS),
                    {"300": info},
                    {},
                    [],
                    all_details=detailed,
                )
            )
            row = next(row for row in rows if row["PID"] == "300")
            self.assertEqual(row["User"], "root")
            if detailed:
                self.assertEqual((row["UID"], row["EUID"]), ("1000", "0"))

    def test_user_lookup_is_cached_and_unknown_accounts_use_numeric_uid(self):
        processes = {
            "2044": {"euid": 1001, "age_s": 3723},
            "300": {"euid": 1001, "age_s": 45},
        }
        for error in (KeyError("missing fixture user"), OSError("lookup unavailable")):
            with mock.patch.object(p.pwd, "getpwuid", side_effect=error) as lookup:
                rows = self.column_rows(
                    p.format_process_columns(
                        p.parse_sockets(SOCKETS), processes, {}, []
                    )
                )
            self.assertEqual(lookup.call_count, 1)
            selected = [row for row in rows if row["PID"] in processes]
            self.assertEqual([row["User"] for row in selected], ["1001"] * 3)
            self.assertEqual(
                [row["Age"] for row in selected], ["1h02m", "1h02m", "45s"]
            )

    def test_process_age_uses_one_uptime_read_and_actual_clock_tick_rate(self):
        self.clock_ticks.return_value = 250
        self.process(300, "python3", ["python3"], "/usr/bin/python3", started=225000)
        self.process(400, "node", ["node"], "/usr/bin/node", started=249999)
        processes = p.collect_processes(
            [{"pid": 300, "fds": [3]}, {"pid": 400, "fds": [3]}], self.root
        )
        self.assertEqual(processes["300"]["age_s"], 100)
        self.assertEqual(processes["400"]["age_s"], 0)
        self.clock_ticks.assert_called_once_with("SC_CLK_TCK")
        self.assertEqual(
            sum(
                call.args[0] == self.root / "uptime"
                for call in p.read_limited.call_args_list
            ),
            1,
        )

    def test_missing_or_invalid_age_data_does_not_hide_process_metadata(self):
        self.process(300, "python3", ["python3"], "/usr/bin/python3")
        for content in ("", "bad", "nan", "inf", "-1 0", "0 0"):
            (self.root / "uptime").write_text(content)
            info = self.collect(300)
            self.assertNotIn("age_s", info)
            self.assertEqual(info["chain"], "python3")
        (self.root / "uptime").unlink()
        self.assertNotIn("age_s", self.collect(300))
        (self.root / "uptime").write_text("1000 0\n")
        self.clock_ticks.return_value = 0
        self.assertNotIn("age_s", self.collect(300))

    def test_compact_process_age_units_and_unknown_values(self):
        cases = {
            0: "0s",
            59: "59s",
            60: "1m00s",
            728: "12m08s",
            3599: "59m59s",
            3600: "1h00m",
            86399: "23h59m",
            86400: "1d00h",
            273600: "3d04h",
        }
        for seconds, expected in cases.items():
            self.assertEqual(p.format_age(seconds), expected)
        for invalid in (None, -1, True, "12", float("nan")):
            self.assertEqual(p.format_age(invalid), "")


if __name__ == "__main__":
    unittest.main()
