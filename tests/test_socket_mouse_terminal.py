"""Decode real terminal mouse bytes against fixture rows, never real sockets."""

import fcntl
import json
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
import unittest
from pathlib import Path

CHILD = r"""
import curses, json, os, socket, subprocess, sys, time
sys.path.insert(0, sys.argv[1])
import sockets_tui as t

def forbidden(*args, **kwargs):
    raise AssertionError("Live collection/network access forbidden in mouse fixture")

subprocess.Popen = subprocess.run = socket.socket = socket.getaddrinfo = forbidden
os.kill = os.killpg = t.Collector = t.snapshot_command = forbidden
fd = int(sys.argv[2])

def report(data):
    os.write(fd, (json.dumps(data) + "\n").encode())

class FixtureCollector:
    def start(self): pass
    def close(self): report({"closed": True})
    def latest(self):
        if getattr(self, "sent", False): return None
        self.sent = True
        rows = tuple(
            ("ESTAB", "tcp", "OUTBOUND*", "192.0.2.1:5000", "192.0.2.2:443",
             "1024", "512", "0", "0", str(pid), "fixture", "2s", "fixture-app", "/fixture")
            for pid in (30, 10, 20)
        )
        return t.Update(t.Table(rows=rows), time.monotonic())

original_draw, original_mouse = t.draw, t.View.mouse

def draw(window, view, *args):
    original_draw(window, view, *args)
    if not getattr(view, "reported", False):
        report({"ready": True, "regions": view.header_regions})
        view.reported = True

def mouse(view, event, *args):
    original_mouse(view, event, *args)
    report({"buttons": event[4], "sort": view.sort_column,
            "reverse": view.sort_reverse,
            "pids": [row[view.filtered.labels.index("PID")] for row in view.filtered.rows]})

t.draw, t.View.mouse = draw, mouse
curses.wrapper(t.run_screen, FixtureCollector())
"""


class TerminalMouseTests(unittest.TestCase):
    def test_actual_ncurses_decodes_two_header_clicks_as_descending_then_ascending(
        self,
    ):
        for terminal in ("xterm-256color", "xterm"):
            with self.subTest(terminal=terminal):
                self.check_mouse(terminal)

    def check_mouse(self, terminal):
        master, slave = pty.openpty()
        read_fd, write_fd = os.pipe()
        proc = None
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 180, 0, 0))
            env = {**os.environ, "TERM": terminal, "NO_COLOR": "1"}
            for key in ("LINES", "COLUMNS", "TERMINFO", "TERMINFO_DIRS"):
                env.pop(key, None)
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    CHILD,
                    str(Path(__file__).resolve().parents[1] / "lib"),
                    str(write_fd),
                ],
                stdin=slave,
                stdout=slave,
                stderr=slave,
                pass_fds=(write_fd,),
                env=env,
            )
            os.close(slave)
            os.close(write_fd)
            slave = write_fd = None
            buffer, output = bytearray(), bytearray()
            records, inputs = [], {master, read_fd}

            def receive(predicate, seconds=3):
                end = time.monotonic() + seconds
                while inputs and time.monotonic() < end and not predicate():
                    ready, _, _ = select.select(
                        inputs, [], [], max(0, end - time.monotonic())
                    )
                    for fd in ready:
                        try:
                            data = os.read(fd, 65536)
                        except OSError:
                            data = b""
                        if not data:
                            inputs.remove(fd)
                        elif fd == master:
                            output.extend(data)
                        else:
                            buffer.extend(data)
                            while b"\n" in buffer:
                                line, _, remaining = buffer.partition(b"\n")
                                records.append(json.loads(line))
                                buffer[:] = remaining
                return predicate()

            self.assertTrue(receive(lambda: bool(records)), repr(output[-2000:]))
            self.assertTrue(records[0].get("ready"), records)
            x = next(
                start for start, _, label in records[0]["regions"] if label == "PID"
            )
            press = f"\x1b[<0;{x + 1};3M".encode()
            release = f"\x1b[<0;{x + 1};3m".encode()
            for count, reverse in ((1, True), (2, False)):
                before = len(records)
                os.write(master, press)
                self.assertTrue(
                    receive(lambda previous=before: len(records) > previous),
                    repr(output[-2000:]),
                )
                self.assertEqual(records[-1]["sort"], "PID")
                self.assertEqual(records[-1]["reverse"], reverse)
                self.assertEqual(
                    records[-1]["pids"],
                    ["30", "20", "10"] if reverse else ["10", "20", "30"],
                )
                os.write(master, release)
                receive(lambda previous=before: len(records) > previous + 1, 0.1)
                self.assertEqual(records[-1]["reverse"], reverse)
            os.write(master, b"q")
            self.assertTrue(receive(lambda: any(row.get("closed") for row in records)))
            self.assertEqual(proc.wait(timeout=3), 0, repr(output[-2000:]))
            changes = []
            for row in records:
                if row.get("sort") == "PID" and (
                    not changes or changes[-1] != row["reverse"]
                ):
                    changes.append(row["reverse"])
            self.assertEqual(changes, [True, False], records)
        finally:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait(timeout=3)
            for fd in (master, slave, read_fd, write_fd):
                if fd is not None:
                    os.close(fd)


if __name__ == "__main__":
    unittest.main()
