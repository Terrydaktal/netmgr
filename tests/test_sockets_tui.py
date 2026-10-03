"""Synthetic terminal/collector fixtures only; real processes and networking forbidden."""

import argparse
import importlib.util
import io
import signal
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "sockets_tui", Path(__file__).resolve().parents[1] / "lib" / "sockets_tui.py"
)
t = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = t
SPEC.loader.exec_module(t)

LABELS = t.Table().labels
ROW = (
    "LISTEN",
    "tcp",
    "-",
    "0.0.0.0:8080",
    "0.0.0.0:*",
    "-",
    "-",
    "0",
    "128",
    "300",
    "fixture",
    "3d04h",
    "python3.14<-uv-bin<-fish<-xfce4-terminal<-systemd",
    "/home/fixture/a very long workspace/services/transcription/working-directory",
)


def raw_table(rows=(ROW,), labels=LABELS):
    return "\n".join("\t".join(row) for row in (labels, *rows)) + "\n"


def changed_row(**fields):
    return tuple(fields.get(label, value) for label, value in zip(LABELS, ROW))


class Screen:
    def __init__(self, height=24, width=180, keys=()):
        self.height, self.width = height, width
        self.keys = iter(keys)
        self.lines = {}
        self.frames = []

    def getmaxyx(self):
        return self.height, self.width

    def erase(self):
        self.lines = {}

    def addstr(self, y, x, text, style):
        assert 0 <= y < self.height
        assert x == 0
        assert t.text_width(text) < self.width, (self.width, text)
        assert all(char.isprintable() for char in text)
        self.lines[y] = (text, style)

    def noutrefresh(self):
        self.frames.append(dict(self.lines))

    def keypad(self, enabled):
        assert enabled

    def timeout(self, value):
        assert value <= 100

    def scrollok(self, enabled):
        assert not enabled

    def get_wch(self):
        key = next(self.keys)
        if isinstance(key, BaseException):
            raise key
        return key


class Fixtures(unittest.TestCase):
    def setUp(self):
        for target in (
            "subprocess.Popen",
            "subprocess.run",
            "os.killpg",
            "os.kill",
            "socket.socket",
            "socket.getaddrinfo",
            "curses.initscr",
            "curses.wrapper",
            "curses.getmouse",
        ):
            patcher = mock.patch(
                target, side_effect=AssertionError(f"live call forbidden: {target}")
            )
            patcher.start()
            self.addCleanup(patcher.stop)
        for target in ("curses.doupdate", "curses.curs_set"):
            patcher = mock.patch(target)
            patcher.start()
            self.addCleanup(patcher.stop)
        for target, result in (
            ("curses.mousemask", (t.MOUSE_MASK, 0)),
            ("curses.mouseinterval", 166),
        ):
            patcher = mock.patch(target, return_value=result)
            patcher.start()
            self.addCleanup(patcher.stop)

    def view(self, rows=(ROW,)):
        view = t.View()
        view.update(t.Update(t.Table(LABELS, tuple(rows)), sampled_at=10))
        return view

    def test_parse_preserves_untruncated_values_spaces_and_column_aliases(self):
        table = t.Table.parse(raw_table())
        self.assertEqual(table.rows, (ROW,))
        labels = tuple({v: k for k, v in t.ALIASES.items()}.get(s, s) for s in LABELS)
        self.assertEqual(t.Table.parse(raw_table(labels=labels)), table)
        self.assertEqual(t.Table.parse(raw_table(rows=())).rows, ())
        self.assertGreater(table.widths[-1], 64)

    def test_invalid_snapshot_is_not_an_empty_success(self):
        for raw in (
            "",
            "Warning: failed\n",
            raw_table() + "incomplete\trow\n",
            raw_table(labels=LABELS + ("PID",)),
        ):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                t.Table.parse(raw)

    def test_traffic_units_preserve_exact_values_and_use_compact_display_widths(self):
        cases = {
            "-": "-",
            "0": "0B",
            "999": "999B",
            "1024": "1.0KiB",
            "1048575": "1.0MiB",
            "1048576": "1.0MiB",
            "1073741824": "1.0GiB",
            "1099511627776": "1.0TiB",
            "9007199254740993": "8.0PiB",
            "18446744073709551615": "16.0EiB",
        }
        for label in t.TRAFFIC_COLUMNS:
            for raw, rendered in cases.items():
                with self.subTest(label=label, raw=raw):
                    self.assertEqual(t.display_value(label, raw), rendered)
                    exact = raw if raw == "-" else f"{raw} bytes"
                    self.assertEqual(t.display_value(label, raw, exact=True), exact)
                    row = changed_row(**{label: raw})
                    table = t.Table.parse(raw_table((row,)))
                    index = LABELS.index(label)
                    width = table.widths[index]
                    self.assertEqual(width, max(len(label), len(rendered)))
                    self.assertEqual(
                        t.render_row(table, row, ((index, width),)),
                        rendered.rjust(width),
                    )
                    self.assertEqual(table.rows[0][index], raw)
        self.assertEqual(t.display_value("Recv", "1024"), "1024")

    def test_traffic_sorts_exact_bytes_not_rounded_units_with_unknowns_last(self):
        values = (
            "1048580",
            "9007199254740993",
            "1024",
            "1048576",
            "9007199254740992",
            "0",
            "-",
        )
        for label in t.TRAFFIC_COLUMNS:
            rows = tuple(
                changed_row(State="ESTAB", **{label: value}) for value in values
            )
            table = t.Table(LABELS, rows)
            index = LABELS.index(label)
            for reverse in (False, True):
                expected = sorted(values[:-1], key=int, reverse=reverse) + ["-"]
                self.assertEqual(
                    [row[index] for row in t.sorted_rows(table, label, reverse)],
                    expected,
                )

    def test_traffic_sort_is_global_with_state_origin_ties_and_missing_last(self):
        for label in t.TRAFFIC_COLUMNS:
            rows = (
                changed_row(
                    State="ESTAB", Origin="INBOUND*", PID="20", **{label: "20"}
                ),
                changed_row(
                    State="CLOSE-WAIT", Origin="OUTBOUND*", PID="50a", **{label: "50"}
                ),
                changed_row(
                    State="ESTAB", Origin="SAME-HOST*", PID="50c", **{label: "50"}
                ),
                changed_row(
                    State="CLOSE-WAIT", Origin="INBOUND*", PID="50b", **{label: "50"}
                ),
                changed_row(
                    State="ESTAB", Origin="OUTBOUND*", PID="100", **{label: "100"}
                ),
                changed_row(
                    State="CLOSE-WAIT", Origin="UNKNOWN", PID="missing", **{label: "-"}
                ),
            )
            table = t.Table(LABELS, rows)
            for reverse, expected in (
                (False, ["20", "50a", "50b", "50c", "100", "missing"]),
                (True, ["100", "50a", "50b", "50c", "20", "missing"]),
            ):
                with self.subTest(label=label, reverse=reverse):
                    self.assertEqual(
                        [
                            row[LABELS.index("PID")]
                            for row in t.sorted_rows(table, label, reverse)
                        ],
                        expected,
                    )

    def test_traffic_headers_toggle_global_sort_and_preserve_selection(self):
        for label in t.TRAFFIC_COLUMNS:
            rows = (
                changed_row(
                    State="CLOSE-WAIT", Origin="OUTBOUND*", PID="1", **{label: "2048"}
                ),
                changed_row(
                    State="ESTAB", Origin="OUTBOUND*", PID="2", **{label: "1048576"}
                ),
                changed_row(State="LISTEN", PID="3"),
            )
            view, screen = self.view(rows), Screen()
            selected = view.selected_key()
            for expected in (("2", "1", "3"), ("1", "2", "3")):
                t.draw(screen, view, 11)
                x = next(
                    start
                    for start, _, heading in view.header_regions
                    if heading == label
                )
                view.mouse((0, x, 2, 0, t.HEADER_CLICK), 24, 180)
                self.assertEqual(
                    tuple(row[LABELS.index("PID")] for row in view.filtered.rows),
                    expected,
                )
                self.assertEqual(view.selected_key(), selected)
                t.draw(screen, view, 11)
                self.assertIn("(global) > State > Origin", screen.lines[1][0])
                self.assertIn("State[2]", screen.lines[2][0])
                self.assertIn("Origin[3]", screen.lines[2][0])

    def test_traffic_sort_picker_marks_global_columns(self):
        view = self.view()
        view.key(t.curses.KEY_F6, 24, 180)
        for label in t.TRAFFIC_COLUMNS:
            view.sort_selected = view.sort_choices.index(label)
            screen = Screen()
            t.draw(screen, view, 11)
            self.assertTrue(
                any(f"{label} (global)" in text for text, _ in screen.lines.values())
            )

    def test_traffic_search_matches_units_or_raw_bytes_and_details_are_exact(self):
        row = changed_row(State="ESTAB", Downloaded="1048576", Uploaded="2048")
        view = self.view((ROW, row))
        for query in ("1.0mib", "1048576", "2.0KiB", "2048"):
            view.query = query
            view.refilter()
            self.assertEqual(view.filtered.rows, (row,))
        view.key("\n", 24, 180)
        self.assertIn("Downloaded: 1048576 bytes", view.details)
        self.assertIn("Uploaded: 2048 bytes", view.details)
        view.key("\n", 24, 180)
        view.query = ""
        view.refilter()
        updated = changed_row(State="ESTAB", Downloaded="2097152", Uploaded="4096")
        view.update(t.Update(t.Table(LABELS, (updated,)), 12))
        self.assertEqual(view.filtered.rows, (updated,))
        self.assertEqual(
            view.selected_key(), tuple(updated[i] for i in t.IDENTITY_COLUMNS)
        )

    def test_traffic_columns_never_wrap_and_hidden_totals_remain_in_details(self):
        view = self.view(
            (
                changed_row(
                    Downloaded="18446744073709551615", Uploaded="9007199254740993"
                ),
            )
        )
        for width in (40, 80, 120, 180, 300):
            t.draw(Screen(width=width), view, 11)
        screen = Screen(width=180)
        t.draw(screen, view, 11)
        self.assertIn("Downloaded", screen.lines[2][0])
        self.assertIn("Uploaded", screen.lines[2][0])
        self.assertIn("16.0EiB", screen.lines[3][0])
        t.draw(Screen(width=40), view, 11)
        view.key("\n", 24, 40)
        self.assertIn("Downloaded: 18446744073709551615 bytes", view.details)

    def test_destroy_event_parser_uses_ss_fields_and_ignores_non_connections(self):
        line = (
            "tcp ESTAB 0 0 192.0.2.1:50123 198.51.100.2:443 "
            'users:(("browser bytes_received:999",pid=42,fd=3)) '
            "cubic bytes_received:1048576 bytes_acked:2048"
        )
        event = t.parse_destroyed(line, 100.5)
        self.assertEqual(event.when, 100.5)
        self.assertEqual(event.values["Local"], "192.0.2.1:50123")
        self.assertEqual(event.values["PID"], "42")
        self.assertEqual(event.values["App"], "browser bytes_received:999")
        self.assertEqual(
            (event.values["Downloaded"], event.values["Uploaded"]), ("1048576", "2048")
        )
        unsafe = t.parse_destroyed(
            'tcp ESTAB 0 0 192.0.2.1:1 198.51.100.1:443 users:(("bad\x1b[31m",pid=1,fd=2))',
            100,
        )
        self.assertNotIn("\x1b", unsafe.values["App"])
        self.assertEqual(
            t.parse_destroyed(
                "tcp CLOSE-WAIT 0 0 [2001:db8::1]:5000 [2001:db8::2]:443 bytes_acked:7",
                101,
            ).values["Downloaded"],
            "0",
        )
        self.assertEqual(
            t.parse_destroyed("udp ESTAB 0 0 192.0.2.1:1 198.51.100.1:443", 101).values[
                "Downloaded"
            ],
            "-",
        )
        for line in (
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port",
            "tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*",
            "udp UNCONN 0 0 0.0.0.0:9 0.0.0.0:*",
            "tcp ESTAB nope 0 192.0.2.1:1 198.51.100.1:443",
            "tcp ESTAB 0 0 192.0.2.1:1 198.51.100.1:0",
            "noise from stderr",
        ):
            self.assertIsNone(t.parse_destroyed(line, 101))

    def test_event_closure_preserves_last_known_process_origin_and_final_counters(self):
        row = changed_row(
            State="ESTAB",
            Origin="OUTBOUND*",
            Local="192.0.2.1:5000",
            Peer="198.51.100.2:443",
            PID="42",
            App="browser<-systemd",
            Downloaded="100",
            Uploaded="20",
        )
        view = t.View()
        view.update(t.Update(t.Table(LABELS, (row,)), 100))
        event = t.parse_destroyed(
            "tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443 bytes_received:120 bytes_acked:25",
            100.5,
        )
        view.accept_events((event,))
        self.assertEqual(len(view.table.rows), 1)
        closed = dict(zip(view.table.labels, view.table.rows[0]))
        self.assertEqual(closed["State"], "CLOSED")
        self.assertEqual(closed["Origin"], "OUTBOUND*")
        self.assertEqual(closed["App"], "browser<-systemd")
        self.assertEqual((closed["Downloaded"], closed["Uploaded"]), ("120", "25"))
        self.assertEqual((closed["Age"], closed["Process age"]), ("0s", "3d04h"))
        screen = Screen()
        t.draw(screen, view, 102, listener_style=123, inbound_style=456)
        self.assertEqual(screen.lines[3][1] & t.curses.A_DIM, t.curses.A_DIM)
        self.assertEqual(view.table.rows[0][view.table.labels.index("Age")], "1s")
        view.key("\n", 24, 180)
        self.assertIn("Downloaded: 120 bytes", view.details)
        self.assertIn("Age: 1s", view.details)
        self.assertIn("Process age: 3d04h", view.details)

    def test_event_only_connection_is_visible_then_expires_after_sixty_seconds(self):
        view = t.View()
        event = t.parse_destroyed(
            'tcp ESTAB 0 0 192.0.2.1:6000 198.51.100.2:443 users:(("browser",pid=91,fd=2)) bytes_acked:8',
            100,
        )
        view.accept_events((event,))
        row = dict(zip(view.table.labels, view.table.rows[0]))
        self.assertEqual(
            (row["State"], row["Origin"], row["PID"], row["App"]),
            ("CLOSED", "UNKNOWN", "91", "browser"),
        )
        self.assertEqual((row["Downloaded"], row["Uploaded"]), ("0", "8"))
        self.assertEqual((row["Age"], row["Process age"]), ("0s", "-"))
        view.update(t.Update(t.Table(LABELS), 101))
        self.assertEqual(len(view.table.rows), 1)
        view.refresh_recent(159)
        self.assertEqual(view.table.rows[0][view.table.labels.index("Age")], "59s")
        view.refresh_recent(160)
        self.assertEqual(view.table.rows, ())
        self.assertNotIn("Process age", view.table.labels)

    def test_recent_keeps_metadata_across_sparse_live_snapshots(self):
        rich = changed_row(
            State="ESTAB",
            Origin="OUTBOUND*",
            Local="192.0.2.1:5000",
            Peer="198.51.100.2:443",
            PID="42",
            App="browser<-systemd",
            Downloaded="100",
            Uploaded="20",
        )
        values = dict(zip(LABELS, rich))
        values.update(
            State="FIN-WAIT-2",
            Origin="UNKNOWN",
            PID="-",
            User="-",
            Age="-",
            App="-",
            CWD="-",
            Downloaded="-",
            Uploaded="-",
            Recv="7",
            Send="0",
        )
        sparse = tuple(values[label] for label in LABELS)
        for closure in ("event", "absence"):
            with self.subTest(closure=closure):
                view = t.View()
                view.update(t.Update(t.Table(LABELS, (rich,)), 100))
                view.update(t.Update(t.Table(LABELS, (sparse,)), 101))
                view.update(t.Update(error="metadata snapshot failed"))
                # The live row remains the actual sample, not cached ownership/queues.
                self.assertEqual(view.live.rows, (sparse,))
                if closure == "event":
                    view.accept_events(
                        (
                            t.parse_destroyed(
                                "tcp CLOSE 0 0 192.0.2.1:5000 198.51.100.2:443 bytes_acked:25",
                                102,
                            ),
                        )
                    )
                else:
                    view.update(t.Update(t.Table(LABELS), 102))
                row = dict(zip(view.table.labels, view.table.rows[0]))
                for label in ("Origin", "PID", "User", "App", "CWD"):
                    self.assertEqual(row[label], rich[LABELS.index(label)], label)
                self.assertEqual(row["Process age"], rich[LABELS.index("Age")])
                self.assertEqual(row["Downloaded"], "100")
                self.assertEqual(row["Uploaded"], "25" if closure == "event" else "20")
                self.assertEqual(row["Age"], "0s")
                self.assertEqual(row["Recv"], "0" if closure == "event" else "7")
                self.assertFalse(view.last_known)

    def test_recent_keeps_latest_usable_fields_including_verbose_details(self):
        labels = LABELS + ("Command", "Service", "Metadata")
        rich = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443"
        )
        original = (*rich, "python worker.py", "worker.service", "-")
        updated = dict(zip(labels, original))
        updated.update(
            CWD="/new/workspace",
            Age="3d05h",
            Command="python next.py",
            Downloaded="100",
            Uploaded="30",
        )
        fallback = dict(
            updated,
            CWD="-",
            Age="-",
            Command="-",
            Service="-",
            App="python3.14<-?",
            Downloaded="-",
            Uploaded="-",
            Metadata="process metadata unavailable",
        )
        view = t.View()
        for when, values in (
            (100, dict(zip(labels, original))),
            (101, updated),
            (102, fallback),
        ):
            view.update(
                t.Update(
                    t.Table(labels, (tuple(values[label] for label in labels),)), when
                )
            )
        view.accept_events(
            (
                t.parse_destroyed(
                    'tcp CLOSE 0 0 192.0.2.1:5000 198.51.100.2:443 users:(("python3.14",pid=300,fd=3))',
                    103,
                ),
            )
        )
        row = dict(zip(view.table.labels, view.table.rows[0]))
        for label in ("App", "CWD", "Command", "Service", "Downloaded", "Uploaded"):
            self.assertEqual(row[label], updated[label], label)
        self.assertEqual(row["Process age"], "3d05h")
        self.assertEqual(row["Metadata"], "process metadata unavailable")

    def test_delayed_snapshot_enriches_closed_row_without_resetting_age_or_counters(
        self,
    ):
        rich = changed_row(
            State="ESTAB",
            Origin="OUTBOUND*",
            Local="192.0.2.1:5000",
            Peer="198.51.100.2:443",
            App="browser<-systemd",
            Downloaded="100",
            Uploaded="20",
        )
        for owners in ("", ' users:(("browser",pid=300,fd=3))'):
            with self.subTest(owners=owners):
                view = t.View()
                view.accept_events(
                    (
                        t.parse_destroyed(
                            f"tcp CLOSE 0 0 192.0.2.1:5000 198.51.100.2:443{owners} bytes_received:120 bytes_acked:25",
                            101,
                        ),
                    )
                )
                view.update(t.Update(t.Table(LABELS, (rich,)), 100, completed_at=102))
                view.refresh_recent(104)
                self.assertEqual(len(view.table.rows), 1)
                row = dict(zip(view.table.labels, view.table.rows[0]))
                for label in ("Origin", "PID", "User", "App", "CWD"):
                    self.assertEqual(row[label], rich[LABELS.index(label)], label)
                self.assertEqual((row["State"], row["Age"]), ("CLOSED", "3s"))
                self.assertEqual((row["Downloaded"], row["Uploaded"]), ("120", "25"))
                self.assertFalse(view.last_known)
                view.refresh_recent(161)
                self.assertFalse(view.table.rows)

    def test_closed_metadata_survives_temporary_loss_of_metadata_columns(self):
        rich = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443"
        )
        brief = tuple(
            "-" if label == "PID" else rich[index]
            for index, label in enumerate(t.BASE_COLUMNS)
        )
        view = t.View()
        view.update(t.Update(t.Table(LABELS, (rich,)), 100))
        view.update(t.Update(t.Table(t.BASE_COLUMNS, (brief,)), 101))
        view.update(t.Update(t.Table(t.BASE_COLUMNS), 102))
        row = dict(zip(view.table.labels, view.table.rows[0]))
        self.assertEqual(row["App"], rich[LABELS.index("App")])
        self.assertEqual(row["CWD"], rich[LABELS.index("CWD")])
        self.assertEqual(row["Process age"], rich[LABELS.index("Age")])
        view.query = "transcription"
        view.refilter()
        self.assertEqual(len(view.filtered.rows), 1)
        view.key("\n", 24, 180)
        self.assertIn("CWD: " + row["CWD"], view.details)
        view.refresh_recent(162)
        self.assertEqual(view.table.labels, t.BASE_COLUMNS)

    def test_metadata_cache_resets_after_absence_or_confirmed_closure(self):
        rich = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443"
        )
        values = dict(zip(LABELS, rich))
        values.update(PID="-", User="-", Age="-", App="-", CWD="-")
        sparse = tuple(values[label] for label in LABELS)
        for closure in ("absence", "event", "expired_event"):
            with self.subTest(closure=closure):
                view = t.View()
                view.update(t.Update(t.Table(LABELS, (rich,)), 100))
                if closure == "absence":
                    view.update(t.Update(t.Table(LABELS), 101))
                else:
                    view.accept_events(
                        (
                            t.parse_destroyed(
                                "tcp CLOSE 0 0 192.0.2.1:5000 198.51.100.2:443", 101
                            ),
                        )
                    )
                if closure == "expired_event":
                    view.refresh_recent(161)
                view.update(t.Update(t.Table(LABELS, (sparse,)), 162))
                view.update(t.Update(t.Table(LABELS), 163))
                row = dict(zip(view.table.labels, view.table.rows[0]))
                for label in ("PID", "User", "App", "CWD", "Process age"):
                    self.assertEqual(row[label], "-", label)
                self.assertFalse(view.last_known)

    def test_metadata_cache_does_not_cross_observed_connection_reuse(self):
        rich = changed_row(
            State="FIN-WAIT-2",
            Origin="OUTBOUND*",
            Local="192.0.2.1:5000",
            Peer="198.51.100.2:443",
            Downloaded="100",
            Uploaded="20",
        )
        for change in ({"PID": "400"}, {"Downloaded": "5"}, {"State": "SYN-SENT"}):
            with self.subTest(change=change):
                values = dict(zip(LABELS, rich))
                values.update(Origin="UNKNOWN", User="-", Age="-", App="-", CWD="-")
                values.update(change)
                view = t.View()
                view.update(t.Update(t.Table(LABELS, (rich,)), 100))
                view.update(
                    t.Update(
                        t.Table(LABELS, (tuple(values[label] for label in LABELS),)),
                        101,
                    )
                )
                view.update(t.Update(t.Table(LABELS), 102))
                row = dict(zip(view.table.labels, view.table.rows[0]))
                self.assertEqual(row["Origin"], "UNKNOWN")
                for label in ("User", "App", "CWD", "Process age"):
                    self.assertEqual(row[label], "-", label)

    def test_late_snapshot_does_not_enrich_event_with_different_owner(self):
        rich = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443"
        )
        view = t.View()
        view.accept_events(
            (
                t.parse_destroyed(
                    'tcp CLOSE 0 0 192.0.2.1:5000 198.51.100.2:443 users:(("other",pid=400,fd=3))',
                    101,
                ),
            )
        )
        view.update(t.Update(t.Table(LABELS, (rich,)), 100, completed_at=102))
        row = dict(zip(view.table.labels, view.table.rows[0]))
        self.assertEqual((row["PID"], row["App"], row["CWD"]), ("400", "other", "-"))

    def test_recent_connection_age_stays_visible_without_moving_beside_state(self):
        active = changed_row(
            State="ESTAB",
            Local="192.0.2.1:5000",
            Peer="198.51.100.2:443",
            Age="4h00m",
        )
        gone = t.View()
        gone.update(t.Update(t.Table(LABELS, (active,)), 10))
        gone.update(t.Update(t.Table(LABELS), 11))
        closed = t.View()
        closed.accept_events(
            (t.parse_destroyed("tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443", 10),)
        )
        for state, view in (("GONE*", gone), ("CLOSED", closed)):
            for width in (40, 80, 180):
                with self.subTest(state=state, width=width):
                    screen = Screen(width=width)
                    t.draw(screen, view, 14)
                    labels = [label for _, _, label in view.header_regions]
                    self.assertEqual(labels[0], "State")
                    self.assertGreater(labels.index("Age"), 1)
                    if "Uploaded" in labels:
                        self.assertEqual(
                            labels.index("Age"), labels.index("Uploaded") + 1
                        )
                    if "PID" in labels:
                        self.assertLess(labels.index("Age"), labels.index("PID"))
                    self.assertIn("Age", screen.lines[2][0])
                    self.assertIn(
                        "3s" if state == "GONE*" else "4s", screen.lines[3][0]
                    )
            if state == "GONE*":
                row = dict(zip(view.table.labels, view.table.rows[0]))
                self.assertEqual((row["Age"], row["Process age"]), ("3s", "4h00m"))

    def test_gone_age_starts_when_absence_is_detected_and_expires_from_that_time(self):
        active = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443"
        )
        view = t.View()
        view.update(t.Update(t.Table(LABELS, (active,)), 100))
        view.update(t.Update(t.Table(LABELS), 101))
        self.assertEqual(view.table.rows[0][LABELS.index("Age")], "0s")
        view.refresh_recent(160)
        self.assertEqual(view.table.rows[0][LABELS.index("Age")], "59s")
        view.refresh_recent(161)
        self.assertEqual(view.table.rows, ())

    def test_gone_age_uses_snapshot_completion_not_start(self):
        active = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443"
        )
        view = t.View()
        view.update(t.Update(t.Table(LABELS, (active,)), 100))
        view.update(t.Update(t.Table(LABELS), 101, completed_at=105))
        self.assertEqual(view.table.rows[0][LABELS.index("Age")], "0s")
        view.refresh_recent(106)
        self.assertEqual(view.table.rows[0][LABELS.index("Age")], "1s")
        view.refresh_recent(164)
        self.assertEqual(view.table.rows[0][LABELS.index("Age")], "59s")
        view.refresh_recent(165)
        self.assertEqual(view.table.rows, ())

    def test_late_destroy_event_confirms_gone_without_resetting_process_details(self):
        active = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443"
        )
        view = t.View()
        view.update(t.Update(t.Table(LABELS, (active,)), 100))
        view.update(t.Update(t.Table(LABELS), 101))
        view.accept_events(
            (t.parse_destroyed("tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443", 100.5),)
        )
        row = dict(zip(view.table.labels, view.table.rows[0]))
        self.assertEqual(
            (row["State"], row["Age"], row["Process age"]), ("CLOSED", "0s", "3d04h")
        )
        view.refresh_recent(102)
        self.assertEqual(view.table.rows[0][LABELS.index("Age")], "1s")

    def test_brief_recent_row_has_age_without_process_metadata(self):
        view = t.View()
        view.update(t.Update(t.Table(t.BASE_COLUMNS), 100))
        view.accept_events(
            (t.parse_destroyed("tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443", 101),)
        )
        self.assertEqual(view.table.labels, t.BASE_COLUMNS + ("Age",))
        self.assertEqual(view.table.rows[0][-1], "0s")
        screen = Screen(width=40)
        t.draw(screen, view, 105)
        labels = [label for _, _, label in view.header_regions]
        self.assertEqual(labels[0], "State")
        self.assertGreater(labels.index("Age"), 1)
        self.assertIn("4s", screen.lines[3][0])

    def test_recent_age_sort_uses_elapsed_seconds_not_text_order(self):
        view = t.View()
        view.accept_events(
            (
                t.parse_destroyed("tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443", 100),
                t.parse_destroyed("tcp ESTAB 0 0 192.0.2.1:5001 198.51.100.2:443", 109),
            )
        )
        view.refresh_recent(111)
        view.sort_by("Age", reverse=True)
        self.assertEqual(
            [row[view.table.labels.index("Age")] for row in view.filtered.rows],
            ["11s", "2s"],
        )
        view.sort_by("Age", reverse=False)
        self.assertEqual(
            [row[view.table.labels.index("Age")] for row in view.filtered.rows],
            ["2s", "11s"],
        )

    def test_snapshot_disappearance_is_inferred_only_after_successful_collection(self):
        active = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443", PID="1"
        )
        listener = changed_row(State="LISTEN", PID="2")
        udp = changed_row(State="BOUND", Net="udp", Local="0.0.0.0:5353", PID="3")
        view = t.View()
        view.update(t.Update(t.Table(LABELS, (active, listener, udp)), 10))
        view.update(t.Update(error="collection failed"))
        self.assertEqual(len(view.table.rows), 3)
        self.assertFalse(view.recent)
        view.update(t.Update(t.Table(LABELS), 11))
        self.assertEqual(len(view.table.rows), 1)
        self.assertEqual(view.table.rows[0][0], "GONE*")
        self.assertEqual(view.table.rows[0][view.table.labels.index("Age")], "0s")
        view.update(t.Update(error="collection failed again"))
        self.assertEqual(view.table.rows[0][0], "GONE*")
        view.update(t.Update(t.Table(LABELS, (active,)), 12))
        self.assertEqual(view.table.rows, (active,))

    def test_event_order_keeps_closed_row_until_fresh_snapshot_and_ignores_late_event(
        self,
    ):
        old = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443", PID="1"
        )
        new = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443", PID="2"
        )
        view = t.View()
        view.update(t.Update(t.Table(LABELS, (old,)), 100))
        event = t.parse_destroyed("tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443", 101)
        view.accept_events((event,))
        view.update(t.Update(t.Table(LABELS, (old,)), 100.5))
        self.assertEqual(len(view.table.rows), 1)
        self.assertEqual(view.table.rows[0][0], "CLOSED")
        view.update(t.Update(t.Table(LABELS, (new,)), 102))
        self.assertEqual(view.table.rows, (new,))
        view.accept_events((event,))
        self.assertEqual(view.table.rows, (new,))

    def test_confirmed_close_cannot_resurface_when_old_snapshot_outlives_history(self):
        old = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443", PID="1"
        )
        new = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443", PID="2"
        )
        view = t.View()
        view.update(t.Update(t.Table(LABELS, (old,)), 100))
        event = t.parse_destroyed(
            "tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443", 100.5
        )
        view.accept_events((event,))
        view.update(t.Update(error="snapshot failed"))
        view.refresh_recent(160.5)
        self.assertEqual(view.table.rows, ())
        self.assertEqual(len(view.closed_at), 1)
        view.update(t.Update(t.Table(LABELS), 161))
        self.assertEqual(view.table.rows, ())
        self.assertFalse(view.closed_at)
        view.update(t.Update(t.Table(LABELS, (new,)), 162))
        self.assertEqual(view.table.rows, (new,))

    def test_event_only_close_suppresses_a_delayed_older_snapshot(self):
        row = changed_row(
            State="ESTAB", Local="192.0.2.1:5000", Peer="198.51.100.2:443"
        )
        view = t.View()
        event = t.parse_destroyed("tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443", 100)
        view.accept_events((event,))
        view.update(t.Update(t.Table(LABELS, (row,)), 99.5))
        self.assertEqual(view.table.rows[0][0], "CLOSED")
        view.refresh_recent(160)
        self.assertEqual(view.table.rows, ())

    def test_recent_history_is_bounded_and_sorts_after_active_states(self):
        view = self.view((ROW,))
        events = tuple(
            t.parse_destroyed(
                f"tcp ESTAB 0 0 192.0.2.1:{1000 + index} 198.51.100.2:443", 100
            )
            for index in range(t.MAX_RECENT + 10)
        )
        view.accept_events(events)
        self.assertEqual(len(view.recent), t.MAX_RECENT)
        self.assertEqual(view.table.rows[0], (*ROW, "-"))
        self.assertEqual(view.table.rows[1][0], "CLOSED")
        view.sort_by("Peer", reverse=True)
        self.assertEqual(view.filtered.rows[0][0], "LISTEN")
        self.assertEqual(len(view.filtered.rows), t.MAX_RECENT + 1)

    def test_event_worker_uses_ss_destroy_stream_and_retries_failed_stream(self):
        self.assertEqual(t.event_command()[:5], ["sudo", "-n", "ss", "-E", "-H"])
        worker = t.EventCollector()
        proc = mock.Mock(pid=1234, returncode=5)
        proc.poll.return_value = 5
        proc.wait.return_value = 5
        waits = []

        def stop_after_first_retry(delay):
            waits.append(delay)
            worker.stop.set()

        worker.stop.wait = stop_after_first_retry
        with (
            mock.patch.object(t.subprocess, "Popen", return_value=proc) as popen,
            mock.patch.object(worker, "read_events", return_value="permission denied"),
        ):
            worker.run()
        self.assertEqual(popen.call_args.args[0], t.event_command())
        self.assertEqual(popen.call_args.kwargs["process_group"], 0)
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(waits, [5])
        self.assertIn("permission denied", worker.latest()[1])
        proc.stdout.close.assert_called_once()
        proc.stderr.close.assert_called_once()

    def test_event_stream_reads_partial_lines_and_stderr_without_using_real_sockets(
        self,
    ):
        worker = t.EventCollector()
        proc = mock.Mock()
        proc.stdout.fileno.return_value = 10
        proc.stderr.fileno.return_value = 11
        valid = b"tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443 bytes_received:13\n"
        first = (
            b"Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            + valid[:30]
        )
        chunks = [
            first,
            valid[30:],
            b"event warning\n",
            b"",
            b"",
        ]
        ready = iter((proc.stdout, proc.stdout, proc.stderr, proc.stdout, proc.stderr))
        with (
            mock.patch.object(
                t.select, "select", side_effect=lambda *_: ([next(ready)], [], [])
            ),
            mock.patch.object(t.os, "read", side_effect=chunks),
        ):
            warning = worker.read_events(proc)
        events, error, dropped = worker.latest()
        self.assertEqual(warning, "event warning")
        self.assertEqual(error, "")
        self.assertEqual(dropped, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].values["Downloaded"], "13")
        self.assertEqual(worker.latest()[0], ())

    def test_event_stream_drops_oversized_lines_and_bounds_backlog(self):
        worker = t.EventCollector()
        proc = mock.Mock()
        proc.stdout.fileno.return_value = 10
        proc.stderr.fileno.return_value = 11
        valid = b"tcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443\n"
        oversized = (
            b"tcp ESTAB 0 0 192.0.2.1:1 198.51.100.2:443 " + b"x" * t.MAX_EVENT_LINE
        )
        chunks = [oversized, b"trailer\n" + valid * (t.MAX_EVENTS + 1), b"", b""]
        ready = iter((proc.stdout, proc.stdout, proc.stdout, proc.stderr))
        with (
            mock.patch.object(
                t.select, "select", side_effect=lambda *_: ([next(ready)], [], [])
            ),
            mock.patch.object(t.os, "read", side_effect=chunks),
        ):
            worker.read_events(proc)
        events, _, dropped = worker.latest()
        self.assertEqual(len(events), t.MAX_EVENTS)
        self.assertEqual(dropped, 1)
        self.assertEqual(worker.latest(), ((), "", 1))

    def test_event_worker_stops_its_process_group_on_shutdown(self):
        worker = t.EventCollector()
        proc = mock.Mock(pid=1234)
        proc.poll.return_value = None

        def stop_reading(_proc):
            worker.stop.set()
            return ""

        with (
            mock.patch.object(t.subprocess, "Popen", return_value=proc),
            mock.patch.object(worker, "read_events", side_effect=stop_reading),
            mock.patch.object(t, "terminate") as terminate,
        ):
            worker.run()
        terminate.assert_called_once_with(proc)

    def test_live_screen_starts_and_stops_both_collectors(self):
        collector, events = mock.Mock(), mock.Mock()
        collector.latest.return_value = t.Update(t.Table(LABELS, (ROW,)), 10)
        events.latest.return_value = ((), "", 0)
        with mock.patch.object(t.curses, "has_colors", return_value=False):
            self.assertEqual(t.run_screen(Screen(keys=("q",)), collector, events), 0)
        collector.start.assert_called_once()
        events.start.assert_called_once()
        collector.close.assert_called_once()
        events.close.assert_called_once()

    def test_event_errors_are_visible_without_marking_snapshot_stale(self):
        view = self.view()
        view.events_error = "ss -E exited (1): permission denied"
        screen = Screen()
        t.draw(screen, view, 11)
        self.assertIn("LIVE", screen.lines[0][0])
        self.assertIn(view.events_error, screen.lines[1][0])

    def test_paused_event_overflow_warning_persists_after_an_empty_poll(self):
        collector, events = mock.Mock(), mock.Mock()
        collector.latest.return_value = t.Update(t.Table(LABELS, (ROW,)), 10)
        events.latest.side_effect = (
            ((), "", 0),
            ((None,) * (t.MAX_EVENTS + 1), "", 0),
            ((), "", 0),
        )
        screen = Screen(keys=(" ", t.curses.error(), "q"))
        with mock.patch.object(t.curses, "has_colors", return_value=False):
            self.assertEqual(t.run_screen(screen, collector, events), 0)
        self.assertIn("ss -E event backlog overflow: 1 lost", screen.lines[1][0])

    def test_sort_keeps_state_and_origin_groups_fixed_for_non_global_columns(
        self,
    ):
        states = ("CLOSE-WAIT", "ESTAB", "LISTEN", "TIME-WAIT", "BOUND")
        origins = ("-", "OUTBOUND*", "SAME-HOST*", "INBOUND*", "UNKNOWN")
        rows = tuple(
            changed_row(State=state, Origin=origin, Recv=str(number))
            for state in reversed(states)
            for origin in reversed(origins)
            for number in (100, 2, 10)
        )
        expected_groups = [(state, origin) for state in states for origin in origins]
        table = t.Table(LABELS, rows)
        for label in LABELS:
            if label in t.LOCKED_COLUMNS | t.GLOBAL_PRIMARY_COLUMNS:
                continue
            for reverse in (False, True):
                with self.subTest(label=label, reverse=reverse):
                    ordered = t.sorted_rows(table, label, reverse)
                    self.assertEqual(
                        [(row[0], row[2]) for row in ordered[::3]], expected_groups
                    )
                    for start in range(0, len(ordered), 3):
                        group = ordered[start : start + 3]
                        self.assertEqual(len({(row[0], row[2]) for row in group}), 1)
                        if label == "Recv":
                            self.assertEqual(
                                [int(row[LABELS.index("Recv")]) for row in group],
                                [100, 10, 2] if reverse else [2, 10, 100],
                            )

    def test_default_order_and_equal_key_ties_are_preserved(self):
        rows = tuple(changed_row(PID=str(pid)) for pid in (8, 3, 20))
        table = t.Table(LABELS, rows)
        for label in (None, "State", "Origin", "unavailable"):
            self.assertEqual(t.sorted_rows(table, label, True), rows)
        for reverse in (False, True):
            self.assertEqual(t.sorted_rows(table, "App", reverse), rows)
        view = self.view(rows)
        view.sort_by("PID")
        self.assertNotEqual(view.filtered.rows, rows)
        view.sort_by(None)
        self.assertEqual(view.filtered.rows, rows)

    def test_numeric_counts_ids_and_shared_owner_values_sort_numerically(self):
        for label in ("Downloaded", "Uploaded", "Recv", "Send", "PID", "UID", "EUID"):
            labels = LABELS if label in LABELS else LABELS + (label,)
            index = labels.index(label)
            values = ("20", "3", "100", "3;20", "3;8")
            rows = []
            for value in values:
                row = list(ROW) if label in LABELS else [*ROW, "-"]
                row[index] = value
                rows.append(tuple(row))
            table = t.Table(labels, tuple(rows))
            expected = ["3", "3;8", "3;20", "20", "100"]
            with self.subTest(label=label):
                for reverse in (False, True):
                    self.assertEqual(
                        [row[index] for row in t.sorted_rows(table, label, reverse)],
                        expected[::-1] if reverse else expected,
                    )

    def test_endpoint_sort_uses_numeric_address_then_port_with_ipv6_and_scopes(self):
        expected = [
            "*:443",
            "0.0.0.0:22",
            "192.0.2.2:80",
            "192.0.2.2:443",
            "192.0.2.10:9",
            "[::]:22",
            "[2001:db8::2]:9",
            "[2001:db8::2]:80",
            "[2001:db8::a]:9",
            "[fe80::1%eth2]:80",
            "[fe80::1%eth10]:80",
        ]
        for label in ("Local", "Peer"):
            rows = tuple(changed_row(**{label: value}) for value in reversed(expected))
            table = t.Table(LABELS, rows)
            for reverse in (False, True):
                self.assertEqual(
                    [
                        row[LABELS.index(label)]
                        for row in t.sorted_rows(table, label, reverse)
                    ],
                    expected[::-1] if reverse else expected,
                )

    def test_age_sort_uses_durations_and_handles_shared_owners_and_missing_values(self):
        expected = [
            "9s",
            "59s",
            "1m00s",
            "2m00s",
            "10m00s",
            "1h00m",
            "23h59m",
            "1d00h",
            "10d02h",
        ]
        table = t.Table(
            LABELS, tuple(changed_row(Age=age) for age in reversed(expected))
        )
        for reverse in (False, True):
            self.assertEqual(
                [
                    row[LABELS.index("Age")]
                    for row in t.sorted_rows(table, "Age", reverse)
                ],
                expected[::-1] if reverse else expected,
            )
        self.assertLess(t.age_key("1h00m | 10s"), t.age_key("1h00m | 2m00s"))
        self.assertLess(t.age_key("2m00s | -"), t.age_key("1h00m | 9s"))
        t.age_key("unknown | -")

    def test_age_is_global_across_states_and_origins_with_missing_ages_last(self):
        rows = (
            changed_row(State="CLOSE-WAIT", Origin="INBOUND*", Age="9s", PID="1"),
            changed_row(State="LISTEN", Origin="-", Age="3d04h", PID="2"),
            changed_row(State="ESTAB", Origin="OUTBOUND*", Age="2h15m", PID="3"),
            changed_row(State="BOUND", Origin="-", Age="45s", PID="4"),
            changed_row(State="ESTAB", Origin="INBOUND*", Age="1m00s", PID="5"),
            changed_row(State="ESTAB", Origin="SAME-HOST*", Age="5s", PID="6"),
            changed_row(State="CLOSE-WAIT", Origin="OUTBOUND*", Age="-", PID="7"),
            changed_row(State="ESTAB", Origin="OUTBOUND*", Age="?", PID="8"),
            changed_row(State="LISTEN", Origin="-", Age="- | -", PID="9"),
        )
        table = t.Table(LABELS, rows)
        for reverse, expected in (
            (False, ["6", "1", "4", "5", "3", "2"]),
            (True, ["2", "3", "5", "4", "1", "6"]),
        ):
            ordered = t.sorted_rows(table, "Age", reverse)
            self.assertEqual(
                [row[LABELS.index("PID")] for row in ordered[:6]], expected
            )
            self.assertCountEqual(
                [row[LABELS.index("PID")] for row in ordered[6:]], ["7", "8", "9"]
            )

    def test_equal_ages_use_state_then_origin_ties_without_reversing_them(self):
        groups = (
            ("CLOSE-WAIT", "UNKNOWN"),
            ("ESTAB", "OUTBOUND*"),
            ("ESTAB", "SAME-HOST*"),
            ("ESTAB", "INBOUND*"),
            ("ESTAB", "UNKNOWN"),
            ("LISTEN", "-"),
            ("BOUND", "-"),
        )
        rows = tuple(
            changed_row(State=state, Origin=origin, Age=age, PID=pid)
            for state, origin in reversed(groups)
            for age, pid in (("1h00m", "20"), ("60m00s", "3"))
        )
        table = t.Table(LABELS, rows)
        for reverse in (False, True):
            ordered = t.sorted_rows(table, "Age", reverse)
            self.assertEqual([(row[0], row[2]) for row in ordered[::2]], list(groups))
            self.assertEqual(
                [row[LABELS.index("PID")] for row in ordered], ["20", "3"] * len(groups)
            )

    def test_age_header_clicks_sort_globally_then_other_headers_restore_grouping(self):
        rows = (
            changed_row(State="CLOSE-WAIT", Origin="INBOUND*", Age="1s", PID="1"),
            changed_row(State="ESTAB", Origin="OUTBOUND*", Age="2s", PID="2"),
            changed_row(State="ESTAB", Origin="INBOUND*", Age="3s", PID="3"),
            changed_row(State="LISTEN", Origin="-", Age="4s", PID="4"),
        )
        view, screen = self.view(rows), Screen()
        selected = view.selected_key()
        for expected in (("4", "3", "2", "1"), ("1", "2", "3", "4")):
            t.draw(screen, view, 11)
            x = next(start for start, _, label in view.header_regions if label == "Age")
            view.mouse((0, x, 2, 0, t.curses.BUTTON1_RELEASED), 24, 180)
            self.assertEqual(
                tuple(row[LABELS.index("PID")] for row in view.filtered.rows), expected
            )
            self.assertEqual(view.selected_key(), selected)
            t.draw(screen, view, 11)
            self.assertIn("(global) > State > Origin", screen.lines[1][0])
            self.assertIn("State[2]", screen.lines[2][0])
            self.assertIn("Origin[3]", screen.lines[2][0])
        x = next(start for start, _, label in view.header_regions if label == "PID")
        view.mouse((0, x, 2, 0, t.curses.BUTTON1_RELEASED), 24, 180)
        self.assertTrue(view.sort_reverse)
        self.assertEqual(view.filtered.rows, rows)
        t.draw(screen, view, 11)
        self.assertIn("State[1]", screen.lines[2][0])
        self.assertIn("Origin[2]", screen.lines[2][0])
        self.assertNotIn("(global)", screen.lines[1][0])

    def test_age_picker_sort_persists_through_refresh_filter_and_missing_metadata(self):
        rows = (
            changed_row(State="CLOSE-WAIT", Age="5s", PID="1"),
            changed_row(State="ESTAB", Age="1s", PID="2"),
            changed_row(State="LISTEN", Age="9s", PID="3"),
        )
        view = self.view(rows)
        view.key(t.curses.KEY_F6, 24, 180)
        view.sort_selected = view.sort_choices.index("Age")
        screen = Screen()
        t.draw(screen, view, 11)
        self.assertTrue(
            any("Age (global)" in text for text, _ in screen.lines.values())
        )
        view.key("\n", 24, 180)
        self.assertEqual(
            [row[LABELS.index("PID")] for row in view.filtered.rows], ["2", "1", "3"]
        )
        view.key("r", 24, 180)
        view.update(t.Update(t.Table(LABELS, rows), 12))
        self.assertEqual(
            [row[LABELS.index("PID")] for row in view.filtered.rows], ["3", "1", "2"]
        )
        view.query = "ESTAB"
        view.refilter()
        self.assertEqual(view.filtered.rows, (rows[1],))
        view.key("\x1b", 24, 180)
        self.assertEqual(
            [row[LABELS.index("PID")] for row in view.filtered.rows], ["3", "1", "2"]
        )
        view.update(
            t.Update(
                t.Table(
                    t.BASE_COLUMNS, tuple(row[: len(t.BASE_COLUMNS)] for row in rows)
                ),
                13,
            )
        )
        self.assertFalse(view.global_primary_sort())
        self.assertEqual(view.headings()[0], "State[1]")
        view.update(t.Update(t.Table(LABELS, rows), 14))
        self.assertTrue(view.global_primary_sort())
        self.assertEqual(
            [row[LABELS.index("PID")] for row in view.filtered.rows], ["3", "1", "2"]
        )

    def test_missing_sort_values_stay_last_in_both_directions(self):
        for label, known in (
            ("PID", ("2", "10")),
            ("CWD", ("/a", "/b")),
            ("Age", ("9s", "1m00s")),
        ):
            missing = ("-", "?", "", "- | -")
            values = (known[1], *missing, known[0])
            table = t.Table(
                LABELS, tuple(changed_row(**{label: value}) for value in values)
            )
            for reverse in (False, True):
                ordered = [
                    row[LABELS.index(label)]
                    for row in t.sorted_rows(table, label, reverse)
                ]
                self.assertEqual(ordered[:2], list(known[::-1] if reverse else known))
                self.assertCountEqual(ordered[2:], missing)

    def test_text_sort_uses_full_hidden_values_and_is_natural_and_case_insensitive(
        self,
    ):
        prefix = "/long/" * 40
        values = (prefix + "APP10", prefix + "app2", prefix + "App1")
        table = t.Table(LABELS + ("Command",), tuple((*ROW, value) for value in values))
        self.assertNotIn(len(LABELS), dict(t.column_layout(table, 60)))
        self.assertEqual(
            [row[-1] for row in t.sorted_rows(table, "Command")],
            [values[2], values[1], values[0]],
        )
        self.assertLess(
            t.natural_key("a" + "9" * 5000), t.natural_key("a1" + "0" * 5000)
        )

    def test_sort_persists_across_refresh_filtering_and_temporarily_missing_columns(
        self,
    ):
        rows = tuple(
            changed_row(PID=str(pid), CWD=f"/tmp/work/{pid}") for pid in (30, 10, 20)
        )
        view = self.view(rows)
        selected = view.selected_key()
        view.sort_by("CWD")
        self.assertEqual(
            [row[LABELS.index("PID")] for row in view.filtered.rows], ["10", "20", "30"]
        )
        self.assertEqual(view.selected_key(), selected)
        view.sort_by("CWD")
        self.assertTrue(view.sort_reverse)
        view.update(t.Update(t.Table(LABELS, tuple(reversed(rows))), 12))
        self.assertEqual(
            [row[LABELS.index("PID")] for row in view.filtered.rows], ["30", "20", "10"]
        )
        view.query = "work/20"
        view.refilter()
        self.assertEqual(view.filtered.rows, (rows[2],))
        view.query = ""
        view.refilter()
        view.update(
            t.Update(
                t.Table(
                    t.BASE_COLUMNS, tuple(row[: len(t.BASE_COLUMNS)] for row in rows)
                ),
                13,
            )
        )
        screen = Screen()
        t.draw(screen, view, 13)
        self.assertIn("CWD descending (unavailable; default order)", screen.lines[1][0])
        view.update(t.Update(t.Table(LABELS, rows), 14))
        self.assertEqual(
            [row[LABELS.index("PID")] for row in view.filtered.rows], ["30", "20", "10"]
        )
        view.sort_by("Origin")
        self.assertEqual((view.sort_column, view.sort_reverse), ("CWD", True))
        view.sort_by("State")
        self.assertEqual((view.sort_column, view.sort_reverse), (None, False))
        self.assertEqual(view.filtered.rows, rows)

    def test_state_header_restores_default_after_global_or_grouped_sort(self):
        rows = (
            changed_row(
                State="CLOSE-WAIT",
                Origin="OUTBOUND*",
                PID="3",
                Age="1s",
                Downloaded="100",
                Uploaded="300",
                App="client",
            ),
            changed_row(
                State="ESTAB",
                Origin="SAME-HOST*",
                PID="2",
                Age="3s",
                Downloaded="300",
                Uploaded="100",
                App="client",
            ),
            changed_row(
                State="ESTAB",
                Origin="INBOUND*",
                PID="1",
                Age="2s",
                Downloaded="200",
                Uploaded="200",
                App="client",
            ),
            changed_row(App="server"),
        )
        for label in ("Age", "Downloaded", "Uploaded", "PID"):
            for reverse in (False, True):
                with self.subTest(label=label, reverse=reverse):
                    view = self.view(rows)
                    view.query = "client"
                    view.refilter()
                    view.selected = 1
                    selected = view.selected_key()
                    view.sort_by(label, reverse=reverse)
                    screen = Screen()
                    for _ in range(2):
                        t.draw(screen, view, 11)
                        x = next(
                            start
                            for start, _, name in view.header_regions
                            if name == "State"
                        )
                        view.mouse((0, x, 2, 0, t.LEFT_PRESS), 24, 180)
                        view.mouse((0, x, 2, 0, t.HEADER_CLICK), 24, 180)
                        self.assertEqual(
                            (view.sort_column, view.sort_reverse), (None, False)
                        )
                        self.assertEqual(view.filtered.rows, rows[:3])
                        self.assertEqual(view.query, "client")
                        self.assertEqual(view.selected_key(), selected)
                        self.assertEqual(view.headings()[0], "State[1]")
                        self.assertEqual(view.headings()[2], "Origin[2]")
                    view.update(t.Update(t.Table(LABELS, rows), 12))
                    self.assertEqual(view.filtered.rows, rows[:3])

    def test_header_clicks_use_displayed_cells_and_toggle_only_the_third_key(self):
        for width in (45, 80, 180, 400):
            view = self.view(tuple(changed_row(PID=str(pid)) for pid in (30, 10, 20)))
            screen = Screen(width=width)
            t.draw(screen, view, 11)
            self.assertIn("State[1]", screen.lines[2][0])
            regions = view.header_regions
            for start, end, label in regions:
                for x in (start, end - 1):
                    view.sort_by(None)
                    t.draw(screen, view, 11)
                    view.mouse((0, x, 2, 0, t.HEADER_CLICK), 24, width)
                    self.assertEqual(
                        view.sort_column, None if label in t.LOCKED_COLUMNS else label
                    )
                    if label not in t.LOCKED_COLUMNS:
                        t.draw(screen, view, 11)
                        self.assertIn(label + "v", screen.lines[2][0])
                        active = next(
                            region
                            for region in view.header_regions
                            if region[2] == label
                        )
                        view.mouse((0, active[0], 2, 0, t.HEADER_CLICK), 24, width)
                        self.assertFalse(view.sort_reverse)
                        t.draw(screen, view, 11)
                        self.assertIn(label + "^", screen.lines[2][0])
            view.sort_by(None)
            t.draw(screen, view, 11)
            for start, end, label in view.header_regions:
                view.mouse((0, end, 2, 0, t.HEADER_CLICK), 24, width)
                view.mouse((0, start, 3, 0, t.HEADER_CLICK), 24, width)
                view.mouse((0, start, 2, 0, t.HEADER_CLICK), 24, width + 1)
                self.assertIsNone(view.sort_column)

    def test_header_click_variants_toggle_once_per_gesture_without_shift(self):
        press = t.curses.BUTTON1_PRESSED
        release = t.curses.BUTTON1_RELEASED
        click = t.curses.BUTTON1_CLICKED
        double_click = t.curses.BUTTON1_DOUBLE_CLICKED
        for gesture in (
            (press, release),
            (press, click),
            (release,),
            (click,),
            (double_click,),
            (press | release,),
        ):
            with self.subTest(gesture=gesture):
                view = self.view()
                screen = Screen()
                with mock.patch.object(view, "sort_by", wraps=view.sort_by) as sort_by:
                    for expected_reverse in (True, False, True):
                        for buttons in gesture:
                            t.draw(screen, view, 11)
                            start = next(
                                start
                                for start, _, label in view.header_regions
                                if label == "PID"
                            )
                            view.mouse((0, start, 2, 0, buttons), 24, 180)
                        self.assertEqual(view.sort_column, "PID")
                        self.assertEqual(view.sort_reverse, expected_reverse)
                    self.assertEqual(sort_by.call_count, 3)
        self.assertEqual(
            t.MOUSE_MASK & (press | release | click | double_click),
            press | release | click | double_click,
        )

    def test_header_press_sorts_immediately_but_its_release_cannot_sort_again(
        self,
    ):
        view = self.view()
        screen = Screen()
        t.draw(screen, view, 11)
        pid_x = next(start for start, _, label in view.header_regions if label == "PID")
        view.mouse((0, pid_x, 2, 0, t.curses.BUTTON1_PRESSED), 24, 180)
        self.assertEqual((view.sort_column, view.sort_reverse), ("PID", True))
        view.update(
            t.Update(t.Table(rows=(changed_row(Local="[2001:db8:ffff::1]:54321"),)), 12)
        )
        t.draw(screen, view, 12)
        app_x = next(start for start, _, label in view.header_regions if label == "App")
        view.mouse((0, app_x, 2, 0, t.curses.BUTTON1_RELEASED), 24, 180)
        self.assertEqual((view.sort_column, view.sort_reverse), ("PID", True))
        view.mouse((0, app_x, 2, 0, t.curses.BUTTON1_CLICKED), 24, 180)
        self.assertEqual((view.sort_column, view.sort_reverse), ("App", True))

    def test_sort_picker_can_choose_hidden_fields_cancel_and_restore_default_order(
        self,
    ):
        rows = tuple(changed_row(CWD=f"/work/{number}") for number in (30, 10, 20))
        view = self.view(rows)
        view.key(t.curses.KEY_F6, 12, 60)
        self.assertNotIn("State", view.sort_choices)
        self.assertNotIn("Origin", view.sort_choices)
        view.key(t.curses.KEY_END, 12, 60)
        self.assertEqual(view.sort_choices[view.sort_selected], "CWD")
        screen = Screen(12, 60)
        t.draw(screen, view, 11)
        self.assertTrue(
            any("CWD (hidden)" in text for text, _ in screen.lines.values())
        )
        self.assertFalse(view.header_regions)
        view.key("\n", 12, 60)
        self.assertIsNone(view.sort_choices)
        self.assertEqual(
            [row[-1] for row in view.filtered.rows],
            ["/work/10", "/work/20", "/work/30"],
        )
        view.key("r", 12, 60)
        self.assertTrue(view.sort_reverse)
        for cancel in ("\x1b", t.curses.KEY_F6):
            view.key(t.curses.KEY_F6, 12, 60)
            view.key(t.curses.KEY_HOME, 12, 60)
            view.key(cancel, 12, 60)
            self.assertEqual((view.sort_column, view.sort_reverse), ("CWD", True))
        view.key(t.curses.KEY_F6, 12, 60)
        view.key("\n", 12, 60)
        self.assertTrue(view.sort_reverse)
        view.key(t.curses.KEY_F6, 12, 60)
        view.key(t.curses.KEY_HOME, 12, 60)
        view.key("\n", 12, 60)
        self.assertEqual(view.filtered.rows, rows)
        self.assertFalse(view.sort_reverse)

    def test_picker_navigation_and_resize_keep_selection_and_sort_valid(self):
        view = self.view()
        view.key(t.curses.KEY_F6, 10, 60)
        view.wheel(t.WHEEL_DOWN, 10, 60)
        self.assertEqual((view.sort_selected, view.sort_offset), (5, 5))
        t.draw(Screen(10, 60), view, 11)
        view.key(t.curses.KEY_END, 10, 60)
        view.update(
            t.Update(t.Table(t.BASE_COLUMNS, (ROW[: len(t.BASE_COLUMNS)],)), 12)
        )
        for height in (1, 4, 12, 40):
            for width in (1, 30, 80, 300):
                t.draw(Screen(height, width), view, 12)
        self.assertEqual(view.sort_choices[view.sort_selected], "CWD")
        view.key("\n", 40, 300)
        view.update(t.Update(t.Table(LABELS, (ROW,)), 13))
        self.assertEqual(view.sort_column, "CWD")

    def test_sort_headers_stay_bounded_at_all_widths_and_picker_footer_can_cancel(self):
        view = self.view()
        for label in LABELS:
            if label in t.LOCKED_COLUMNS:
                continue
            view.sort_by(label)
            for width in range(1, 181):
                t.draw(Screen(12, width), view, 11)
                self.assertTrue(all(end < width for _, end, _ in view.header_regions))
        view.key(t.curses.KEY_F6, 5, 40)
        rows = t.footer_rows(view, 5, 40)
        self.assertEqual(rows, ["[Esc] Cancel | [q] Quit"])
        view.key("\x1b", 5, 40)
        self.assertIsNone(view.sort_choices)

    def test_sort_controls_do_not_intercept_search_text_or_overlay_mouse_events(self):
        for key in ("/", "?", "\n", t.curses.KEY_F6):
            view = self.view()
            screen = Screen()
            t.draw(screen, view, 11)
            start = next(
                start for start, _, label in view.header_regions if label == "App"
            )
            view.key(key, 24, 180)
            view.mouse((0, start, 2, 0, t.HEADER_CLICK), 24, 180)
            self.assertIsNone(view.sort_column)
        view = self.view()
        view.key("/", 24, 180)
        view.key("r", 24, 180)
        view.key(t.curses.KEY_F6, 24, 180)
        self.assertEqual(view.query, "r")
        self.assertIsNone(view.sort_choices)
        self.assertIsNone(view.sort_column)

    def test_header_clicks_are_dispatched_by_the_ui_loop_and_survive_refresh(self):
        rows = tuple(changed_row(PID=str(pid)) for pid in (300, 10, 20))
        view = self.view(rows)
        screen = Screen(keys=(t.curses.KEY_MOUSE, t.curses.KEY_MOUSE, "q"))
        t.draw(screen, view, 11)
        start = next(start for start, _, label in view.header_regions if label == "PID")
        screen.frames.clear()
        collector = mock.Mock()
        collector.latest.return_value = t.Update(t.Table(LABELS, rows), 10)
        with (
            mock.patch.object(t.curses, "has_colors", return_value=False),
            mock.patch.object(
                t.curses, "getmouse", return_value=(0, start, 2, 0, t.HEADER_CLICK)
            ),
        ):
            self.assertEqual(t.run_screen(screen, collector), 0)
        self.assertIn("PIDv", screen.frames[1][2][0])
        self.assertIn("300", screen.frames[1][3][0])
        self.assertIn("PID^", screen.frames[2][2][0])
        self.assertIn("10", screen.frames[2][3][0])
        collector.close.assert_called_once()

    def test_switching_to_a_different_header_always_starts_descending(self):
        view = self.view()
        screen = Screen()
        for label, expected_reverse in (
            ("PID", True),
            ("PID", False),
            ("App", True),
            ("CWD", True),
            ("CWD", False),
            ("PID", True),
        ):
            t.draw(screen, view, 11)
            x = next(
                start for start, _, heading in view.header_regions if heading == label
            )
            view.mouse((0, x, 2, 0, t.curses.BUTTON1_RELEASED), 24, 180)
            self.assertEqual(
                (view.sort_column, view.sort_reverse), (label, expected_reverse)
            )

    def test_layout_fits_every_terminal_width_and_expands_beyond_old_caps(self):
        row = changed_row(
            App=ROW[LABELS.index("App")] * 5, CWD=ROW[LABELS.index("CWD")] * 5
        )
        table = t.Table(LABELS, (row,))
        for width in range(401):
            layout = t.column_layout(table, width)
            self.assertLessEqual(
                sum(w for _, w in layout) + max(0, len(layout) - 1), width
            )
            self.assertLessEqual(t.text_width(t.render_row(table, row, layout)), width)
        small = dict(t.column_layout(table, 180))
        wide = dict(t.column_layout(table, 1000))
        self.assertGreater(wide[LABELS.index("App")], 112)
        self.assertGreater(wide[LABELS.index("CWD")], 64)
        self.assertGreater(wide[LABELS.index("App")], small[LABELS.index("App")])
        self.assertGreater(wide[LABELS.index("CWD")], small[LABELS.index("CWD")])
        self.assertEqual(
            wide[LABELS.index("App")], t.text_width(row[LABELS.index("App")])
        )
        self.assertEqual(
            wide[LABELS.index("CWD")], t.text_width(row[LABELS.index("CWD")])
        )

    def test_many_detail_columns_hide_then_return_when_there_is_room(self):
        labels = LABELS + tuple(f"Metadata {i}" for i in range(25))
        row = ROW + ("value" * 20,) * 25
        table = t.Table(labels, (row,))
        self.assertLess(len(t.column_layout(table, 80)), len(labels))
        self.assertEqual(len(t.column_layout(table, 4000)), len(labels) - 2)
        self.assertEqual(
            len(t.column_layout(table, 4000, show_queues=True)), len(labels)
        )
        for width in (1, 20, 80, 160, 268):
            layout = t.column_layout(table, width)
            self.assertLessEqual(t.text_width(t.render_row(table, row, layout)), width)

    def test_default_hides_queues_and_age_keeps_its_position_across_closure(self):
        expected = (
            "State",
            "Net",
            "Origin",
            "Local",
            "Peer",
            "Downloaded",
            "Uploaded",
            "Age",
            "PID",
            "User",
            "App",
            "CWD",
        )
        active = changed_row(
            State="ESTAB",
            Local="192.0.2.1:5000",
            Peer="198.51.100.2:443",
            Recv="123456",
            Send="654321",
        )
        for show_queues in (False, True):
            view = t.View(show_queues=show_queues)
            view.update(t.Update(t.Table(LABELS, (active,)), 100))
            for closed in (False, True):
                with self.subTest(show_queues=show_queues, closed=closed):
                    if closed:
                        view.update(t.Update(t.Table(LABELS), 101))
                    screen = Screen(width=1000)
                    t.draw(screen, view, 102)
                    visible = tuple(label for _, _, label in view.header_regions)
                    ordered = (
                        expected[:8]
                        + (("Recv", "Send") if show_queues else ())
                        + expected[8:]
                    )
                    self.assertEqual(
                        visible, ordered + (("Process age",) if closed else ())
                    )
                    view.query = "654321"
                    view.refilter()
                    self.assertEqual(len(view.filtered.rows), 1)
                    view.key("\n", 24, 1000)
                    self.assertIn("Recv: 123456", view.details)
                    self.assertIn("Send: 654321", view.details)
                    view.key("\n", 24, 1000)
                    view.query = ""

    def test_hidden_queues_free_width_for_process_columns(self):
        table = t.Table(LABELS, (changed_row(App="a" * 300, CWD="/" + "b" * 300),))
        compact = dict(t.column_layout(table, 240))
        verbose = dict(t.column_layout(table, 240, show_queues=True))
        self.assertGreater(
            sum(compact[LABELS.index(label)] for label in ("App", "CWD")),
            sum(verbose[LABELS.index(label)] for label in ("App", "CWD")),
        )

    def test_main_only_shows_queue_columns_in_verbose_or_all_details(self):
        for args in ([], ["--brief"], ["--verbose"], ["--all-details"]):
            with (
                self.subTest(args=args),
                mock.patch.object(t.sys.stdin, "isatty", return_value=True),
                mock.patch.object(t.sys.stdout, "isatty", return_value=True),
                mock.patch.object(t.curses, "wrapper", return_value=0) as wrapper,
                mock.patch.object(t.signal, "signal"),
            ):
                self.assertEqual(t.main(args), 0)
                self.assertEqual(
                    wrapper.call_args.kwargs["show_queues"],
                    bool(set(args) & {"--verbose", "--all-details"}),
                )

    def test_clipping_preserves_directory_suffix_and_endpoint_port(self):
        self.assertEqual(
            t.fit(ROW[LABELS.index("CWD")], 24, "tail"),
            "..." + ROW[LABELS.index("CWD")][-21:],
        )
        clipped = t.fit("[2001:db8:1234:5678::abcd]:54321", 20, "middle")
        self.assertTrue(clipped.startswith("[2001:db"))
        self.assertTrue(clipped.endswith(":54321"))
        for width in range(4):
            self.assertLessEqual(len(t.fit(ROW[LABELS.index("CWD")], width)), width)

    def test_unicode_width_and_terminal_control_sanitization(self):
        value = "\u7ea2\u9b54" * 20 + " e\u0301"
        self.assertEqual(t.text_width(value), 82)
        row = (*ROW[:-2], value, value + ROW[-1])
        table = t.Table.parse(raw_table(((*row[:-1], row[-1] + "\x1b[2J\x07"),)))
        self.assertNotIn("\x1b", table.rows[0][-1])
        self.assertNotIn("\x07", table.rows[0][-1])
        for width in range(1, 121):
            for mode in ("head", "middle", "tail"):
                self.assertLessEqual(t.text_width(t.fit(value, width, mode)), width)
            self.assertLessEqual(t.text_width(t.text_slice(value, 1, width)), width)
            layout = t.column_layout(table, width)
            self.assertLessEqual(
                t.text_width(t.render_row(table, table.rows[0], layout)), width
            )

    def test_wildcard_highlighting_is_for_actual_tcp_listeners(self):
        for host in ("0.0.0.0", "[::]", "*", "[::ffff:0.0.0.0]", "[0:0:0:0:0:0:0:0]"):
            self.assertTrue(t.wildcard_listener((*ROW[:3], host + ":22", *ROW[4:])))
        for host in ("127.0.0.1", "[::1]", "192.0.2.10", "not-an-ip"):
            self.assertFalse(t.wildcard_listener((*ROW[:3], host + ":22", *ROW[4:])))
        self.assertFalse(t.wildcard_listener(("BOUND", "udp", *ROW[2:])))
        self.assertFalse(t.wildcard_listener(("ESTAB", *ROW[1:])))

    def test_inbound_rows_have_their_own_style_and_selection_keeps_it(self):
        listener_style, inbound_style = 1 << 8, 2 << 8
        for state in ("ESTAB", "CLOSE-WAIT"):
            inbound = (state, "tcp", "INBOUND*", *ROW[3:])
            others = tuple(
                (state, "tcp", origin, *ROW[3:])
                for origin in ("OUTBOUND*", "SAME-HOST*", "UNKNOWN")
            )
            view = self.view((ROW, inbound, *others))
            view.selected = 1
            screen = Screen()
            t.draw(screen, view, 11, listener_style, inbound_style)
            self.assertEqual(screen.lines[3][1], listener_style)
            self.assertEqual(screen.lines[4][1], inbound_style | t.curses.A_REVERSE)
            for index in range(5, 8):
                self.assertEqual(screen.lines[index][1], 0)

    def test_palette_uses_yellow_and_cyan_and_honors_no_color(self):
        inbound = ("ESTAB", "tcp", "INBOUND*", *ROW[3:])
        for no_color in ("", "1"):
            collector = mock.Mock()
            collector.latest.return_value = t.Update(
                t.Table(LABELS, (ROW, inbound)), 10
            )
            screen = Screen(keys=("q",))
            with (
                mock.patch.dict(t.os.environ, {"NO_COLOR": no_color}),
                mock.patch.object(t.curses, "has_colors", return_value=True),
                mock.patch.object(t.curses, "use_default_colors"),
                mock.patch.object(t.curses, "init_pair") as init_pair,
                mock.patch.object(t.curses, "color_pair", side_effect=lambda i: i << 8),
            ):
                self.assertEqual(t.run_screen(screen, collector), 0)
            if no_color:
                init_pair.assert_not_called()
                self.assertEqual(screen.lines[4][1], t.curses.A_BOLD)
            else:
                self.assertEqual(
                    init_pair.call_args_list,
                    [
                        mock.call(1, t.curses.COLOR_YELLOW, -1),
                        mock.call(2, t.curses.COLOR_CYAN, -1),
                    ],
                )
                self.assertEqual(
                    screen.lines[3][1], t.curses.A_BOLD | t.curses.A_REVERSE | (1 << 8)
                )
                self.assertEqual(screen.lines[4][1], t.curses.A_BOLD | (2 << 8))

    def test_selection_survives_refresh_reorder_and_state_change(self):
        other = changed_row(PID="400")
        view = self.view((ROW, other))
        view.key(t.curses.KEY_DOWN, 24, 180)
        changed = ("CLOSE-WAIT", *other[1:])
        view.update(t.Update(t.Table(LABELS, (changed, ROW)), 11))
        self.assertEqual(view.selected, 0)
        self.assertEqual(view.selected_key()[-1], "400")
        view.update(t.Update(t.Table(LABELS, (ROW,)), 12))
        self.assertEqual(view.selected, 0)
        view.update(t.Update(t.Table(), 13))
        self.assertIsNone(view.selected_key())

    def test_filter_searches_all_fields_and_escape_restores_previous_filter(self):
        view = self.view()
        view.key("/", 10, 80)
        for key in "TRANSCRIPTION":
            view.key(key, 10, 80)
        self.assertEqual(len(view.filtered.rows), 1)
        view.key("x", 10, 80)
        self.assertFalse(view.filtered.rows)
        view.key(t.curses.KEY_BACKSPACE, 10, 80)
        view.key("\n", 10, 80)
        self.assertFalse(view.editing)
        self.assertEqual(view.query, "TRANSCRIPTION")
        view.key("/", 10, 80)
        view.key("q", 10, 80)
        view.key("\x1b", 10, 80)
        self.assertEqual(view.query, "TRANSCRIPTION")
        view.key("\x1b", 10, 80)
        self.assertEqual(view.query, "")

    def test_typed_search_matches_every_column_including_hidden_details(self):
        labels = LABELS + ("Command", "Metadata")
        row = (
            "ESTAB",
            "tcp",
            "INBOUND*",
            *changed_row(Downloaded="1048576", Uploaded="2048")[3:],
            "python --label 'literal.*value'",
            "extra detail",
        )
        other = ("-",) * len(labels)
        table = t.Table(labels, (row, other))
        self.assertLess(len(t.column_layout(table, 40)), len(labels))
        for index, value in enumerate(row):
            with self.subTest(column=labels[index]):
                view = t.View()
                view.update(t.Update(table, 10))
                view.key(t.curses.KEY_F3, 10, 40)
                for key in value.swapcase():
                    view.key(key, 10, 40)
                self.assertEqual(view.filtered.rows, (row,))
                view.key("\n", 10, 40)
                t.draw(Screen(10, 40), view, 11)
                view.update(t.Update(t.Table(labels, (other, row)), 12))
                self.assertEqual(view.filtered.rows, (row,))

    def test_search_stays_visible_after_enter_and_escape_clears_it(self):
        inbound = ("ESTAB", "tcp", "INBOUND*", *ROW[3:])
        view = self.view((ROW, inbound))
        view.key("/", 24, 180)
        for key in "inbound":
            view.key(key, 24, 180)
        screen = Screen()
        t.draw(screen, view, 11)
        self.assertIn("Search all columns: inbound_", screen.lines[23][0])
        self.assertEqual(view.filtered.rows, (inbound,))
        view.key("\n", 24, 180)
        t.draw(screen, view, 11)
        self.assertIn("Search all columns: inbound", screen.lines[23][0])
        self.assertIn("[Esc] Clear search", screen.lines[23][0])
        view.key("\x1b", 24, 180)
        t.draw(screen, view, 11)
        self.assertEqual(view.filtered.rows, (ROW, inbound))
        self.assertIn("[/ F3] Search", screen.lines[21][0])

    def test_search_focus_exits_overlays_and_long_input_shows_the_typed_end(self):
        view = self.view()
        view.key("\n", 24, 180)
        view.key("?", 24, 180)
        self.assertIsNotNone(view.details)
        self.assertTrue(view.help)
        view.key(t.curses.KEY_F3, 24, 180)
        self.assertIsNone(view.details)
        self.assertFalse(view.help)
        for key in "x" * 190 + "TAIL":
            view.key(key, 10, 40)
        screen = Screen(10, 40)
        t.draw(screen, view, 11)
        self.assertIn("TAIL_", screen.lines[9][0])
        view.key("\x15", 10, 40)
        self.assertEqual(view.query, "")
        self.assertEqual(view.filtered.rows, (ROW,))

    def test_details_include_hidden_fields_and_freeze_the_selected_record(self):
        view = self.view()
        view.key("\n", 8, 60)
        original = view.details
        self.assertIn("CWD: " + ROW[-1], original)
        view.key(t.curses.KEY_RIGHT, 8, 60)
        self.assertEqual(view.detail_x, 12)
        view.update(t.Update(t.Table(), 12))
        self.assertEqual(view.details, original)
        view.key("\n", 8, 60)
        self.assertIsNone(view.details)

    def test_details_resize_reveals_text_and_closing_preserves_filter(self):
        view = self.view()
        view.query = "fixture"
        view.refilter()
        view.key("\n", 8, 60)
        view.key(t.curses.KEY_RIGHT, 8, 60)
        view.key(t.curses.KEY_NPAGE, 8, 60)
        self.assertGreater(view.detail_x, 0)
        self.assertGreater(view.detail_y, 0)
        t.draw(Screen(30, 200), view, 11)
        self.assertEqual((view.detail_x, view.detail_y), (0, 0))
        view.key("\x1b", 30, 200)
        self.assertIsNone(view.details)
        self.assertEqual(view.query, "fixture")

    def test_no_color_and_failed_worker_start_restore_ui_without_extra_collection(self):
        collector = mock.Mock()
        collector.start.side_effect = OSError("worker unavailable")
        with (
            mock.patch.dict(t.os.environ, {"NO_COLOR": "1"}),
            mock.patch.object(t.curses, "init_pair") as init_color,
            self.assertRaises(OSError),
        ):
            t.run_screen(Screen(keys=("q",)), collector)
        init_color.assert_not_called()
        collector.latest.assert_not_called()
        collector.close.assert_called_once()
        not_started = t.Collector(["fixture-only"])
        not_started.close()
        self.assertTrue(not_started.stop.is_set())

    def test_draw_handles_resize_tiny_screens_and_both_directions_of_scrolling(self):
        view = self.view(tuple(changed_row(PID=str(pid)) for pid in range(60)))
        view.key(t.curses.KEY_END, 24, 180)
        for height in (1, 2, 3, 4, 5, 12, 24, 100):
            for width in (1, 2, 15, 60, 80, 160, 268, 500):
                screen = Screen(height, width)
                t.draw(screen, view, 11, listener_style=123)
                self.assertLessEqual(len(screen.lines), height)
        screen = Screen()
        view.key(t.curses.KEY_HOME, 24, 180)
        t.draw(screen, view, 11, listener_style=123)
        self.assertEqual(view.offset, 0)
        self.assertTrue(screen.lines[3][1] & t.curses.A_REVERSE)
        self.assertEqual(screen.lines[4][1], 123)
        view.key(t.curses.KEY_NPAGE, 24, 180)
        self.assertEqual(view.selected, t.body_rows(view, 24, 180))
        view.key(t.curses.KEY_PPAGE, 24, 180)
        self.assertEqual(view.selected, 0)

    def test_footer_separates_actions_navigation_and_context_specific_controls(self):
        view = self.view()
        for width in (80, 120, 180):
            rows = t.footer_rows(view, 24, width)
            self.assertEqual(len(rows), 3)
            self.assertIn("[q/F10] Quit", rows[0])
            self.assertIn("[/ F3] Search", rows[0])
            self.assertIn("[Enter] Details", rows[0])
            self.assertIn("[Space] Pause", rows[0])
            self.assertIn("[?] Help", rows[0])
            self.assertIn("[Click header/F6] Sort", rows[1])
            self.assertIn("[r] Reverse sort", rows[1])
            self.assertIn("[Up/Down] Select", rows[2])
            self.assertIn("[Wheel] 5 rows", rows[2])
            self.assertIn("[PgUp/PgDn] Page", rows[2])
            self.assertEqual(t.body_rows(view, 24, width), 18)
        view.key(" ", 24, 180)
        self.assertIn("[Space] Resume", " ".join(t.footer_rows(view, 24, 180)))
        view.key("/", 24, 180)
        view.key("p", 24, 180)
        rows = t.footer_rows(view, 24, 180)
        self.assertIn("[Enter] Apply", rows[0])
        self.assertIn("[Esc] Cancel", rows[0])
        self.assertIn("[Ctrl+U] Clear input", rows[0])
        self.assertEqual(rows[-1], "Search all columns: p_")
        view.key("\x1b", 24, 180)
        view.key("\n", 24, 180)
        rows = t.footer_rows(view, 24, 180)
        self.assertIn("[Enter/Esc] Back", rows[0])
        self.assertIn("[Left/Right] Scroll text", rows[1])

    def test_context_footer_stays_bounded_in_tiny_and_narrow_terminals(self):
        for mode in ("normal", "search", "filtered", "details", "help", "sort"):
            view = self.view()
            if mode in {"search", "filtered"}:
                view.query = "x" * 195
                view.editing = mode == "search"
            elif mode == "details":
                view.key("\n", 24, 180)
            elif mode == "help":
                view.key("?", 24, 180)
            elif mode == "sort":
                view.key(t.curses.KEY_F6, 24, 180)
            for height in (1, 2, 3, 4, 5, 8, 24):
                for width in (1, 2, 15, 40, 80, 180):
                    with self.subTest(mode=mode, height=height, width=width):
                        footers = t.footer_rows(view, height, width)
                        self.assertLessEqual(len(footers), max(1, min(5, height - 4)))
                        self.assertGreaterEqual(t.body_rows(view, height, width), 0)
                        self.assertTrue(
                            all(t.text_width(row) < width for row in footers)
                        )
                        t.draw(Screen(height, width), view, 11)

    def test_wheel_scrolls_viewport_five_rows_immediately_and_preserves_arrow_step(
        self,
    ):
        rows = tuple(changed_row(PID=str(pid)) for pid in range(60))
        view = self.view(rows)
        view.wheel(t.WHEEL_DOWN, 24, 180)
        self.assertEqual((view.selected, view.offset), (5, 5))
        t.draw(Screen(), view, 11)
        self.assertEqual(view.offset, 5)
        view.key(t.curses.KEY_DOWN, 24, 180)
        self.assertEqual((view.selected, view.offset), (6, 5))
        view.wheel(t.WHEEL_UP, 24, 180)
        self.assertEqual((view.selected, view.offset), (1, 0))
        for _ in range(20):
            view.wheel(t.WHEEL_DOWN, 24, 180)
        self.assertEqual(view.selected, 59)
        self.assertEqual(view.offset, 60 - t.body_rows(view, 24, 180))
        view.wheel(t.curses.BUTTON1_PRESSED, 24, 180)
        self.assertEqual(view.selected, 59)
        for _ in range(20):
            view.wheel(t.WHEEL_UP | t.curses.BUTTON_CTRL, 24, 180)
        self.assertEqual((view.selected, view.offset), (0, 0))

    def test_wheel_handles_filtered_empty_details_and_help_views(self):
        view = self.view(tuple(changed_row(PID=str(pid)) for pid in range(60)))
        view.key("/", 10, 80)
        for key in "zzzz":
            view.key(key, 10, 80)
        self.assertEqual(view.filtered.rows, ())
        view.wheel(t.WHEEL_DOWN, 10, 80)
        self.assertEqual((view.selected, view.offset), (0, 0))
        self.assertEqual(view.query, "zzzz")
        view.key("\x1b", 10, 80)
        view.key("\n", 8, 80)
        view.wheel(t.WHEEL_DOWN, 8, 80)
        self.assertEqual(view.detail_y, 5)
        self.assertEqual(view.selected, 0)
        view.wheel(t.WHEEL_UP, 8, 80)
        self.assertEqual(view.detail_y, 0)
        view.key("\x1b", 10, 80)
        view.key("?", 10, 80)
        view.wheel(t.WHEEL_DOWN, 10, 80)
        self.assertEqual(view.help_y, 5)
        screen = Screen(10, 80)
        t.draw(screen, view, 11)
        self.assertEqual(screen.lines[2][0], t.fit(t.HELP[5], 79))
        view.key(t.curses.KEY_UP, 10, 80)
        self.assertEqual(view.help_y, 4)

    def test_mouse_events_are_enabled_dispatched_and_restored_on_exit(self):
        rows = tuple(changed_row(PID=str(1000 + pid)) for pid in range(60))
        for last in ("q", KeyboardInterrupt()):
            collector = mock.Mock()
            collector.latest.return_value = t.Update(t.Table(LABELS, rows), 10)
            screen = Screen(keys=(t.curses.KEY_MOUSE, last))
            with (
                mock.patch.object(t.curses, "has_colors", return_value=False),
                mock.patch.object(
                    t.curses, "mousemask", return_value=(t.MOUSE_MASK, 123)
                ) as mask,
                mock.patch.object(
                    t.curses, "mouseinterval", return_value=166
                ) as interval,
                mock.patch.object(
                    t.curses, "getmouse", return_value=(0, 5, 5, 0, t.WHEEL_DOWN)
                ) as getmouse,
            ):
                if isinstance(last, BaseException):
                    with self.assertRaises(KeyboardInterrupt):
                        t.run_screen(screen, collector)
                else:
                    self.assertEqual(t.run_screen(screen, collector), 0)
            self.assertIn("1005", screen.frames[1][3][0])
            self.assertEqual(
                mask.call_args_list,
                [mock.call(t.MOUSE_MASK), mock.call(123)],
            )
            self.assertEqual(interval.call_args_list, [mock.call(0), mock.call(166)])
            getmouse.assert_called_once()
            collector.close.assert_called_once()

    def test_unsupported_mouse_and_stale_mouse_events_do_not_break_keyboard_controls(
        self,
    ):
        collector = mock.Mock()
        collector.latest.return_value = None
        with (
            mock.patch.object(t.curses, "has_colors", return_value=False),
            mock.patch.object(
                t.curses, "mousemask", side_effect=t.curses.error("unsupported")
            ),
            mock.patch.object(t.curses, "mouseinterval") as interval,
            mock.patch.object(
                t.curses, "getmouse", side_effect=t.curses.error("expired event")
            ),
        ):
            self.assertEqual(
                t.run_screen(Screen(keys=(t.curses.KEY_MOUSE, "q")), collector), 0
            )
        interval.assert_not_called()
        collector.close.assert_called_once()

    def test_missing_mouse_click_support_is_visible_without_hiding_the_table(self):
        for available in (0, t.WHEEL_UP | t.WHEEL_DOWN):
            collector = mock.Mock()
            collector.latest.return_value = t.Update(t.Table(rows=(ROW,)), 10)
            screen = Screen(keys=("q",))
            with (
                mock.patch.object(t.curses, "has_colors", return_value=False),
                mock.patch.object(t.curses, "mousemask", return_value=(available, 0)),
                mock.patch.dict(t.os.environ, {"TERM": "fixture-terminal"}),
            ):
                self.assertEqual(t.run_screen(screen, collector), 0)
            self.assertIn(
                "Mouse clicks unavailable (TERM=fixture-terminal)",
                screen.frames[0][1][0],
            )
            self.assertIn("State[1]", screen.frames[0][2][0])
            self.assertIn("LISTEN", screen.frames[0][3][0])

    def test_mouse_decode_errors_are_visible_and_clear_after_a_successful_event(self):
        collector = mock.Mock()
        collector.latest.return_value = t.Update(t.Table(rows=(ROW,)), 10)
        screen = Screen(keys=(t.curses.KEY_MOUSE, t.curses.KEY_MOUSE, "q"))
        with (
            mock.patch.object(t.curses, "has_colors", return_value=False),
            mock.patch.object(
                t.curses,
                "getmouse",
                side_effect=[
                    t.curses.error("invalid event"),
                    (0, 0, 0, 0, t.WHEEL_DOWN),
                ],
            ),
            mock.patch.dict(t.os.environ, {"TERM": "fixture-terminal"}),
        ):
            self.assertEqual(t.run_screen(screen, collector), 0)
        self.assertIn(
            "Mouse decoding failed (TERM=fixture-terminal): invalid event",
            screen.frames[1][1][0],
        )
        self.assertNotIn("Mouse decoding failed", screen.frames[2][1][0])

    def test_errors_retain_snapshot_and_make_staleness_visible(self):
        view = self.view()
        view.update(t.Update(error="snapshot failed"))
        self.assertEqual(view.table.rows, (ROW,))
        self.assertEqual(view.sampled_at, 10)
        screen = Screen()
        t.draw(screen, view, 25)
        self.assertIn("STALE", screen.lines[0][0])
        self.assertIn("15.0s ago", screen.lines[0][0])
        self.assertEqual(screen.lines[1][0], "snapshot failed")
        view.update(
            t.Update(t.Table(LABELS, (ROW,)), 25, warning="conntrack unavailable")
        )
        t.draw(screen, view, 25)
        self.assertIn("LIVE", screen.lines[0][0])
        self.assertEqual(screen.lines[1][0], "conntrack unavailable")

    def test_ui_keyboard_loop_closes_collector_on_quit_or_interrupt(self):
        for last in ("q", KeyboardInterrupt()):
            collector = mock.Mock()
            collector.latest.side_effect = [
                t.Update(t.Table(LABELS, (ROW,)), 10),
                None,
                None,
            ]
            screen = Screen(keys=(" ", " ", last))
            with mock.patch.object(t.curses, "has_colors", return_value=False):
                if isinstance(last, BaseException):
                    with self.assertRaises(KeyboardInterrupt):
                        t.run_screen(screen, collector)
                else:
                    self.assertEqual(t.run_screen(screen, collector), 0)
            collector.start.assert_called_once()
            collector.close.assert_called_once()
            self.assertIn("PAUSED", screen.frames[1][0][0])

    def test_snapshot_command_uses_existing_read_only_function_and_literal_arguments(
        self,
    ):
        options = argparse.Namespace(brief=False, verbose=True, all_details=False)
        command = t.snapshot_command(options)
        self.assertEqual(command[:4], ["bash", "-o", "pipefail", "-c"])
        self.assertEqual(command[4], 'source "$1"; socket_snapshot "$2" "$3" "$4" 1')
        self.assertEqual(command[-3:], ["0", "0", "1"])
        self.assertTrue(command[-4].endswith("/netmgr"))

    def test_capture_is_noninteractive_and_drains_both_pipes(self):
        proc = mock.Mock(returncode=0)
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired("fixture", 0.1),
            (raw_table(), "warning\n"),
        ]
        with mock.patch.object(t.subprocess, "Popen", return_value=proc) as popen:
            update = t.Collector(["fixture-only"]).capture()
        self.assertEqual(update.table.rows, (ROW,))
        self.assertEqual(update.warning, "warning")
        self.assertGreaterEqual(update.completed_at, update.sampled_at)
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(popen.call_args.kwargs["process_group"], 0)
        self.assertNotIn("start_new_session", popen.call_args.kwargs)
        self.assertEqual(proc.communicate.call_count, 2)

    def test_capture_failure_or_malformed_rows_are_not_displayed_as_success(self):
        proc = mock.Mock(returncode=7)
        proc.communicate.return_value = (raw_table(), "not authorized")
        with mock.patch.object(t.subprocess, "Popen", return_value=proc):
            result = t.Collector(["fixture-only"]).capture()
            self.assertIsNone(result.table)
            self.assertEqual(result.error, "not authorized")
            proc.returncode = 0
            proc.communicate.return_value = ("bad\n", "")
            with self.assertRaises(ValueError):
                t.Collector(["fixture-only"]).capture()

    def test_capture_timeout_and_cancellation_stop_collector_process_group(self):
        for cancelled in (False, True):
            collector = t.Collector(["fixture-only"])
            if cancelled:
                collector.stop.set()
            proc = mock.Mock()
            with (
                mock.patch.object(t.subprocess, "Popen", return_value=proc),
                mock.patch.object(t.time, "monotonic", side_effect=[0, 16]),
                mock.patch.object(t, "terminate") as terminate,
            ):
                update = collector.capture()
            terminate.assert_called_once_with(proc)
            if cancelled:
                self.assertIsNone(update)
            else:
                self.assertIn("timed out", update.error)

    def test_group_termination_escalates_and_reaps(self):
        proc = mock.Mock(pid=999)
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired("fixture", 0.5),
            ("", ""),
        ]
        with mock.patch.object(t.os, "killpg") as killpg:
            t.terminate(proc)
        self.assertEqual(
            killpg.call_args_list,
            [mock.call(999, signal.SIGTERM), mock.call(999, signal.SIGKILL)],
        )
        self.assertEqual(proc.communicate.call_count, 2)

    def test_scheduler_uses_one_second_cadence_without_overlap_or_update_backlog(self):
        collector = t.Collector(["fixture-only"])
        clock, starts, delays = [0.0], [], []
        durations = iter((0.2, 1.5, 0.4))
        stop = mock.Mock()
        stop.is_set.side_effect = lambda: len(delays) == 3

        def capture():
            starts.append(clock[0])
            clock[0] += next(durations)
            return t.Update(error=f"frame {len(starts)}")

        def wait(delay):
            delays.append(delay)
            clock[0] += delay

        stop.wait.side_effect = wait
        collector.stop = stop
        with (
            mock.patch.object(t.time, "monotonic", side_effect=lambda: clock[0]),
            mock.patch.object(collector, "capture", side_effect=capture),
        ):
            collector.run()
        self.assertEqual(starts, [0, 1, 2.5])
        self.assertEqual(delays[:2], [0.8, 0])
        self.assertAlmostEqual(delays[2], 0.6)
        self.assertEqual(collector.latest().error, "frame 3")
        self.assertIsNone(collector.latest())

    def test_main_restores_signal_handlers_after_terminal_exit_paths(self):
        for failure, code in (
            (KeyboardInterrupt(), 130),
            (t.TerminalExit(signal.SIGTERM), 143),
            (t.curses.error("no terminal"), 1),
        ):
            old = mock.Mock()
            with (
                mock.patch.object(t.sys.stdin, "isatty", return_value=True),
                mock.patch.object(t.sys.stdout, "isatty", return_value=True),
                mock.patch.object(t.sys, "stderr", io.StringIO()),
                mock.patch.object(t.curses, "wrapper", side_effect=failure),
                mock.patch.object(t.signal, "signal", return_value=old) as signals,
            ):
                self.assertEqual(t.main([]), code)
            self.assertEqual(
                signals.call_args_list[-2:],
                [mock.call(signal.SIGTERM, old), mock.call(signal.SIGHUP, old)],
            )


if __name__ == "__main__":
    unittest.main()
