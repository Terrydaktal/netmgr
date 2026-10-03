"""Read-only, terminal-sized socket snapshots; no network probes or packet capture."""

from __future__ import annotations

import argparse
import curses
import dataclasses
import ipaddress
import os
import queue
import re
import select
import signal
import subprocess
import sys
import threading
import time
import unicodedata
from collections import deque
from functools import lru_cache
from pathlib import Path

INTERVAL = 1.0
SNAPSHOT_TIMEOUT = 15.0
RECENT_SECONDS = 60
MAX_RECENT = 512
MAX_EVENTS = 2048
MAX_EVENT_LINE = 16384
WHEEL_ROWS = 5
WHEEL_UP = getattr(curses, "BUTTON4_PRESSED", 0)
WHEEL_DOWN = getattr(curses, "BUTTON5_PRESSED", 0)
LEFT_PRESS = getattr(curses, "BUTTON1_PRESSED", 0)
HEADER_CLICK = getattr(curses, "BUTTON1_RELEASED", 0)
LEFT_CLICK = getattr(curses, "BUTTON1_CLICKED", 0)
LEFT_DOUBLE_CLICK = getattr(curses, "BUTTON1_DOUBLE_CLICKED", 0)
HEADER_MOUSE_MASK = LEFT_PRESS | HEADER_CLICK | LEFT_CLICK | LEFT_DOUBLE_CLICK
MOUSE_MASK = WHEEL_UP | WHEEL_DOWN | HEADER_MOUSE_MASK
BASE_COLUMNS = (
    "State",
    "Net",
    "Origin",
    "Local",
    "Peer",
    "Downloaded",
    "Uploaded",
    "Recv",
    "Send",
    "PID",
)
TRAFFIC_COLUMNS = {"Downloaded", "Uploaded"}
GLOBAL_PRIMARY_COLUMNS = TRAFFIC_COLUMNS | {"Age"}
NUMERIC_COLUMNS = TRAFFIC_COLUMNS | {"Recv", "Send"}
IDENTITY_COLUMNS = tuple(
    BASE_COLUMNS.index(label) for label in ("Net", "Local", "Peer", "PID")
)
LOCKED_COLUMNS = {"State", "Origin"}
ORIGIN_ORDER = {"-": 0, "OUTBOUND*": 1, "SAME-HOST*": 2, "INBOUND*": 3, "UNKNOWN": 4}
ALIASES = {
    "Netid": "Net",
    "Local Address:Port": "Local",
    "Peer Address:Port": "Peer",
    "Recv-Q": "Recv",
    "Send-Q": "Send",
}
MIN_WIDTH = {
    "State": 9,
    "Net": 3,
    "Origin": 9,
    "Local": 12,
    "Peer": 12,
    "Downloaded": 10,
    "Uploaded": 8,
    "Recv": 4,
    "Send": 4,
    "PID": 5,
    "User": 6,
    "Age": 5,
    "Process age": 11,
    "App": 12,
    "CWD": 12,
}
PRIORITY = {
    "State": 100,
    "Local": 95,
    "Peer": 94,
    "Origin": 90,
    "App": 85,
    "CWD": 80,
    "Net": 65,
    "PID": 60,
    "Downloaded": 55,
    "Uploaded": 54,
    "Command": 50,
    "User": 40,
    "Age": 30,
    "Process age": 25,
    "Recv": 20,
    "Send": 19,
}
HELP = (
    "Read-only socket monitor | one snapshot per second, no overlapping collectors",
    "Up/Down or j/k: select   PgUp/PgDn: page   Home/End: first/last",
    "Mouse wheel: scroll five rows per notch; arrow keys still move one row",
    "Click a column header: descending first, then ascending; each click reverses",
    "Header v means descending, ^ means ascending; r also reverses the selected key",
    "F6: choose any sort column, including hidden fields; Enter applies, Esc cancels",
    "Age, Downloaded and Uploaded sort globally, then by State[2] > Origin[3].",
    "Other columns keep State[1] > Origin[2]; missing values stay last.",
    "Click State or F6 > Default to restore State > Origin > Net > Local > Port.",
    "/ or F3: type a search across all columns, including hidden/untruncated values",
    "Search is live, literal and case-insensitive; Enter applies, Esc cancels/clears",
    "Ctrl+U clears the search input; the applied search stays visible after Enter",
    "Space: freeze/resume display (collection continues)",
    "Enter: inspect selected row; arrows scroll fields/text without wrapping",
    "?: help   q/F10: quit   Ctrl+C: interrupt",
    "Columns shrink/hide to fit, and expand on resize; Enter includes hidden fields.",
    "Yellow: TCP listener bound to all interfaces; not proof of firewall exposure.",
    "Cyan: inferred INBOUND* connection; other origins keep their normal colour.",
    "OUTBOUND*/INBOUND*: inferred local/remote initiator; SAME-HOST*: local endpoints.",
    "*: inference only; conntrack may start midstream. UNKNOWN: no unique match.",
    "-: listener/no connected peer. BOUND: UDP local port with no fixed peer.",
    "Age is process age for live rows; for CLOSED/GONE* it is time since closure was seen.",
    "Downloaded/Uploaded: TCP lifetime bytes received/acknowledged, not file sizes.",
    "Totals use binary units; Enter shows exact bytes. UDP/listeners/missing: -.",
    "Recv/Send: queue sizes, not traffic totals or speeds. No packet capture added.",
    "Recv/Send are in --verbose/--all-details and Enter details, not the default table.",
    "CLOSED: ss -E saw destruction. GONE*: absent from a successful snapshot.",
    "GONE* age starts at first successful absence, not the unknown exact close time.",
    "Recent rows last 60s; Process age keeps their last known process uptime.",
    "Recent rows retain known details across sparse refreshes and late snapshots.",
    "Short connections may lack PID, origin or byte totals if never sampled.",
    "The event listener retries after failure; the warning appears above the table.",
    "Collection errors retain the old table and show STALE plus snapshot age.",
)


def safe_text(value):
    return "".join(char if char.isprintable() else " " for char in value)


def display_value(label, value, *, exact=False):
    if label not in TRAFFIC_COLUMNS or not re.fullmatch(r"[0-9]+", value):
        return value
    amount = int(value)
    if exact:
        return f"{amount} bytes"
    if amount < 1024:
        return f"{amount}B"
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")
    unit = 0
    while amount >= 1024 and unit < len(units) - 1:
        amount /= 1024
        unit += 1
    if amount >= 1023.95 and unit < len(units) - 1:
        amount /= 1024
        unit += 1
    return f"{amount:.1f}{units[unit]}"


@lru_cache(maxsize=8192)
def char_width(char):
    if unicodedata.combining(char):
        return 0
    return 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1


def text_width(value):
    return sum(map(char_width, value))


def text_slice(value, start, width):
    result, position = [], 0
    for char in value:
        size = char_width(char)
        if position + size > start + width:
            break
        if position >= start and (size or result):
            result.append(char)
        elif position < start < position + size:
            result.append(" " * (position + size - start))
        position += size
    return "".join(result)


def fit(value, width, mode="head"):
    size = text_width(value)
    if size <= width:
        return value
    if width <= 3:
        return "." * max(0, width)
    room = width - 3
    if mode == "tail":
        return "..." + text_slice(value, size - room, room)
    if mode == "middle":
        left = room // 2
        return (
            text_slice(value, 0, left)
            + "..."
            + text_slice(value, size - room + left, room - left)
        )
    return text_slice(value, 0, room) + "..."


def pack_controls(items, width):
    rows, current = [], ""
    for item in items:
        combined = f"{current} | {item}" if current else item
        if current and text_width(combined) > width:
            rows.append(current)
            current = fit(item, width)
        else:
            current = fit(combined, width)
    if current:
        rows.append(current)
    return rows


def footer_rows(view, height, columns):
    width = max(0, columns - 1)
    navigation = [
        "[Up/Down] Select",
        "[Wheel] 5 rows",
        "[PgUp/PgDn] Page",
        "[Home/End] First/last",
    ]
    prompt = None
    if view.editing:
        groups = [
            [
                "[Enter] Apply",
                "[Esc] Cancel",
                "[Ctrl+U] Clear input",
                "[Backspace] Delete",
            ]
        ]
    elif view.sort_choices is not None:
        groups = [
            ["[Enter] Sort", "[Esc/F6] Cancel", "[q/F10] Quit"],
            navigation,
        ]
    elif view.help or view.details is not None:
        back = "[?/Esc] Back" if view.help else "[Enter/Esc] Back"
        groups = [
            [back, "[q/F10] Quit"],
            ["[Up/Down] Scroll", "[Wheel] 5 rows", "[PgUp/PgDn] Page"],
        ]
        if view.details is not None:
            groups[1].append("[Left/Right] Scroll text")
    else:
        groups = [
            [
                "[q/F10] Quit",
                "[/ F3] Search",
                "[Enter] Details",
                "[Space] Resume" if view.paused else "[Space] Pause",
                "[?] Help",
            ],
            ["[Click header/F6] Sort", "[r] Reverse sort"],
            navigation,
        ]
    if view.editing or (
        view.query
        and not view.help
        and view.details is None
        and view.sort_choices is None
    ):
        prefix = "Search all columns: "
        suffix = "_" if view.editing else "  [Esc] Clear search"
        if width - len(prefix + suffix) < 8:
            prefix, suffix = "Search: ", "_" if view.editing else ""
        prompt = fit(
            prefix
            + fit(view.query, max(0, width - len(prefix + suffix)), "tail")
            + suffix,
            width,
        )
    rows = [row for group in groups for row in pack_controls(group, width)]
    # Preserve a usable viewport; tiny terminals get the essential controls first.
    budget = max(1, min(5, height - 4))
    control_budget = budget - (prompt is not None)
    if len(rows) > control_budget:
        rows = rows[:control_budget]
        if rows and not view.editing:
            rows[-1] = fit(
                "[Esc] Cancel | [q] Quit"
                if view.sort_choices is not None
                else "[q] Quit | [?] All controls",
                width,
            )
    if prompt is not None:
        rows.append(prompt)
    return rows


def body_rows(view, height, width):
    return max(
        0, height - (2 if view.help else 3) - len(footer_rows(view, height, width))
    )


@dataclasses.dataclass(frozen=True)
class Table:
    labels: tuple[str, ...] = BASE_COLUMNS + ("User", "Age", "App", "CWD")
    rows: tuple[tuple[str, ...], ...] = ()
    widths: tuple[int, ...] = dataclasses.field(init=False)

    def __post_init__(self):
        object.__setattr__(
            self,
            "widths",
            tuple(
                max(
                    text_width(label),
                    max(
                        (text_width(display_value(label, row[i])) for row in self.rows),
                        default=0,
                    ),
                )
                for i, label in enumerate(self.labels)
            ),
        )

    @classmethod
    def parse(cls, output):
        lines = output.rstrip("\n").split("\n")
        labels = tuple(ALIASES.get(label, label) for label in lines[0].split("\t"))
        if labels[: len(BASE_COLUMNS)] != BASE_COLUMNS or len(set(labels)) != len(
            labels
        ):
            raise ValueError("invalid socket snapshot header")
        rows = tuple(
            tuple(safe_text(cell) for cell in line.split("\t")) for line in lines[1:]
        )
        if any(len(row) != len(labels) for row in rows):
            raise ValueError("incomplete socket snapshot row")
        return cls(labels, rows)


def natural_key(value):
    # Length plus digits avoids integer-size limits in arbitrary command/path text.
    return tuple(
        (1, len(part.lstrip("0")), part.lstrip("0"))
        if part.isascii() and part.isdecimal()
        else (0, part.casefold())
        for part in re.split(r"([0-9]+)", value)
    )


def endpoint_key(value):
    host, _, port = value.rpartition(":")
    host, _, zone = host.strip("[]").partition("%")
    if host == "*":
        return (0, 0, (), natural_key(port))
    try:
        address = ipaddress.ip_address(host)
        return (address.version, int(address), natural_key(zone), natural_key(port))
    except ValueError:
        return (9, 0, natural_key(host), natural_key(port or value))


def age_key(value):
    result = []
    for age in value.split(" | "):
        if re.fullmatch(r"(?:[0-9]+[dhms])+", age):
            seconds = sum(
                int(number) * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
                for number, unit in re.findall(r"([0-9]+)([dhms])", age)
            )
            result.append((0, seconds))
        else:
            result.append((1, natural_key(age)))
    return tuple(result)


def state_origin_key(row):
    # BOUND is only a display alias; preserve the shell's original UNCONN position.
    state = "UNCONN" if row[0] == "BOUND" else row[0]
    if state in {"CLOSED", "GONE*"}:
        state = "ZZZ" + state
    return (state, ORIGIN_ORDER.get(row[2], 4))


def sorted_rows(table, label, reverse=False):
    if label is None or label in LOCKED_COLUMNS or label not in table.labels:
        return table.rows
    index = table.labels.index(label)
    key = (
        endpoint_key
        if label in {"Local", "Peer"}
        else age_key
        if label in {"Age", "Process age"}
        else natural_key
    )
    global_primary = label in GLOBAL_PRIMARY_COLUMNS
    rows = (
        sorted(table.rows, key=state_origin_key) if global_primary else list(table.rows)
    )
    rows.sort(key=lambda row: key(row[index]), reverse=reverse)
    # Global keys use State/Origin only for ties; other keys stay inside those
    # groups. Missing values remain last in either direction.
    rows.sort(
        key=lambda row: (
            (() if global_primary else state_origin_key(row))
            + (
                all(
                    part.strip() in {"", "-", "?"}
                    for part in re.split(r" \| |;", row[index])
                ),
            )
        )
    )
    return tuple(rows)


def column_layout(table, width, headings=None, *, show_queues=False):
    """Keep useful columns, then share remaining space up to each field's full width."""
    if width <= 0:
        return ()
    headings = headings or table.labels
    recent_mode = "Process age" in table.labels or any(
        row[0] in {"CLOSED", "GONE*"} for row in table.rows
    )
    needs = tuple(max(need, text_width(h)) for need, h in zip(table.widths, headings))
    active = [
        i
        for i, label in enumerate(table.labels)
        if show_queues or label not in {"Recv", "Send"}
    ]
    if "Age" in table.labels:
        age_index = table.labels.index("Age")
        active.remove(age_index)
        active.insert(sum(i < BASE_COLUMNS.index("Recv") for i in active), age_index)
    sizes = [
        min(need, max(text_width(h), MIN_WIDTH.get(label, max(8, len(label)))))
        for label, h, need in zip(table.labels, headings, needs)
    ]
    while len(active) > 1 and sum(sizes[i] for i in active) + len(active) - 1 > width:
        active.remove(
            min(
                active,
                key=lambda i: (
                    99
                    if recent_mode and table.labels[i] == "Age"
                    else PRIORITY.get(table.labels[i], 0),
                    -i,
                ),
            )
        )
    if len(active) == 1:
        return ((active[0], min(needs[active[0]], width)),)
    spare = width - sum(sizes[i] for i in active) - len(active) + 1
    for i in active:
        if table.labels[i] in {
            "State",
            "Net",
            "Origin",
            "Downloaded",
            "Uploaded",
            "Recv",
            "Send",
            "PID",
            "User",
            "Age",
        }:
            extra = min(spare, needs[i] - sizes[i])
            sizes[i] += extra
            spare -= extra
    while spare > 0:
        grew = False
        for i in active:
            weight = 3 if table.labels[i] in {"App", "CWD", "Command"} else 2
            extra = min(spare, needs[i] - sizes[i], weight)
            sizes[i] += extra
            spare -= extra
            grew |= extra > 0
        if not grew:
            break
    return tuple((i, sizes[i]) for i in active)


def render_row(table, row, layout, header=False):
    fields = []
    for index, width in layout:
        label = table.labels[index]
        mode = (
            "head"
            if header
            else "tail"
            if label == "CWD"
            else "middle"
            if label in {"Local", "Peer"}
            else "head"
        )
        value = fit(
            row[index] if header else display_value(label, row[index]), width, mode
        )
        padding = " " * (width - text_width(value))
        fields.append(padding + value if label in NUMERIC_COLUMNS else value + padding)
    return " ".join(fields)


def wildcard_listener(row):
    if row[0] != "LISTEN":
        return False
    host = row[3].rpartition(":")[0].strip("[]")
    if host == "*":
        return True
    try:
        ip = ipaddress.ip_address(host)
        return (getattr(ip, "ipv4_mapped", None) or ip).is_unspecified
    except ValueError:
        return False


@dataclasses.dataclass
class Update:
    table: Table | None = None
    sampled_at: float = 0.0
    warning: str = ""
    error: str = ""
    completed_at: float | None = None


@dataclasses.dataclass(frozen=True)
class Destroyed:
    values: dict[str, str]
    when: float


def event_command():
    return ["sudo", "-n", "ss", "-E", "-H", "-a", "-t", "-u", "-n", "-p", "-i", "-O"]


def connection_key(row):
    if row[1] not in {"tcp", "udp"} or row[0] in {"LISTEN", "BOUND", "CLOSED", "GONE*"}:
        return None
    peer_port = row[4].rpartition(":")[2]
    if not peer_port.isdecimal() or not 0 < int(peer_port) <= 65535:
        return None
    return row[1], row[3], row[4]


def has_detail(value):
    return any(part.strip() not in {"", "-", "?"} for part in value.split(" | "))


def owners_changed(previous, current):
    before = set(previous.get("PID", "-").split(";")) - {"", "-", "?"}
    after = set(current.get("PID", "-").split(";")) - {"", "-", "?"}
    return bool(before and after and before != after)


def connection_restarted(previous, current):
    if owners_changed(previous, current):
        return True
    if current.get("Net") != "tcp":
        return False
    if previous.get("State") in {
        "CLOSE",
        "CLOSE-WAIT",
        "FIN-WAIT-1",
        "FIN-WAIT-2",
        "TIME-WAIT",
        "LAST-ACK",
        "CLOSING",
    } and current.get("State") in {"SYN-SENT", "SYN-RECV", "ESTAB"}:
        return True
    return any(
        previous.get(label, "-").isdecimal()
        and current.get(label, "-").isdecimal()
        and int(current[label]) < int(previous[label])
        for label in TRAFFIC_COLUMNS
    )


def merge_socket_values(previous, current, *, event=False):
    values = dict(previous)
    for label, new in current.items():
        old = values.setdefault(label, "-")
        if label in TRAFFIC_COLUMNS:
            if new.isdecimal() and (not old.isdecimal() or int(new) >= int(old)):
                values[label] = new
        elif label in {"State", "Net", "Local", "Peer", "Recv", "Send", "Metadata"}:
            values[label] = new
        elif has_detail(new) and not (label == "Origin" and new == "UNKNOWN"):
            if event and has_detail(old) and old != "UNKNOWN":
                continue
            # A failed /proc read can leave only the executable plus an unknown parent.
            if label == "App" and new.endswith("<-?") and old.startswith(new[:-1]):
                continue
            values[label] = new
        elif label not in previous:
            values[label] = new
    return values


def parse_destroyed(line, when):
    line = safe_text(line)
    parts = line.split(None, 6)
    if len(parts) < 6 or parts[0] not in {"tcp", "udp"}:
        return None
    protocol, state, recv, send, local, peer = parts[:6]
    if not recv.isdecimal() or not send.isdecimal() or ":" not in local:
        return None
    values = dict.fromkeys(BASE_COLUMNS, "-")
    values.update(
        State=state,
        Net=protocol,
        Origin="UNKNOWN",
        Local=local,
        Peer=peer,
        Recv=recv,
        Send=send,
    )
    if connection_key(tuple(values[label] for label in BASE_COLUMNS)) is None:
        return None
    tail = parts[6] if len(parts) == 7 else ""
    owners = re.findall(r'\("((?:\\.|[^"\\])*)",pid=(\d+),fd=\d+\)', tail)
    if owners:
        values["PID"] = ";".join(dict.fromkeys(pid for _, pid in owners))
        values["App"] = " | ".join(dict.fromkeys(name for name, _ in owners))
    counters = re.sub(r'"(?:\\.|[^"\\])*"', "", tail)
    received = re.findall(r"(?<!\w)bytes_received:([0-9]+)(?!\S)", counters)
    acked = re.findall(r"(?<!\w)bytes_acked:([0-9]+)(?!\S)", counters)
    if protocol == "tcp" and (received or acked):
        for label, matches in (("Downloaded", received), ("Uploaded", acked)):
            if len(matches) == 1 and int(matches[0]) <= 18446744073709551615:
                values[label] = matches[0]
            elif not matches:
                values[label] = "0"
    return Destroyed(values, when)


def snapshot_command(options):
    return [
        "bash",
        "-o",
        "pipefail",
        "-c",
        'source "$1"; socket_snapshot "$2" "$3" "$4" 1',
        "netmgr-sockets",
        str(Path(__file__).resolve().parents[1] / "netmgr"),
        str(int(options.brief)),
        str(int(options.all_details)),
        str(int(options.verbose)),
    ]


def terminate(proc):
    # Retain the controlling tty for sudo's ticket, but stop the entire collector group.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        try:
            proc.communicate(timeout=0.5)
            return
        except subprocess.TimeoutExpired:
            continue
    for pipe in (proc.stdout, proc.stderr):
        pipe.close()
    proc.wait(timeout=1)


class Collector(threading.Thread):
    def __init__(self, command):
        super().__init__(name="netmgr-socket-snapshots", daemon=True)
        self.command = command
        self.stop = threading.Event()
        self.updates = queue.Queue(maxsize=1)

    def capture(self):
        started = time.monotonic()
        proc = subprocess.Popen(
            self.command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            process_group=0,
        )
        finished = False
        try:
            while not self.stop.is_set():
                if time.monotonic() - started >= SNAPSHOT_TIMEOUT:
                    return Update(error="Snapshot timed out; retained previous data.")
                try:
                    output, errors = proc.communicate(timeout=0.1)
                except subprocess.TimeoutExpired:
                    continue
                finished = True
                warning = safe_text(errors.strip())[:600]
                if proc.returncode:
                    return Update(
                        error=warning or f"Snapshot command exited {proc.returncode}."
                    )
                table = Table.parse(output)
                return Update(table, started, warning, completed_at=time.monotonic())
            return None
        finally:
            if not finished:
                terminate(proc)

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            try:
                update = self.capture()
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                update = Update(error=safe_text(str(exc))[:600])
            if update is not None:
                try:
                    self.updates.get_nowait()
                except queue.Empty:
                    pass
                self.updates.put_nowait(update)
            self.stop.wait(max(0, INTERVAL - (time.monotonic() - started)))

    def latest(self):
        try:
            return self.updates.get_nowait()
        except queue.Empty:
            return None

    def close(self):
        self.stop.set()
        if self.ident is not None:
            self.join(timeout=3)


class EventCollector(threading.Thread):
    def __init__(self):
        super().__init__(name="netmgr-socket-destroy-events", daemon=True)
        self.stop = threading.Event()
        self.items = deque(maxlen=MAX_EVENTS)
        self.lock = threading.Lock()
        self.error = ""
        self.dropped = 0
        self.process = None

    def latest(self):
        with self.lock:
            events, dropped = tuple(self.items), self.dropped
            self.items.clear()
            return events, self.error, dropped

    def read_events(self, proc):
        streams = [proc.stdout, proc.stderr]
        pending = b""
        stderr_tail = b""
        discarding = False
        while streams and not self.stop.is_set():
            for stream in select.select(streams, [], [], 0.1)[0]:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    streams.remove(stream)
                elif stream is proc.stderr:
                    stderr_tail = (stderr_tail + chunk)[-4096:]
                else:
                    if discarding:
                        if b"\n" not in chunk:
                            continue
                        chunk = chunk.split(b"\n", 1)[1]
                        discarding = False
                    *lines, pending = (pending + chunk).split(b"\n")
                    for line in lines:
                        if len(line) > MAX_EVENT_LINE:
                            continue
                        event = parse_destroyed(
                            line.decode("utf-8", "replace"), time.monotonic()
                        )
                        if event is not None:
                            with self.lock:
                                if len(self.items) == MAX_EVENTS:
                                    self.dropped += 1
                                self.items.append(event)
                    if len(pending) > MAX_EVENT_LINE:
                        pending = b""
                        discarding = True
        return safe_text(stderr_tail.decode("utf-8", "replace").strip())[-400:]

    def run(self):
        while not self.stop.is_set():
            proc = None
            try:
                proc = subprocess.Popen(
                    event_command(),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=0,
                    process_group=0,
                    env={**os.environ, "LC_ALL": "C"},
                )
                self.process = proc
                with self.lock:
                    self.error = ""
                stderr = self.read_events(proc)
                if not self.stop.is_set():
                    with self.lock:
                        self.error = f"ss -E exited ({proc.wait()}): {stderr or 'event stream stopped'}"
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                with self.lock:
                    self.error = f"ss -E unavailable: {safe_text(str(exc))[:400]}"
            finally:
                if proc is not None:
                    if proc.poll() is None:
                        terminate(proc)
                    else:
                        proc.wait()
                        proc.stdout.close()
                        proc.stderr.close()
                self.process = None
            self.stop.wait(5)

    def close(self):
        self.stop.set()
        if self.ident is not None:
            self.join(timeout=3)
            if self.is_alive() and self.process is not None:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.join(timeout=2)


@dataclasses.dataclass
class RecentSocket:
    values: dict[str, str]
    gone_at: float
    last_observed_at: float = 0.0


class View:
    def __init__(self, *, show_queues=False):
        self.show_queues = show_queues
        self.live = self.table = self.filtered = Table()
        self.last_known = {}
        self.recent = {}
        self.closed_at = {}
        self.last_recent_tick = None
        self.events_error = ""
        self.selected = self.offset = 0
        self.query = self.saved_query = ""
        self.editing = self.paused = self.help = False
        self.details = None
        self.detail_x = self.detail_y = 0
        self.help_y = 0
        self.sort_column = None
        self.sort_reverse = False
        self.sort_choices = None
        self.sort_selected = self.sort_offset = 0
        self.header_regions = ()
        self.header_size = None
        self.left_down = None
        self.mouse_warning = self.mouse_error = ""
        self.sampled_at = None
        self.warning = self.error = ""

    def selected_key(self):
        if not self.filtered.rows:
            return None
        row = self.filtered.rows[self.selected]
        return tuple(row[i] for i in IDENTITY_COLUMNS)

    def refilter(self, anchor=None):
        query = self.query.casefold()
        rows = tuple(
            row
            for row in sorted_rows(self.table, self.sort_column, self.sort_reverse)
            if not query
            or query in "\t".join(row).casefold()
            or query
            in "\t".join(
                display_value(label, value)
                for label, value in zip(self.table.labels, row)
            ).casefold()
        )
        self.filtered = Table(self.table.labels, rows)
        self.selected = min(self.selected, max(0, len(rows) - 1))
        if anchor is not None:
            for index, row in enumerate(rows):
                if tuple(row[i] for i in IDENTITY_COLUMNS) == anchor:
                    self.selected = index
                    break

    def update(self, update):
        self.error, self.warning = update.error, update.warning
        if update.table is not None:
            anchor = self.selected_key()
            previous = {
                key: row
                for row in self.live.rows
                if (key := connection_key(row)) is not None
            }
            current = {
                key: row
                for row in update.table.rows
                if (key := connection_key(row)) is not None
            }
            detected_at = (
                update.completed_at
                if update.completed_at is not None
                else update.sampled_at
            )
            for key in previous.keys() - current.keys():
                if key in self.closed_at:
                    continue
                if (
                    key not in self.recent
                    or self.recent[key].values["State"] != "CLOSED"
                ):
                    values = dict(
                        self.last_known.get(
                            key, dict(zip(self.live.labels, previous[key]))
                        )
                    )
                    values["State"] = "GONE*"
                    self.recent[key] = RecentSocket(
                        values, detected_at, self.sampled_at
                    )
            self.closed_at = {
                key: when
                for key, when in self.closed_at.items()
                if key in current and update.sampled_at <= when
            }
            known = {}
            for key, row in current.items():
                values = dict(zip(update.table.labels, row))
                old = self.last_known.get(key)
                item = self.recent.get(key)
                if (
                    old is not None
                    and (item is None or update.sampled_at <= item.gone_at)
                    and not connection_restarted(old, values)
                ):
                    values = merge_socket_values(old, values)
                if (
                    item is not None
                    and item.values["State"] == "CLOSED"
                    and update.sampled_at <= item.gone_at
                ):
                    self.closed_at[key] = item.gone_at
                    if (
                        update.sampled_at >= item.last_observed_at
                        and not owners_changed(item.values, values)
                    ):
                        enriched = merge_socket_values(item.values, values)
                        # A late snapshot supplies metadata, not a new close time or queues.
                        for label in ("State", "Recv", "Send"):
                            enriched[label] = item.values.get(label, "-")
                        item.values = enriched
                        item.last_observed_at = update.sampled_at
                if key not in self.closed_at:
                    known[key] = values
            for key in current:
                if key in self.recent and update.sampled_at > self.recent[key].gone_at:
                    del self.recent[key]
            # Only live connections are cached; closed rows use the bounded recent history.
            self.last_known = known
            self.live, self.sampled_at = update.table, update.sampled_at
            self.rebuild(update.sampled_at, anchor)

    def accept_events(self, events):
        anchor = self.selected_key()
        live = {
            key: row
            for row in self.live.rows
            if (key := connection_key(row)) is not None
        }
        for event in events:
            key = event.values["Net"], event.values["Local"], event.values["Peer"]
            if key in live and event.when < self.sampled_at:
                continue
            if event.when < self.closed_at.get(key, 0):
                continue
            previous = self.recent.get(key)
            if previous and event.when < (
                previous.last_observed_at
                if previous.values["State"] == "GONE*"
                else previous.gone_at
            ):
                continue
            values = (
                dict(previous.values)
                if previous is not None
                else self.last_known.get(key, dict(zip(self.live.labels, live[key])))
                if key in live
                else dict(event.values)
            )
            if owners_changed(values, event.values):
                values = {}
            values = merge_socket_values(values, event.values, event=True)
            values["State"] = "CLOSED"
            self.recent[key] = RecentSocket(
                values,
                event.when,
                previous.last_observed_at
                if previous is not None
                else self.sampled_at
                if key in live and self.sampled_at is not None
                else 0.0,
            )
            if key in live:
                self.closed_at[key] = event.when
            self.last_known.pop(key, None)
        if events:
            self.rebuild(max(event.when for event in events), anchor)

    def rebuild(self, now, anchor=None):
        expired = [
            key
            for key, item in self.recent.items()
            if now - item.gone_at >= RECENT_SECONDS
        ]
        for key in expired:
            del self.recent[key]
        if len(self.recent) > MAX_RECENT:
            oldest = sorted(self.recent, key=lambda key: self.recent[key].gone_at)
            for key in oldest[: len(self.recent) - MAX_RECENT]:
                del self.recent[key]
        active_rows = tuple(
            row
            for row in self.live.rows
            if (key := connection_key(row)) not in self.closed_at
        )
        if not self.recent:
            self.table = (
                self.live
                if len(active_rows) == len(self.live.rows)
                else Table(self.live.labels, active_rows)
            )
        else:
            extra_labels = tuple(
                dict.fromkeys(
                    label
                    for item in self.recent.values()
                    for label, value in item.values.items()
                    if label not in self.live.labels and has_detail(value)
                )
            )
            row_labels = self.live.labels + extra_labels
            has_process_age = "Age" in row_labels
            labels = row_labels + (("Process age",) if has_process_age else ("Age",))
            active = (
                (*row, *("-" for _ in extra_labels), "-")
                for row in active_rows
                if (key := connection_key(row)) not in self.recent
                or self.recent[key].gone_at < self.sampled_at
            )

            def recent_row(item):
                gone_age = f"{max(0, int(now - item.gone_at))}s"
                values = tuple(
                    gone_age if label == "Age" else item.values.get(label, "-")
                    for label in row_labels
                )
                return values + (
                    (item.values.get("Age", "-"),) if has_process_age else (gone_age,)
                )

            recent = (
                recent_row(item)
                for item in sorted(
                    self.recent.values(), key=lambda item: item.gone_at, reverse=True
                )
            )
            self.table = Table(labels, tuple(active) + tuple(recent))
        self.last_recent_tick = int(now)
        self.refilter(anchor)

    def refresh_recent(self, now):
        if self.recent and int(now) != self.last_recent_tick:
            self.rebuild(now, self.selected_key())

    def sort_by(self, label, *, reverse=None):
        if label == "State":
            label, reverse = None, False
        if label in LOCKED_COLUMNS:
            return
        anchor = self.selected_key()
        self.sort_reverse = (
            reverse
            if reverse is not None
            else not self.sort_reverse
            if label is not None and label == self.sort_column
            else False
        )
        self.sort_column = label
        self.refilter(anchor)

    def headings(self):
        global_primary = self.global_primary_sort()
        return tuple(
            f"State[{2 if global_primary else 1}]"
            if label == "State"
            else f"Origin[{3 if global_primary else 2}]"
            if label == "Origin"
            else label + ("v" if self.sort_reverse else "^")
            if label == self.sort_column
            else label
            for label in self.filtered.labels
        )

    def global_primary_sort(self):
        return (
            self.sort_column in GLOBAL_PRIMARY_COLUMNS
            and self.sort_column in self.table.labels
        )

    def move(self, delta, height, width, *, wheel=False):
        page = max(1, body_rows(self, height, width))
        if self.sort_choices is not None:
            self.sort_selected = max(
                0, min(self.sort_selected + delta, len(self.sort_choices) - 1)
            )
            if wheel:
                self.sort_offset = max(
                    0, min(self.sort_offset + delta, len(self.sort_choices) - page)
                )
                self.sort_selected = max(
                    self.sort_offset,
                    min(self.sort_selected, self.sort_offset + page - 1),
                )
        elif self.help:
            self.help_y = max(0, min(self.help_y + delta, len(HELP) - page))
        elif self.details is not None:
            self.detail_y = max(0, min(self.detail_y + delta, len(self.details) - page))
        else:
            self.selected = max(
                0, min(self.selected + delta, len(self.filtered.rows) - 1)
            )
            if wheel:
                self.offset = max(
                    0, min(self.offset + delta, len(self.filtered.rows) - page)
                )
                self.selected = max(
                    self.offset, min(self.selected, self.offset + page - 1)
                )

    def wheel(self, buttons, height, width):
        direction = bool(buttons & WHEEL_DOWN) - bool(buttons & WHEEL_UP)
        if direction:
            self.move(direction * WHEEL_ROWS, height, width, wheel=True)

    def mouse(self, event, height, width):
        mouse_id, x, y, _, buttons = event
        if buttons & (WHEEL_UP | WHEEL_DOWN):
            self.wheel(buttons, height, width)
            return
        # Terminals may report a click as a press/release pair or a click event.
        if buttons & LEFT_PRESS:
            self.left_down = (
                None
                if buttons & (HEADER_CLICK | LEFT_CLICK | LEFT_DOUBLE_CLICK)
                else mouse_id
            )
        elif buttons & (HEADER_CLICK | LEFT_CLICK | LEFT_DOUBLE_CLICK):
            if self.left_down == mouse_id:
                self.left_down = None
                return
            self.left_down = None
        else:
            return
        if (
            y == 2
            and self.header_size == (height, width)
            and not (self.editing or self.help)
            and self.details is None
            and self.sort_choices is None
        ):
            for start, end, label in self.header_regions:
                if start <= x < end:
                    self.sort_by(
                        label,
                        reverse=not self.sort_reverse
                        if label == self.sort_column
                        else True,
                    )
                    break

    def key(self, key, height, width):
        if self.editing:
            if key in ("\n", "\r", curses.KEY_ENTER):
                self.editing = False
            elif key == "\x1b":
                self.query, self.editing = self.saved_query, False
            elif key in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                self.query = self.query[:-1]
            elif key == "\x15":
                self.query = ""
            elif isinstance(key, str) and key.isprintable() and len(self.query) < 200:
                self.query += key
            self.selected = self.offset = 0
            self.refilter()
            return False
        if key in ("q", "Q", curses.KEY_F10):
            return True
        if self.sort_choices is not None and key in (
            "\n",
            "\r",
            curses.KEY_ENTER,
            "\x1b",
            curses.KEY_F6,
        ):
            if key in ("\n", "\r", curses.KEY_ENTER):
                label = self.sort_choices[self.sort_selected]
                self.sort_by(
                    label,
                    reverse=self.sort_reverse if label == self.sort_column else False,
                )
            self.sort_choices = None
        elif key == curses.KEY_F6:
            self.sort_choices = (None,) + tuple(
                label for label in self.table.labels if label not in LOCKED_COLUMNS
            )
            self.sort_selected = (
                self.sort_choices.index(self.sort_column)
                if self.sort_column in self.sort_choices
                else 0
            )
            self.sort_offset = 0
            self.help, self.details = False, None
        elif self.sort_choices is not None:
            self.navigate(key, height, width)
        elif key in ("?", "h"):
            self.help = not self.help
            self.help_y = 0
        elif key == "\x1b":
            if self.help:
                self.help = False
            elif self.details is not None:
                self.details = None
            else:
                self.query = ""
                self.refilter()
        elif key == " ":
            self.paused = not self.paused
        elif key in ("/", curses.KEY_F3):
            self.editing, self.saved_query = True, self.query
            self.help, self.details = False, None
        elif key == "r" and not self.help and self.details is None:
            self.sort_by(self.sort_column or "Net", reverse=not self.sort_reverse)
        elif key in ("\n", "\r", curses.KEY_ENTER):
            if self.details is not None:
                self.details = None
            elif self.filtered.rows:
                self.details = tuple(
                    f"{label}: {display_value(label, value, exact=True)}"
                    for label, value in zip(
                        self.filtered.labels, self.filtered.rows[self.selected]
                    )
                )
                self.detail_x = self.detail_y = 0
        else:
            self.navigate(key, height, width)
            if self.details is not None and not self.help:
                self.detail_x = max(
                    0,
                    min(
                        max(map(text_width, self.details)) - max(1, width - 1),
                        self.detail_x
                        + {curses.KEY_RIGHT: 12, curses.KEY_LEFT: -12}.get(key, 0),
                    ),
                )
        return False

    def navigate(self, key, height, width):
        page = max(1, body_rows(self, height, width))
        total = (
            len(self.sort_choices)
            if self.sort_choices is not None
            else len(HELP)
            if self.help
            else len(self.details)
            if self.details is not None
            else len(self.filtered.rows)
        )
        delta = {
            curses.KEY_DOWN: 1,
            "j": 1,
            curses.KEY_UP: -1,
            "k": -1,
            curses.KEY_NPAGE: page,
            curses.KEY_PPAGE: -page,
            curses.KEY_HOME: -total,
            curses.KEY_END: total,
        }.get(key, 0)
        self.move(delta, height, width)


def draw(window, view, now, listener_style=0, inbound_style=0):
    if not view.paused:
        view.refresh_recent(now)
    height, columns = window.getmaxyx()
    width = max(0, columns - 1)  # Never write the terminal's wrap-triggering last cell.
    footers = footer_rows(view, height, columns)
    content_end = height - len(footers)
    count = body_rows(view, height, columns)
    view.header_regions = ()
    view.header_size = (height, columns)
    window.erase()

    def line(y, value, style=0):
        if 0 <= y < height and width:
            try:
                window.addstr(y, 0, fit(value, width), style)
            except curses.error:
                pass  # A resize can arrive between getmaxyx and addstr.

    age = (
        "waiting"
        if view.sampled_at is None
        else f"snapshot {max(0, now - view.sampled_at):.1f}s ago"
    )
    mode = (
        "PAUSED"
        if view.paused
        else "STALE"
        if view.error
        else "COLLECTING"
        if view.sampled_at is None or now - view.sampled_at > 2
        else "LIVE"
    )
    line(
        0,
        f"netmgr sockets | {mode} | 1s refresh | {len(view.filtered.rows)}/{len(view.table.rows)} rows | {len(view.recent)} recent | {age}",
        curses.A_BOLD,
    )
    headings = view.headings()
    layout = column_layout(view.filtered, width, headings, show_queues=view.show_queues)
    hidden = len(view.table.labels) - len(layout)
    sort_label = (
        f"{view.sort_column} {'descending' if view.sort_reverse else 'ascending'}"
        if view.sort_column is not None
        else "Net > Local > Port"
    )
    if view.sort_column is not None and view.sort_column not in view.table.labels:
        sort_label += " (unavailable; default order)"
    sort_order = (
        f"{sort_label} (global) > State > Origin"
        if view.global_primary_sort()
        else f"State > Origin (locked) > {sort_label}"
    )
    note = (
        view.error
        or " | ".join(
            message
            for message in (
                view.events_error,
                view.mouse_warning,
                view.mouse_error,
                view.warning,
            )
            if message
        )
        or f"{sort_order} | {hidden} hidden columns | * origin inferred"
    )
    line(1, note, curses.A_BOLD if view.error else curses.A_DIM)
    if view.sort_choices is not None:
        line(
            2,
            "Choose sort column | Age/Downloaded/Uploaded: global; others: grouped",
            curses.A_REVERSE,
        )
        view.sort_offset = max(0, min(view.sort_offset, len(view.sort_choices) - count))
        if view.sort_selected < view.sort_offset:
            view.sort_offset = view.sort_selected
        elif view.sort_selected >= view.sort_offset + count:
            view.sort_offset = max(0, view.sort_selected - count + 1)
        visible = {view.table.labels[index] for index, _ in layout}
        for i, label in enumerate(
            view.sort_choices[view.sort_offset : view.sort_offset + count]
        ):
            marker = "* " if label == view.sort_column else "  "
            name = label or "Default (Net > Local > Port)"
            if label in GLOBAL_PRIMARY_COLUMNS:
                name += " (global)"
            if label is not None and label not in visible:
                name += " (hidden)" if label in view.table.labels else " (unavailable)"
            line(
                i + 3,
                marker + name,
                curses.A_REVERSE if view.sort_offset + i == view.sort_selected else 0,
            )
    elif view.help:
        view.help_y = max(0, min(view.help_y, len(HELP) - count))
        for i, text in enumerate(HELP[view.help_y : view.help_y + count]):
            line(i + 2, text)
    elif view.details is not None:
        view.detail_x = max(
            0, min(view.detail_x, max(map(text_width, view.details)) - width)
        )
        view.detail_y = max(0, min(view.detail_y, len(view.details) - max(1, count)))
        line(
            2,
            "Selected row (frozen) | arrows scroll | Enter/Esc returns",
            curses.A_REVERSE,
        )
        for i, text in enumerate(view.details[view.detail_y : view.detail_y + count]):
            line(i + 3, text_slice(text, view.detail_x, width))
    elif content_end > 2:
        line(
            2,
            render_row(view.filtered, headings, layout, header=True),
            curses.A_REVERSE,
        )
        regions, x = [], 0
        for index, size in layout:
            regions.append((x, x + size, view.filtered.labels[index]))
            x += size + 1
        view.header_regions = tuple(regions)
        view.offset = max(0, min(view.offset, len(view.filtered.rows) - count))
        if view.selected < view.offset:
            view.offset = view.selected
        elif view.selected >= view.offset + count:
            view.offset = max(0, view.selected - count + 1)
        for i, row in enumerate(view.filtered.rows[view.offset : view.offset + count]):
            style = (
                curses.A_DIM
                if row[0] in {"CLOSED", "GONE*"}
                else listener_style
                if wildcard_listener(row)
                else inbound_style
                if row[2] == "INBOUND*"
                else 0
            )
            if view.offset + i == view.selected:
                style |= curses.A_REVERSE
            line(i + 3, render_row(view.filtered, row, layout), style)
        if not view.filtered.rows and count:
            line(
                3,
                "No matching sockets."
                if view.query
                else "No sockets in snapshot."
                if view.sampled_at is not None
                else "Collecting first snapshot...",
            )
    for i, footer in enumerate(footers):
        line(
            content_end + i,
            footer + " " * (width - text_width(footer)),
            curses.A_REVERSE | curses.A_BOLD,
        )
    window.noutrefresh()
    curses.doupdate()


def run_screen(window, collector, events=None, *, show_queues=False):
    window.keypad(True)
    window.timeout(100)
    window.scrollok(False)
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    listener_style = curses.A_BOLD
    inbound_style = curses.A_BOLD
    if not os.environ.get("NO_COLOR") and curses.has_colors():
        try:
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_YELLOW, -1)
            listener_style |= curses.color_pair(1)
            curses.init_pair(2, curses.COLOR_CYAN, -1)
            inbound_style |= curses.color_pair(2)
        except curses.error:
            pass
    view, pending = View(show_queues=show_queues), None
    pending_events = deque(maxlen=MAX_EVENTS)
    pending_dropped = 0
    terminal = safe_text(os.environ.get("TERM", "unset"))[:60]
    last_draw, last_size, dirty = 0, None, True
    old_mouse_mask = old_mouse_interval = None
    try:
        if MOUSE_MASK:
            try:
                available, old_mouse_mask = curses.mousemask(MOUSE_MASK)
                if available:
                    old_mouse_interval = curses.mouseinterval(0)
                if not available & HEADER_MOUSE_MASK:
                    view.mouse_warning = (
                        f"Mouse clicks unavailable (TERM={terminal}); F6 sorts."
                    )
            except curses.error as exc:
                view.mouse_warning = f"Mouse setup failed (TERM={terminal}): {safe_text(str(exc))}; F6 sorts."
        collector.start()
        if events is not None:
            events.start()
        while True:
            update = collector.latest()
            if update is not None:
                pending = update
            if events is not None:
                arrived, error, dropped = events.latest()
                pending_dropped += max(
                    0, len(pending_events) + len(arrived) - MAX_EVENTS
                )
                pending_events.extend(arrived)
                lost = dropped + pending_dropped
                event_status = " | ".join(
                    message
                    for message in (
                        error,
                        f"ss -E event backlog overflow: {lost} lost" if lost else "",
                    )
                    if message
                )
                if event_status != view.events_error:
                    view.events_error, dirty = event_status, True
            if pending is not None and not view.paused:
                view.update(pending)
                pending, dirty = None, True
            if pending_events and not view.paused:
                view.accept_events(tuple(pending_events))
                pending_events.clear()
                dirty = True
            now, size = time.monotonic(), window.getmaxyx()
            if dirty or size != last_size or now - last_draw >= INTERVAL:
                draw(window, view, now, listener_style, inbound_style)
                dirty, last_size, last_draw = False, size, now
            try:
                key = window.get_wch()
            except curses.error:
                continue
            if key == curses.KEY_MOUSE:
                try:
                    view.mouse(curses.getmouse(), *window.getmaxyx())
                    view.mouse_error = ""
                except curses.error as exc:
                    view.mouse_error = f"Mouse decoding failed (TERM={terminal}): {safe_text(str(exc))}"
                    dirty = True
                    continue
            elif view.key(key, *size):
                return 0
            dirty = True
    finally:
        try:
            collector.close()
        finally:
            try:
                if events is not None:
                    events.close()
            finally:
                for restore, value in (
                    (curses.mousemask, old_mouse_mask),
                    (curses.mouseinterval, old_mouse_interval),
                ):
                    if value is not None:
                        try:
                            restore(value)
                        except curses.error:
                            pass


class TerminalExit(Exception):
    def __init__(self, signum):
        self.code = 128 + signum


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--brief", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--all-details", action="store_true")
    options = parser.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error("live view requires a terminal; use netmgr sockets --once")
    collector = Collector(snapshot_command(options))
    previous = {}

    def interrupted(signum, _frame):
        raise TerminalExit(signum)

    try:
        for signum in (signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, interrupted)
        return curses.wrapper(
            run_screen,
            collector,
            EventCollector(),
            show_queues=options.verbose or options.all_details,
        )
    except KeyboardInterrupt:
        return 130
    except TerminalExit as exc:
        return exc.code
    except curses.error as exc:
        print(
            f"Error: cannot use live terminal: {exc}; use netmgr sockets --once.",
            file=sys.stderr,
        )
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
