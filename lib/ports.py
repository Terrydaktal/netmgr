"""Process and container columns for an existing ss snapshot; no socket probes."""

from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import json
import math
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import tomllib
from pathlib import Path


def clean(value, limit=4096):
    text = str(value)
    text = "".join(c if c.isprintable() else " " for c in text).strip()
    return text if len(text) <= limit else text[:limit] + "..."


def endpoint(value):
    host, _, port = value.rpartition(":")
    return host.strip("[]"), int(port) if port.isdecimal() else 0


@dataclasses.dataclass(frozen=True)
class Socket:
    protocol: str
    state: str
    local: str
    peer: str
    owners: tuple[tuple[int, int, str], ...]

    @property
    def listening(self):
        return self.state == "LISTEN" or (
            self.protocol == "udp" and self.state == "UNCONN"
        )


def parse_sockets(text, all_details=False):
    sockets = []
    for line in text.splitlines():
        fields = line.split(None, 6)
        if len(fields) < 6 or fields[0] not in {"tcp", "udp"}:
            continue
        owners = tuple(
            (int(pid), int(fd), name)
            for name, pid, fd in re.findall(
                r'\("((?:\\.|[^"\\])*)",pid=(\d+),fd=(\d+)\)',
                fields[6] if len(fields) > 6 else "",
            )
            if int(pid) > 0
        )
        item = Socket(fields[0], fields[1], fields[4], fields[5], owners)
        if item.listening or all_details:
            sockets.append(item)
    return sockets


def process_requests(sockets):
    requests = {}
    for item in sockets:
        for pid, fd, _ in item.owners:
            requests.setdefault(pid, set()).add(fd)
    return [{"pid": pid, "fds": sorted(fds)} for pid, fds in sorted(requests.items())]


def read_limited(path, limit=262144):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("metadata is not a regular file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("metadata exceeds size limit")
    return data.decode("utf-8", "replace")


def process_stat(path):
    # comm can contain spaces and parentheses; the remaining fields start at state.
    fields = read_limited(path / "stat").rsplit(") ", 1)[1].split()
    start, parent = int(fields[19]), int(fields[1])
    if start < 0 or parent < 0:
        raise ValueError("invalid process identity")
    return start, parent


def process_name(info):
    return Path(info.get("exe", "")).name or info.get("comm", "") or "?"


def parent_node(path):
    try:
        start, parent = process_stat(path)
        try:
            name = Path(os.readlink(path / "exe")).name
        except OSError:
            name = read_limited(path / "comm").rstrip("\n")
        if not name or process_stat(path) != (start, parent):
            return None
        return {"start": start, "ppid": parent, "name": name}
    except (OSError, ValueError, IndexError):
        return None


def process_chain(info, proc_root, cache, max_depth=64):
    names = [process_name(info)]
    seen = {info["pid"]}
    child_start, parent = info["start"], info["ppid"]
    note = ""
    while parent:
        if parent in seen or len(names) >= max_depth:
            note = "parent chain incomplete: cycle or depth limit"
            break
        seen.add(parent)
        if parent not in cache:
            cache[parent] = parent_node(proc_root / str(parent))
        node = cache[parent]
        if node is None:
            note = "parent chain incomplete: parent unavailable or changed"
            break
        # A reused PID must not attach a newer, unrelated process as a parent.
        if node["start"] > child_start:
            note = "parent chain incomplete: parent PID changed"
            break
        names.append(node["name"])
        child_start, parent = node["start"], node["ppid"]
    if note:
        names.append("?")
    return "<-".join(names), note


def cgroup_identity(text):
    units = []
    container_id = engine = ""
    owner_uid = None
    for line in text.splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        path = fields[2]
        owner = re.search(r"/user-(\d+)\.slice/", path)
        if owner:
            owner_uid = int(owner[1])
        container = re.search(
            r"/(libpod|docker)[-/]([a-f0-9]{64})(?:\.scope)?(?:/|$)", path
        )
        if container:
            engine = "podman" if container[1] == "libpod" else "docker"
            container_id = container[2]
        # Units inside a container do not belong to the host systemd manager.
        unit_path = path[: container.start()] if container else path
        for part in unit_path.split("/"):
            if part.endswith((".service", ".scope")) and not re.match(
                r"(?:user@\d+\.service|session-\d+\.scope|(?:libpod|docker)-)", part
            ):
                units.append(part)
    return {
        "unit": units[-1] if units else "",
        "user_unit": owner_uid is not None,
        "manager_uid": owner_uid,
        "container_id": container_id,
        "engine": engine,
        "container_owner": owner_uid if owner_uid is not None else 0,
    }


def program_kind(info):
    exe = Path(info.get("exe", "").removesuffix(" (deleted)")).name
    argv = info.get("argv", [])
    title = argv[0] if argv else info.get("comm", "")
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", exe):
        return "python"
    if exe in {"node", "nodejs"} or title.startswith("next-server"):
        return "node"
    return exe


def project_metadata(path, kind):
    result = {}
    filename = "package.json" if kind == "node" else "pyproject.toml"
    if kind not in {"node", "python"}:
        return result
    try:
        raw = read_limited(path / "cwd" / filename)
        project = (
            json.loads(raw) if kind == "node" else tomllib.loads(raw).get("project", {})
        )
        if isinstance(project, dict):
            result = {
                key: project[key]
                for key in ("name", "version", "description")
                if isinstance(project.get(key), str)
            }
    except (OSError, ValueError):
        pass
    return result


def collect_processes(requests, proc_root=Path("/proc")):
    result = {}
    for request in requests:
        pid, fds = request["pid"], request["fds"]
        if (
            type(pid) is not int
            or pid <= 0
            or any(type(fd) is not int or fd < 0 for fd in fds)
        ):
            raise ValueError("invalid process request")
        path = proc_root / str(pid)
        info = {"pid": pid}
        try:
            before = process_stat(path)
            links = {}
            for fd in fds:
                try:
                    target = os.readlink(path / "fd" / str(fd))
                except OSError:
                    continue
                if re.fullmatch(r"socket:\[\d+\]", target):
                    links[fd] = target
            if not links:
                info["error"] = "socket ownership changed or is inaccessible"
            else:
                status = read_limited(path / "status")
                uid = re.search(r"^Uid:\s+(\d+)\s+(\d+)", status, re.MULTILINE)
                info["uid"] = int(uid[1]) if uid else None
                info["euid"] = int(uid[2]) if uid else None
                info["comm"] = read_limited(path / "comm").rstrip("\n")
                info["argv"] = read_limited(path / "cmdline").rstrip("\0").split("\0")
                for key in ("exe", "cwd"):
                    try:
                        info[key] = os.readlink(path / key)
                    except OSError:
                        info[key] = ""
                try:
                    cgroups = read_limited(path / "cgroup")
                except OSError:
                    cgroups = ""
                info.update(cgroup_identity(cgroups))
                kind = program_kind(info)
                info["project"] = project_metadata(path, kind)
                if kind == "node":
                    try:
                        package = json.loads(
                            read_limited(path / "cwd/node_modules/next/package.json")
                        )
                        if isinstance(package, dict) and isinstance(
                            package.get("version"), str
                        ):
                            info["next_version"] = package["version"]
                    except (OSError, ValueError):
                        pass
                valid_fds = []
                for fd, target in links.items():
                    try:
                        if os.readlink(path / "fd" / str(fd)) == target:
                            valid_fds.append(fd)
                    except OSError:
                        pass
                if process_stat(path) != before or not valid_fds:
                    info = {
                        "pid": pid,
                        "error": "process or socket changed during collection",
                    }
                else:
                    info["fds"] = valid_fds
                    info["start"], info["ppid"] = before
        except (OSError, ValueError, IndexError) as exc:
            reason = exc.strerror if isinstance(exc, OSError) else str(exc)
            info = {"pid": pid, "error": f"process metadata unavailable: {reason}"}
        result[str(pid)] = info
    parents = {
        info["pid"]: {
            "start": info["start"],
            "ppid": info["ppid"],
            "name": process_name(info),
        }
        for info in result.values()
        if not info.get("error")
    }
    uptime = None
    clock_ticks = 0
    if parents:
        try:
            clock_ticks = os.sysconf("SC_CLK_TCK")
            uptime = float(read_limited(proc_root / "uptime", 128).split()[0])
        except (OSError, ValueError, IndexError):
            pass
    for info in result.values():
        if not info.get("error"):
            info["chain"], info["chain_note"] = process_chain(info, proc_root, parents)
            if uptime is not None and math.isfinite(uptime) and clock_ticks > 0:
                age = uptime - info["start"] / clock_ticks
                if age >= 0:
                    info["age_s"] = int(age)
    return result


class CommandError(Exception):
    pass


class Runner:
    def __init__(self, budget=12):
        self.deadline = time.monotonic() + budget

    def run(self, command, *, input_text=None, timeout=2, env=None):
        remaining = min(timeout, self.deadline - time.monotonic())
        if remaining <= 0:
            raise CommandError("metadata time budget reached")
        try:
            result = subprocess.run(
                command,
                input=input_text,
                stdin=subprocess.DEVNULL if input_text is None else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=remaining,
                check=True,
                env=env,
            )
            return result.stdout
        except subprocess.TimeoutExpired as exc:
            raise CommandError(f"{command[0]} metadata lookup timed out") from exc
        except subprocess.CalledProcessError as exc:
            raise CommandError(
                f"{command[0]}: {clean(exc.stderr, 240) or 'lookup failed'}"
            ) from exc
        except OSError as exc:
            raise CommandError(f"{command[0]}: {exc.strerror}") from exc


def unit_descriptions(processes, runner, uid):
    descriptions = {}
    notes = []
    for user in (False, True):
        units = sorted(
            {
                info["unit"]
                for info in processes.values()
                if info.get("unit")
                and info.get("user_unit") == user
                and (not user or info.get("manager_uid") == uid)
            }
        )
        if not units or not shutil.which("systemctl"):
            continue
        command = ["systemctl", "--no-pager"]
        if user:
            command.append("--user")
        command += ["show", "--property=Id,Description,LoadState", "--", *units]
        try:
            raw = runner.run(command)
        except CommandError as exc:
            notes.append(str(exc))
            continue
        for block in raw.strip().split("\n\n"):
            fields = dict(
                line.split("=", 1) for line in block.splitlines() if "=" in line
            )
            if fields.get("Id") in units and fields.get("LoadState") == "loaded":
                descriptions[(user, fields["Id"])] = fields.get("Description", "")
    return descriptions, notes


def container_engine(info):
    if info.get("engine"):
        return info["engine"], info["container_owner"]
    kind = program_kind(info)
    # The kernel exe for Go reexec helpers can remain /usr/bin/podman.
    title = Path((info.get("argv") or [info.get("comm", "")])[0]).name
    if kind in {"rootlessport", "pasta", "slirp4netns"} or title == "rootlessport":
        return "podman", info.get("uid")
    if kind in {"docker-proxy", "rootlesskit"}:
        return "docker", info.get("uid")
    return "", None


def port_mappings(text):
    mappings = []
    pattern = r"(\[[^]]+\]|[^ ,]+):(\d+)(?:-(\d+))?->(\d+)(?:-(\d+))?/(tcp|udp)"
    for host, first, last, target, target_last, protocol in re.findall(pattern, text):
        first, last, target, target_last = map(
            int, (first, last or first, target, target_last or target)
        )
        if not (0 < first <= last <= 65535 and 0 < target <= target_last <= 65535):
            continue
        if last - first != target_last - target:
            continue
        mappings.append(
            {
                "host": host.strip("[]"),
                "first": first,
                "last": last,
                "target": target,
                "protocol": protocol,
            }
        )
    return mappings


def parse_containers(raw, engine, owner):
    containers = []
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            raise ValueError("invalid container listing")
        cid, names, image, ports = (json.loads(field) for field in fields)
        if not isinstance(cid, str) or not re.fullmatch(r"[a-f0-9]{12,64}", cid):
            continue
        if isinstance(names, list):
            names = ", ".join(str(name) for name in names)
        if not all(isinstance(value, str) for value in (names, image, ports)):
            continue
        containers.append(
            {
                "id": cid,
                "name": names,
                "image": image,
                "engine": engine,
                "owner": owner,
                "ports": port_mappings(ports),
            }
        )
    return containers


def container_inventory(processes, runner, uid):
    wanted = {
        container_engine(info) for info in processes.values() if not info.get("error")
    }
    containers, notes = [], []
    for engine in ("podman", "docker"):
        if (engine, uid) not in wanted or not shutil.which(engine):
            continue
        env = os.environ.copy()
        for key in (
            "CONTAINER_HOST",
            "CONTAINER_CONNECTION",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ):
            env.pop(key, None)
        if engine == "podman":
            command = ["podman", "--remote=false"]
        else:
            rootless_socket = Path(f"/run/user/{uid}/docker.sock")
            docker_socket = (
                rootless_socket
                if uid and rootless_socket.is_socket()
                else Path("/var/run/docker.sock")
            )
            command = ["docker", "--host", f"unix://{docker_socket}"]
        command += [
            "ps",
            "--no-trunc",
            "--format",
            "{{json .ID}}\t{{json .Names}}\t{{json .Image}}\t{{json .Ports}}",
        ]
        try:
            containers.extend(
                parse_containers(runner.run(command, env=env), engine, uid)
            )
        except (CommandError, ValueError) as exc:
            notes.append(f"{engine} container metadata unavailable: {exc}")
    return containers, notes


def same_binding(local, published):
    if local == "*" or published in {"", "*"}:
        return True
    try:
        left = ipaddress.ip_address(local.split("%", 1)[0])
        right = ipaddress.ip_address(published.split("%", 1)[0])
        return left == right or (
            left.version == right.version
            and (left.is_unspecified or right.is_unspecified)
        )
    except ValueError:
        return False


def match_containers(info, sockets, containers):
    engine, owner = container_engine(info)
    candidates = [
        item
        for item in containers
        if item["engine"] == engine and item["owner"] == owner
    ]
    cid = info.get("container_id")
    if cid:
        matches = [item for item in candidates if cid.startswith(item["id"])]
        return [(matches[0], "process cgroup")] if len(matches) == 1 else []
    found = {}
    for item in sockets:
        host, port = endpoint(item.local)
        matches = []
        for container in candidates:
            if any(
                mapping["protocol"] == item.protocol
                and mapping["first"] <= port <= mapping["last"]
                and same_binding(host, mapping["host"])
                for mapping in container["ports"]
            ):
                matches.append(container)
        if len(matches) == 1:
            found[matches[0]["id"]] = (matches[0], "published-port match")
    return list(found.values())


def application_details(info):
    kind = program_kind(info)
    argv = info.get("argv", [])
    details = []
    if kind == "python":
        version = re.search(r"python(\d+(?:\.\d+)*)", info.get("exe", ""))
        details.append(("Runtime", "Python" + (f" {version[1]}" if version else "")))
        args = iter(argv[1:])
        for arg in args:
            if arg in {"-W", "-X"}:
                next(args, None)
            elif arg == "-m":
                module = next(args, "")
                details.append(("Module", module))
                if module == "http.server":
                    details.append(
                        ("Description", "Python static HTTP file server (from command)")
                    )
                break
            elif arg == "-c":
                break
            elif not arg.startswith("-") or arg == "--":
                details.append(("Script", next(args, "") if arg == "--" else arg))
                break
    elif kind == "node":
        details.append(("Runtime", "Node.js"))
        title = " ".join(argv)
        version = re.search(r"next-server \(v([^ )]+)\)", title)
        if title.startswith("next-server") or any("next/dist/" in arg for arg in argv):
            label = "Next.js"
            installed = version[1] if version else info.get("next_version", "")
            details.append(
                ("Application", label + (f" {installed}" if installed else ""))
            )
            details.append(
                ("Description", "Next.js web application server (from command)")
            )
        elif len(argv) > 1 and not argv[1].startswith("-"):
            details.append(("Script", argv[1]))
    project = info.get("project", {})
    if project.get("name"):
        details.append(
            (
                "Project",
                project["name"]
                + (f" ({project['version']})" if project.get("version") else ""),
            )
        )
    if project.get("description"):
        details.append(("Project Description", project["description"]))
    return details


DETAIL_COLUMNS = (
    "PID",
    "User",
    "Age",
    "UID",
    "EUID",
    "Executable",
    "App",
    "CWD",
    "Service",
    "Runtime",
    "Application",
    "Script/Module",
    "Project",
    "Container",
    "Image",
    "Forwarding",
    "Metadata",
    "Command",
    "Description",
)
COMPACT_COLUMNS = ("PID", "User", "Age", "App", "CWD")


def user_name(uid, cache):
    if uid not in cache:
        try:
            cache[uid] = pwd.getpwuid(uid).pw_name
        except (KeyError, OSError, OverflowError):
            cache[uid] = str(uid)
    return cache[uid]


def format_age(seconds):
    if type(seconds) is not int or seconds < 0:
        return ""
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f"{days}d{hours:02}h"
    if hours:
        return f"{hours}h{minutes:02}m"
    if minutes:
        return f"{minutes}m{seconds:02}s"
    return f"{seconds}s"


def short_command(argv):
    shortened = []
    for index, arg in enumerate(argv):
        prefix = ""
        value = arg
        if arg.startswith("-") and "=" in arg:
            prefix, value = arg.split("=", 1)
            prefix += "="
        if value.startswith(("/", "./", "../")):
            name = Path(value).name or "/"
            is_script = not prefix and name.endswith(
                (".py", ".js", ".mjs", ".cjs", ".sh")
            )
            value = name if index == 0 or is_script else ".../" + name
        shortened.append(prefix + value)
    return shlex.join(shortened)


def compact_columns(values, info):
    return {
        **{column: values.get(column, "") for column in COMPACT_COLUMNS},
        "Command": short_command(info.get("argv", [])),
    }


def process_columns(pid, name, info, descriptions, users):
    values = {
        "PID": str(pid),
        "Executable": info.get("exe") or info.get("comm") or name,
    }
    values["App"] = info.get("chain") or (
        (Path(values["Executable"]).name or "?") + "<-?"
    )
    if info.get("uid") is not None:
        values["UID"] = str(info["uid"])
    if info.get("euid") is not None:
        values["EUID"] = str(info["euid"])
        values["User"] = user_name(info["euid"], users)
    values["Age"] = format_age(info.get("age_s"))
    if info.get("error"):
        values["Metadata"] = info["error"]
        return values
    values["Command"] = shlex.join(info.get("argv", []))
    values["CWD"] = info.get("cwd", "")
    values["Metadata"] = info.get("chain_note", "")
    description_parts = []
    unit = info.get("unit")
    if unit:
        context = (
            f"user UID {info.get('manager_uid')}" if info.get("user_unit") else "system"
        )
        values["Service"] = f"{unit} ({context})"
        description = descriptions.get((info.get("user_unit", False), unit))
        if description:
            description_parts.append(description + " (systemd)")
    for label, value in application_details(info):
        if label == "Description":
            description_parts.append(value)
        elif label == "Project Description":
            description_parts.append("Project: " + value)
        elif label in {"Script", "Module"}:
            values["Script/Module"] = f"module: {value}" if label == "Module" else value
        else:
            values[label] = value
    values["Description"] = "; ".join(dict.fromkeys(description_parts))
    return values


def socket_columns(item, pid, info, values, containers):
    values = values.copy()
    if info.get("error"):
        return values
    if "fds" in info and not any(
        owner_pid == pid and fd in info["fds"] for owner_pid, fd, _ in item.owners
    ):
        values["Metadata"] = "socket descriptor changed since the socket snapshot"
        return values
    matches = match_containers(info, [item], containers)
    if matches:
        container, evidence = matches[0]
        values["Container"] = (
            f"{container['name']} ({container['engine']}; {container['id'][:12]}; {evidence})"
        )
        values["Image"] = container["image"]
        host, port = endpoint(item.local)
        forwarded = set()
        for mapping in container["ports"]:
            if (
                item.protocol == mapping["protocol"]
                and mapping["first"] <= port <= mapping["last"]
                and same_binding(host, mapping["host"])
            ):
                forwarded.add(
                    f"{item.local} -> {mapping['target'] + port - mapping['first']}/{item.protocol}"
                )
        values["Forwarding"] = ", ".join(sorted(forwarded))
    elif container_engine(info)[0]:
        values["Container"] = "unresolved (no unique accessible container match)"
    return values


def format_process_columns(
    sockets, processes, descriptions, containers, *, all_details=False, verbose=False
):
    columns = (
        DETAIL_COLUMNS
        if all_details
        else COMPACT_COLUMNS + (("Command",) if verbose else ())
    )
    lines = ["\t".join(("Row", *columns))]
    cached = {}
    users = {}
    for index, item in enumerate(sockets, 1):
        owners = {}
        for pid, _, name in item.owners:
            if pid in owners:
                continue
            info = processes.get(str(pid), {"error": "process metadata unavailable"})
            if pid not in cached:
                cached[pid] = process_columns(pid, name, info, descriptions, users)
            values = socket_columns(item, pid, info, cached[pid], containers)
            owners[pid] = values if all_details else compact_columns(values, info)
        if not owners:
            owners[None] = {
                "Metadata": "process owner unavailable in socket snapshot",
            }
        cells = [str(index)]
        for column in columns:
            separator = ";" if column == "PID" else " | "
            cells.append(
                separator.join(
                    clean(values.get(column, "")) or "-" for values in owners.values()
                )
            )
        lines.append("\t".join(cells))
    return "\n".join(lines)


def metadata_snapshot(requests, runner, uid, *, all_details=False):
    if uid == 0:
        processes = collect_processes(requests)
        containers, notes = (
            container_inventory(processes, runner, 0) if all_details else ([], [])
        )
        return processes, containers, notes
    command = [
        "sudo",
        "-n",
        sys.executable,
        "-I",
        str(Path(__file__).resolve()),
        "--collect",
    ]
    if all_details:
        command.append("--all-details")
    try:
        raw = runner.run(command, input_text=json.dumps(requests), timeout=7)
        data = json.loads(raw)
        if not (
            isinstance(data["processes"], dict)
            and isinstance(data["containers"], list)
            and isinstance(data["notes"], list)
        ):
            raise TypeError("invalid process metadata response")
        return data["processes"], data["containers"], data["notes"]
    except (CommandError, ValueError, KeyError, TypeError) as exc:
        return (
            collect_processes(requests),
            [],
            [f"privileged process details unavailable: {exc}"],
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="add the shortened command column"
    )
    parser.add_argument(
        "--all-details",
        action="store_true",
        help="show every metadata column and complete command paths",
    )
    parser.add_argument("--collect", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    runner = Runner(budget=5 if options.collect else 12)
    uid = os.geteuid()
    if options.collect:
        processes = collect_processes(json.load(sys.stdin))
        containers, notes = (
            container_inventory(processes, runner, uid)
            if options.all_details
            else ([], [])
        )
        json.dump(
            {"processes": processes, "containers": containers, "notes": notes},
            sys.stdout,
        )
        return 0
    sockets = parse_sockets(sys.stdin.read(), all_details=True)
    requests = process_requests(sockets)
    processes, containers, notes = (
        metadata_snapshot(requests, runner, uid, all_details=options.all_details)
        if requests
        else ({}, [], [])
    )
    descriptions = {}
    if options.all_details:
        descriptions, unit_notes = unit_descriptions(processes, runner, uid)
        notes.extend(unit_notes)
    if uid != 0 and options.all_details:
        extra, container_notes = container_inventory(processes, runner, uid)
        containers.extend(extra)
        notes.extend(container_notes)
    print(
        format_process_columns(
            sockets,
            processes,
            descriptions,
            containers,
            all_details=options.all_details,
            verbose=options.verbose,
        )
    )
    for note in dict.fromkeys(notes):
        print(f"Details: {clean(note, 300)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(0) from None
    except KeyboardInterrupt:
        raise SystemExit(130) from None
