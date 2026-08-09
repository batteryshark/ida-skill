#!/usr/bin/env python3
"""cli.py — Thin TCP client for the idalib worker (manifest-driven).

Every worker command is exposed as a real subcommand with proper ``--help``,
generated from the command manifest in ``handlers/`` + ``ida_cmd.py``. A
generic ``call`` escape hatch forwards arbitrary commands/args, and
``commands`` prints the catalog.

Usage:
  python cli.py <command> [args] --binary <path> [--port <n>] [--output text|json] [--raw]
  python cli.py call <command> key=value [key2=value2 ...] --binary <path>
  python cli.py commands [--category X]

Examples:
  python cli.py info --binary a.out
  python cli.py list-functions --filter_pattern "decrypt" --binary a.out
  python cli.py decompile main --binary a.out
  python cli.py call get-xrefs-to address=main --binary a.out

For the full command reference, read references/*.md or run `commands`.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ida_cmd import Command, Param  # noqa: E402
import handlers  # noqa: E402

BIN_DIR = Path(os.environ.get("IDA_SKILL_BIN_DIR", SCRIPT_DIR.parent / "bin")).expanduser().resolve()
RUNTIME_STATE = BIN_DIR / "runtime"


# ─────────────────────────────────────────────────────────────────────────────
# Built-in lifecycle commands — schema only (handled by the worker directly)
# ─────────────────────────────────────────────────────────────────────────────
_BUILTIN_SPECS = [
    Command("open", None, "lifecycle", "Open a binary/database in the worker.",
            params=[Param("file_path", "str", required=True, positional=True,
                          help="Path to binary or .i64/.idb."),
                    Param("run_auto_analysis", "bool", default=True,
                          help="Run auto-analysis on open.")]),
    Command("close", None, "lifecycle", "Close the current database.",
            params=[Param("save", "bool", default=True, help="Save before closing.")]),
    Command("save", None, "lifecycle", "Flush the database to disk."),
    Command("list-commands", None, "lifecycle", "List all commands (worker-side)."),
]


def _all_commands() -> list[Command]:
    return _BUILTIN_SPECS + list(handlers.COMMANDS)


# ─────────────────────────────────────────────────────────────────────────────
# Worker connection
# ─────────────────────────────────────────────────────────────────────────────
def _auto_start_worker(binary_path: str) -> bool:
    """Start the worker via bridge.mjs. Safe under concurrency: the bridge
    serializes simultaneous starts with a lock file, so N agents racing here
    converge on one worker. Opt out with IDA_SKILL_NO_AUTOSTART=1."""
    if os.environ.get("IDA_SKILL_NO_AUTOSTART"):
        return False
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        print("ERROR: node not found on PATH; cannot auto-start the worker.", file=sys.stderr)
        return False
    print(f"No running worker for {binary_path}; starting one (this can take a while "
          "on first import)...", file=sys.stderr)
    proc = subprocess.run(
        [node, str(SCRIPT_DIR / "bridge.mjs"), "start", "--binary", binary_path],
        stdout=sys.stderr, stderr=sys.stderr,
    )
    return proc.returncode == 0


def resolve_port(binary_path: str | None, explicit_port: int | None = None,
                 auto_start: bool = True) -> int:
    if explicit_port:
        return explicit_port
    if not binary_path:
        print("ERROR: --binary or --port is required", file=sys.stderr)
        sys.exit(1)

    import hashlib

    resolved = os.path.realpath(binary_path)
    h = hashlib.md5(resolved.encode()).hexdigest()[:12]
    port_file = RUNTIME_STATE / f"worker-{h}.port"
    if not port_file.exists() and auto_start:
        _auto_start_worker(binary_path)
    if not port_file.exists():
        print(f"ERROR: No worker found for {binary_path}", file=sys.stderr)
        print(f"  Port file not found: {port_file}", file=sys.stderr)
        print(f"  Start a worker: node scripts/bridge.mjs start --binary '{binary_path}'", file=sys.stderr)
        sys.exit(1)
    return int(port_file.read_text().strip())


def send_command(port: int, cmd: str, args: dict) -> dict:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(300)
        sock.connect(("127.0.0.1", port))
        request = json.dumps({"cmd": cmd, "args": args}) + "\n"
        sock.sendall(request.encode("utf-8"))

        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
        sock.close()
        if not data:
            return {"status": "error", "error": "Empty response from worker", "error_type": "EmptyResponse"}
        return json.loads(data.decode("utf-8").strip())
    except ConnectionRefusedError:
        return {"status": "error",
                "error": f"Connection refused on port {port}. Worker may have died.",
                "error_type": "ConnectionRefused"}
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error": str(e), "error_type": type(e).__name__}


# ─────────────────────────────────────────────────────────────────────────────
# Argparse construction (manifest-driven)
# ─────────────────────────────────────────────────────────────────────────────
def _intish(s: str) -> int:
    return int(s, 0)


def _add_param(parser: argparse.ArgumentParser, p: Param) -> None:
    if p.kind == "bool":
        # default True  → offer --no-<name> (store_false)
        # default False → offer --<name>    (store_true)
        if p.default:
            parser.add_argument(f"--no-{p.name}", dest=p.name, action="store_false",
                                default=True, help=f"Disable: {p.help}")
        else:
            parser.add_argument(f"--{p.name}", dest=p.name, action="store_true",
                                default=False, help=p.help)
        return

    kwargs: dict = {"help": p.help}
    if p.kind == "int":
        kwargs["type"] = _intish
    if p.positional:
        if not p.required:
            kwargs["nargs"] = "?"
            kwargs["default"] = p.default
        parser.add_argument(p.name, **kwargs)
    else:
        kwargs["default"] = p.default
        kwargs["required"] = p.required
        parser.add_argument(f"--{p.name}", dest=p.name, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="idalib CLI client (manifest-driven). Talks to the worker bridge.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run `commands` for the catalog, or read references/*.md.",
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--binary", default=None, help="Binary path (resolves worker port).")
    common.add_argument("--port", type=int, default=None, help="Direct worker port.")
    common.add_argument(
        "--output", choices=("text", "json"), default="text",
        help="Output format for the command result (default: compact text). "
             "json is disabled unless IDA_SKILL_ALLOW_JSON=1 is set.",
    )
    common.add_argument("--raw", action="store_true",
                        help="Print the raw envelope JSON. "
                             "Disabled unless IDA_SKILL_ALLOW_JSON=1 is set.")

    sub = parser.add_subparsers(dest="command", required=True)

    # One subparser per manifest command (+ aliases).
    for cmd in _all_commands():
        help_text = cmd.summary or cmd.name
        for name in cmd.all_names():
            sp = sub.add_parser(name, help=help_text, parents=[common],
                                description=f"[{cmd.category}] {cmd.summary}")
            for p in cmd.params:
                _add_param(sp, p)
            sp.set_defaults(_cmd=cmd)

    # Generic escape hatch: `call <cmd> key=value ...`
    sp = sub.add_parser("call", help="Call any command with key=value args.", parents=[common])
    sp.add_argument("target", help="Worker command name.")
    sp.add_argument("kv", nargs="*", help="key=value pairs (values are JSON-parsed if possible).")
    sp.add_argument("--json", dest="json_args", default=None, help="Full args as a JSON object.")

    # Catalog.
    sp = sub.add_parser("commands", help="List all commands and summaries.")
    sp.add_argument("--category", default=None, help="Filter by category.")

    return parser


def _ns_to_args(ns: argparse.Namespace, cmd: Command) -> dict:
    out: dict = {}
    for p in cmd.params:
        val = getattr(ns, p.name, p.default)
        if val is None and not p.required:
            continue
        if p.kind == "json" and isinstance(val, str):
            try:
                val = json.loads(val)
            except json.JSONDecodeError:
                pass
        out[p.name] = val
    return out


def _parse_kv(pairs: list[str]) -> dict:
    out: dict = {}
    for item in pairs:
        if "=" not in item:
            print(f"ERROR: bad key=value pair: {item!r}", file=sys.stderr)
            sys.exit(2)
        key, _, raw = item.partition("=")
        try:
            out[key] = json.loads(raw)
        except json.JSONDecodeError:
            out[key] = raw
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────
def _scalar_text(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _is_single_line_scalar(value) -> bool:
    text = _scalar_text(value)
    return not isinstance(value, (dict, list)) and "\n" not in text and "\t" not in text


def _table_lines(rows: list[dict], indent: int) -> list[str] | None:
    """Render flat record lists with field names once instead of once per row."""
    if not rows or not all(isinstance(row, dict) for row in rows):
        return None
    columns = list(dict.fromkeys(key for row in rows for key in row))
    if not columns or any(
        not _is_single_line_scalar(row.get(column))
        for row in rows
        for column in columns
    ):
        return None
    prefix = " " * indent
    lines = [prefix + "\t".join(columns)]
    lines.extend(
        prefix + "\t".join(_scalar_text(row.get(column)) for column in columns)
        for row in rows
    )
    return lines


def _text_lines(value, indent: int = 0) -> list[str]:
    prefix = " " * indent
    if isinstance(value, dict):
        if not value:
            return [prefix + "{}"]
        lines: list[str] = []
        for key, item in value.items():
            if _is_single_line_scalar(item):
                lines.append(f"{prefix}{key}: {_scalar_text(item)}")
                continue
            if isinstance(item, str):
                lines.append(f"{prefix}{key}:")
                lines.extend(f"{prefix}  {line}" for line in item.splitlines())
                continue
            if isinstance(item, list):
                if not item:
                    lines.append(f"{prefix}{key}: []")
                    continue
                if all(_is_single_line_scalar(entry) for entry in item):
                    lines.append(f"{prefix}{key}: {', '.join(_scalar_text(entry) for entry in item)}")
                    continue
                table = _table_lines(item, indent + 2)
                lines.append(f"{prefix}{key}:")
                lines.extend(table if table is not None else _text_lines(item, indent + 2))
                continue
            lines.append(f"{prefix}{key}:")
            lines.extend(_text_lines(item, indent + 2))
        return lines
    if isinstance(value, list):
        if not value:
            return [prefix + "[]"]
        if all(_is_single_line_scalar(item) for item in value):
            return [prefix + ", ".join(_scalar_text(item) for item in value)]
        table = _table_lines(value, indent)
        if table is not None:
            return table
        lines = []
        for item in value:
            if _is_single_line_scalar(item):
                lines.append(f"{prefix}- {_scalar_text(item)}")
            else:
                lines.append(prefix + "-")
                lines.extend(_text_lines(item, indent + 2))
        return lines
    if isinstance(value, str) and "\n" in value:
        return [prefix + line for line in value.splitlines()]
    return [prefix + _scalar_text(value)]


def _disassembly_lines(data) -> list[str] | None:
    """Return the compact address/instruction view for disassembly-shaped results."""
    if not isinstance(data, dict):
        return None
    records = data.get("instructions")
    text_key = "disasm"
    if records is not None and "instruction_count" not in data:
        return None
    if records is None:
        records = data.get("lines")
        text_key = "text"
        if records is not None and "count" not in data:
            return None
    if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
        return None
    if records and not all("address" in row and text_key in row for row in records):
        return None
    return [f"{row['address']}  {row[text_key]}" for row in records] or ["(no instructions)"]


def format_text(data) -> str:
    lines = _disassembly_lines(data)
    if lines is None:
        lines = _text_lines(data)
    return "\n".join(lines)


def print_result(result: dict, raw: bool = False, output: str = "text"):
    if raw:
        print(json.dumps(result, indent=2, default=str))
        return
    if result.get("status") == "error":
        detail = result.get("details")
        extra = f" {json.dumps(detail)}" if detail else ""
        print(f"ERROR [{result.get('error_type', 'Error')}]: {result.get('error')}{extra}",
              file=sys.stderr)
        sys.exit(1)
    data = result.get("result", result)
    if output == "json":
        print(json.dumps(data, indent=2, default=str))
    else:
        print(format_text(data))


def cmd_commands(category: str | None):
    by_cat: dict[str, list[Command]] = {}
    for c in _all_commands():
        by_cat.setdefault(c.category, []).append(c)
    for cat in sorted(by_cat):
        if category and cat != category:
            continue
        print(f"\n=== {cat} ===")
        for c in sorted(by_cat[cat], key=lambda x: x.name):
            flag = "*" if c.mutates else " "
            alias = f"  (alias: {', '.join(c.aliases)})" if c.aliases else ""
            print(f" {flag} {c.name:<32} {c.summary}{alias}")
    print("\n(* = mutates the database)")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def _enforce_text_output(ns) -> None:
    """Downgrade JSON/raw output to compact text unless explicitly enabled.

    The compact text format is the canonical, token-efficient view for agents;
    JSON is verbose and gated behind IDA_SKILL_ALLOW_JSON=1 for the rare
    programmatic pipeline that parses the output (e.g. rekit_run.py).
    """
    if os.environ.get("IDA_SKILL_ALLOW_JSON"):
        return
    if getattr(ns, "raw", False) or getattr(ns, "output", "text") == "json":
        print("note: JSON output is disabled — compact text is the canonical format. "
              "(Set IDA_SKILL_ALLOW_JSON=1 only for pipelines that must parse JSON.)",
              file=sys.stderr)
        ns.raw = False
        ns.output = "text"


def main():
    parser = build_parser()
    ns = parser.parse_args()
    _enforce_text_output(ns)

    if ns.command == "commands":
        cmd_commands(ns.category)
        return

    if ns.command == "call":
        args = json.loads(ns.json_args) if ns.json_args else _parse_kv(ns.kv)
        target = ns.target
    else:
        cmd: Command = ns._cmd
        # Resolve alias → canonical worker command name.
        target = ns.command if ns.command == cmd.name else cmd.name
        args = _ns_to_args(ns, cmd)

    port = resolve_port(ns.binary, ns.port)
    result = send_command(port, target, args)
    if (result.get("error_type") == "ConnectionRefused"
            and ns.binary and not ns.port
            and _auto_start_worker(ns.binary)):
        # Worker died (idle timeout or crash) — it has been restarted; retry once.
        port = resolve_port(ns.binary, None, auto_start=False)
        result = send_command(port, target, args)
    print_result(result, getattr(ns, "raw", False), getattr(ns, "output", "text"))


if __name__ == "__main__":
    main()
