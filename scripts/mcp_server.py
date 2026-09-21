#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["fastmcp>=2.0,<3"]
# ///
"""mcp_server.py — MCP server mode for the idalib worker (manifest-driven).

Generates one MCP tool per worker command from the shared manifest in
``handlers/`` + ``ida_cmd.py``, so the MCP surface stays in lock-step with the
CLI automatically — no hand-written wrappers to drift.

Usage (with uv):
  uv run scripts/mcp_server.py --binary /path/to/binary
  uv run scripts/mcp_server.py --port 62927

Harness config (Claude Code, Cursor):
  {
    "mcpServers": {
      "ida": {
        "command": "uv",
        "args": ["run", "/path/to/ida-skill/scripts/mcp_server.py", "--binary", "/path/to/bin"]
      }
    }
  }
"""
from __future__ import annotations

import inspect
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ida_cmd import BUILTIN_COMMANDS, Command  # noqa: E402
from worker_state import load_worker_target  # noqa: E402
import handlers  # noqa: E402

BIN_DIR = Path(os.environ.get("IDA_SKILL_BIN_DIR", SCRIPT_DIR.parent / "bin")).expanduser().resolve()
RUNTIME_STATE = BIN_DIR / "runtime"

_worker_port: int | None = None
_worker_binary: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Worker connection
# ─────────────────────────────────────────────────────────────────────────────
def resolve_target(binary: str | None = None, port: int | None = None) -> tuple[int, str | None]:
    selected_port = port if port is not None else _worker_port
    if selected_port is not None:
        return selected_port, None
    if binary is None:
        binary = _worker_binary
    if binary is None:
        raise ValueError("No --binary or --port specified")
    return load_worker_target(RUNTIME_STATE, binary)


def send_command(port: int, cmd: str, args: dict, session_id: str | None = None) -> dict:
    request = {"cmd": cmd, "args": args}
    if session_id is not None:
        request = {"cmd": "worker-command", "args": request, "session_id": session_id}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(300)
        sock.connect(("127.0.0.1", port))
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
    return json.loads(data.decode("utf-8").strip())


def call_worker(cmd: str, **kwargs) -> str:
    port, session_id = resolve_target()
    result = send_command(port, cmd, kwargs, session_id)
    if result.get("status") == "error":
        detail = result.get("details")
        extra = f" {json.dumps(detail)}" if detail else ""
        raise ValueError(f"[{result.get('error_type')}] {result.get('error')}{extra}")
    return json.dumps(result.get("result", result), indent=2, default=str)


# ─────────────────────────────────────────────────────────────────────────────
# Manifest → MCP tools
# ─────────────────────────────────────────────────────────────────────────────
mcp = FastMCP("IDA Pro")

_KIND_TO_TYPE = {"str": str, "int": int, "bool": bool, "hex": str, "json": Any}


def _make_tool_fn(cmd: Command):
    json_params = {p.name for p in cmd.params if p.kind == "json"}

    def impl(**kwargs):
        args: dict = {}
        for k, v in kwargs.items():
            if v is None:
                continue
            if k in json_params and isinstance(v, str):
                try:
                    v = json.loads(v)
                except json.JSONDecodeError:
                    pass
            args[k] = v
        return call_worker(cmd.name, **args)

    params = []
    ann: dict = {}
    for p in cmd.params:
        typ = _KIND_TO_TYPE.get(p.kind, str)
        default = inspect.Parameter.empty if p.required else p.default
        params.append(inspect.Parameter(p.name, inspect.Parameter.KEYWORD_ONLY,
                                         default=default, annotation=typ))
        ann[p.name] = typ
    impl.__signature__ = inspect.Signature(params, return_annotation=str)
    impl.__annotations__ = {**ann, "return": str}
    impl.__name__ = cmd.name.replace("-", "_")
    impl.__doc__ = cmd.summary or cmd.name
    return impl


def register_all():
    seen: set[str] = set()
    for cmd in BUILTIN_COMMANDS + list(handlers.COMMANDS):
        tool_name = cmd.name.replace("-", "_")
        if tool_name in seen:
            continue
        seen.add(tool_name)
        fn = _make_tool_fn(cmd)
        mcp.tool(name=tool_name, description=cmd.summary or cmd.name)(fn)


@mcp.tool()
def bridge_status() -> str:
    """Check if the worker is running and get database info."""
    if _worker_binary is None and _worker_port is not None:
        return json.dumps(send_command(_worker_port, "info", {}), indent=2, default=str)

    import subprocess

    result = subprocess.run(
        ["node", str(SCRIPT_DIR / "bridge.mjs"), "status", "--binary", _worker_binary or ""],
        capture_output=True, text=True,
    )
    return result.stdout


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(description="ida-skill MCP server")
    parser.add_argument("--binary", help="Binary path (resolves worker port)")
    parser.add_argument("--port", type=int, help="Direct worker port (without binary/session verification)")
    args = parser.parse_args()

    global _worker_binary, _worker_port
    _worker_binary = args.binary
    _worker_port = args.port

    register_all()

    try:
        port, _session_id = resolve_target(args.binary, args.port)
        print(f"Connected to worker on port {port}", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"WARNING: {e}", file=sys.stderr)
        print("Start a worker first: node scripts/bridge.mjs start --binary <path>", file=sys.stderr)

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
