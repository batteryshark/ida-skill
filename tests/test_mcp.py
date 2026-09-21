from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from _debugshim import McpShim  # noqa: E402


class FakeFastMCP(McpShim):
    def __init__(self, *_args, **_kwargs):
        super().__init__()


with mock.patch.dict(sys.modules, {"fastmcp": SimpleNamespace(FastMCP=FakeFastMCP)}):
    spec = importlib.util.spec_from_file_location("ida_mcp_test", SCRIPT_DIR / "mcp_server.py")
    assert spec and spec.loader
    MCP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(MCP)


class McpPortTests(unittest.TestCase):
    def setUp(self):
        self.worker_port = MCP._worker_port
        self.worker_binary = MCP._worker_binary

    def tearDown(self):
        MCP._worker_port = self.worker_port
        MCP._worker_binary = self.worker_binary

    def test_port_only_mode_routes_tool_calls_to_the_explicit_port(self):
        MCP._worker_port = 43123
        MCP._worker_binary = None

        with mock.patch.object(
            MCP,
            "send_command",
            return_value={"status": "ok", "result": {"path": "fixture.bin"}},
        ) as send:
            result = json.loads(MCP.call_worker("get-database-info"))

        self.assertEqual({"path": "fixture.bin"}, result)
        send.assert_called_once_with(43123, "get-database-info", {})

    def test_port_only_mode_can_report_worker_status(self):
        MCP._worker_port = 43123
        MCP._worker_binary = None

        with mock.patch.object(
            MCP,
            "send_command",
            return_value={"status": "ok", "result": {"path": "fixture.bin"}},
        ) as send:
            result = json.loads(MCP.bridge_status())

        self.assertEqual("fixture.bin", result["result"]["path"])
        send.assert_called_once_with(43123, "info", {})

    def test_registers_every_canonical_worker_command(self):
        MCP.register_all()

        expected = {
            command.name.replace("-", "_")
            for command in MCP.BUILTIN_COMMANDS + list(MCP.handlers.COMMANDS)
        }
        self.assertEqual(expected, set(MCP.mcp.tools) - {"bridge_status"})


if __name__ == "__main__":
    unittest.main()
