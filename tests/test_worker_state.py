from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from worker_state import WorkerNotReady, load_worker_target
from test_cli_lifecycle import CLI
from test_mcp import MCP


class WorkerStateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.runtime = Path(self.directory.name)
        self.binary = os.path.realpath(self.runtime / "fixture.bin")
        digest = hashlib.md5(self.binary.encode()).hexdigest()[:12]
        self.stem = self.runtime / f"worker-{digest}"
        self.state = {"protocol": 1, "pid": 123, "port": 43123,
                      "session_id": "session-a", "requested_path": self.binary}

    def write_state(self):
        self.stem.with_suffix(".json").write_text(json.dumps(self.state))

    def test_state_record_is_authoritative_over_stale_legacy_files(self):
        self.write_state()
        self.stem.with_suffix(".port").write_text("54321")
        self.stem.with_suffix(".pid").write_text("999")
        self.assertEqual((43123, "session-a"), load_worker_target(self.runtime, self.binary))

    def test_legacy_port_alone_cannot_select_a_worker(self):
        self.stem.with_suffix(".port").write_text("54321")
        with self.assertRaisesRegex(ValueError, "legacy"):
            load_worker_target(self.runtime, self.binary)

    def test_missing_and_starting_workers_can_be_resolved_through_bridge(self):
        with self.assertRaises(WorkerNotReady):
            load_worker_target(self.runtime, self.binary)
        self.state["port"] = None
        self.write_state()
        with self.assertRaises(WorkerNotReady):
            load_worker_target(self.runtime, self.binary)

    def test_corrupt_or_mismatched_state_is_rejected(self):
        for key, value in [("session_id", ""), ("pid", -1), ("pid", True),
                           ("protocol", True), ("protocol", 2), ("port", True),
                           ("port", 65536), ("requested_path", "elsewhere")]:
            with self.subTest(key=key, value=value), mock.patch.dict(self.state, {key: value}):
                self.write_state()
                with self.assertRaises(ValueError):
                    load_worker_target(self.runtime, self.binary)
        self.stem.with_suffix(".json").write_text("{")
        with self.assertRaises(ValueError):
            load_worker_target(self.runtime, self.binary)

    def test_late_readiness_preserves_the_captured_session_guard(self):
        self.state["port"] = None
        self.write_state()
        self.stem.with_suffix(".port").write_text("43124")
        self.assertEqual((43124, "session-a"), load_worker_target(self.runtime, self.binary))
        self.assertIsNone(json.loads(self.stem.with_suffix(".json").read_text())["port"])

    def test_binary_calls_wrap_commands_so_legacy_workers_cannot_execute_them(self):
        for client in [CLI, MCP]:
            with self.subTest(client=client.__name__), mock.patch.object(client.socket, "socket") as factory:
                sock = factory.return_value.__enter__.return_value
                sock.recv.return_value = b'{"status":"ok","result":{}}\n'
                client.send_command(43123, "set-comment", {"comment": "edit"}, "session-a")
                request = json.loads(sock.sendall.call_args.args[0])
                self.assertEqual({"cmd": "worker-command", "session_id": "session-a",
                                  "args": {"cmd": "set-comment", "args": {"comment": "edit"}}}, request)

    def test_explicit_port_retains_direct_protocol(self):
        for client in [CLI, MCP]:
            with self.subTest(client=client.__name__), mock.patch.object(client.socket, "socket") as factory:
                sock = factory.return_value.__enter__.return_value
                sock.recv.return_value = b'{"status":"ok","result":{}}\n'
                client.send_command(43123, "info", {})
                self.assertEqual({"cmd": "info", "args": {}}, json.loads(sock.sendall.call_args.args[0]))


if __name__ == "__main__":
    unittest.main()
