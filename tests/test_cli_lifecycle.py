from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location("ida_cli_lifecycle_test", SCRIPT_DIR / "cli.py")
assert SPEC and SPEC.loader
CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLI)


class CliLifecycleTests(unittest.TestCase):
    def test_resolve_target_autostarts_a_missing_worker(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "fixture.bin"
            binary.write_bytes(b"fixture")
            runtime = Path(temp_dir) / "runtime"
            runtime.mkdir()

            def start(binary_path: str) -> bool:
                digest = hashlib.md5(os.path.realpath(binary_path).encode()).hexdigest()[:12]
                (runtime / f"worker-{digest}.json").write_text(json.dumps({
                    "protocol": 1, "pid": 123, "port": 43123,
                    "session_id": "new-session", "requested_path": os.path.realpath(binary_path),
                }))
                return True

            with mock.patch.object(CLI, "RUNTIME_STATE", runtime), \
                    mock.patch.object(CLI, "_auto_start_worker", side_effect=start) as auto_start:
                target = CLI.resolve_target(str(binary))

            self.assertEqual((43123, "new-session"), target)
            auto_start.assert_called_once_with(str(binary))

    def test_session_mismatch_does_not_restart_or_replay_a_mutation(self):
        error = {"status": "error", "error_type": "SessionMismatch", "error": "stale session"}
        with mock.patch.object(CLI, "resolve_target", return_value=(43123, "old")), \
                mock.patch.object(CLI, "send_command", return_value=error) as send, \
                mock.patch.object(CLI, "_auto_start_worker") as start, \
                mock.patch.object(CLI.sys, "argv", ["cli.py", "call", "edit", "--binary", "fixture"]):
            with self.assertRaises(SystemExit):
                CLI.main()
        send.assert_called_once_with(43123, "edit", {}, "old")
        start.assert_not_called()

    def test_connection_refused_resolves_new_session_before_retry(self):
        refused = {"status": "error", "error_type": "ConnectionRefused"}
        with mock.patch.object(CLI, "resolve_target", side_effect=[(43123, "old"), (43124, "new")]), \
                mock.patch.object(CLI, "send_command", side_effect=[refused, {"status": "ok"}]) as send, \
                mock.patch.object(CLI, "_auto_start_worker", return_value=True), \
                mock.patch.object(CLI.sys, "argv", ["cli.py", "call", "edit", "--binary", "fixture"]):
            CLI.main()
        self.assertEqual([mock.call(43123, "edit", {}, "old"), mock.call(43124, "edit", {}, "new")],
                         send.call_args_list)

    def test_text_output_is_enforced_for_agents(self):
        namespace = SimpleNamespace(raw=True, output="json")

        with mock.patch.dict(os.environ, {}, clear=True):
            CLI._enforce_text_output(namespace)

        self.assertFalse(namespace.raw)
        self.assertEqual("text", namespace.output)

    def test_machine_readable_output_requires_explicit_opt_in(self):
        namespace = SimpleNamespace(raw=True, output="json")

        with mock.patch.dict(os.environ, {"IDA_SKILL_ALLOW_JSON": "1"}, clear=True):
            CLI._enforce_text_output(namespace)

        self.assertTrue(namespace.raw)
        self.assertEqual("json", namespace.output)


if __name__ == "__main__":
    unittest.main()
