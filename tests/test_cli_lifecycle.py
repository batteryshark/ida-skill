from __future__ import annotations

import hashlib
import importlib.util
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
    def test_resolve_port_autostarts_a_missing_worker(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            binary = Path(temp_dir) / "fixture.bin"
            binary.write_bytes(b"fixture")
            runtime = Path(temp_dir) / "runtime"
            runtime.mkdir()

            def start(binary_path: str) -> bool:
                digest = hashlib.md5(os.path.realpath(binary_path).encode()).hexdigest()[:12]
                (runtime / f"worker-{digest}.port").write_text("43123")
                return True

            with mock.patch.object(CLI, "RUNTIME_STATE", runtime), \
                    mock.patch.object(CLI, "_auto_start_worker", side_effect=start) as auto_start:
                port = CLI.resolve_port(str(binary))

            self.assertEqual(43123, port)
            auto_start.assert_called_once_with(str(binary))

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
