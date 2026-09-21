from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location("ida_worker_identity_test", SCRIPT_DIR / "worker.py")
assert SPEC and SPEC.loader
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)


class WorkerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.idapro = SimpleNamespace(close_database=mock.Mock(), open_database=mock.Mock())
        self.loader = SimpleNamespace(PATH_TYPE_IDB=1, get_path=mock.Mock(return_value="/analysis/current.i64"))
        patches = [
            mock.patch.dict(sys.modules, {"idapro": self.idapro, "ida_loader": self.loader}),
            mock.patch.object(WORKER, "WORKER_SESSION_ID", "current-session"),
            mock.patch.object(WORKER, "WORKER_REQUESTED_PATH", "/inputs/original.bin"),
            mock.patch.object(WORKER, "_shutdown_requested", threading.Event()),
            mock.patch.object(WORKER, "_shutdown_response_complete", threading.Event()),
            mock.patch.object(WORKER, "_autosave", {"mutations": 3, "last_save": 1}),
            mock.patch.object(WORKER.ida_session, "current_path", "/analysis/current.i64"),
            mock.patch.object(WORKER.ida_session, "capabilities", {"decompiler": True}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_identity_distinguishes_launch_target_from_current_database(self):
        identity = WORKER.handle_command("worker-identity", {})

        self.assertEqual({
            "protocol": 1, "pid": os.getpid(), "session_id": "current-session",
            "requested_path": "/inputs/original.bin", "current_path": "/analysis/current.i64",
            "idb_path": os.path.realpath("/analysis/current.i64"), "state": "ready",
        }, identity)
        self.loader.get_path.assert_called_once_with(self.loader.PATH_TYPE_IDB)
        WORKER.ida_session.current_path = None
        self.loader.get_path.reset_mock()
        identity = WORKER.handle_command("worker-identity", {})
        self.assertIsNone(identity["idb_path"])
        self.assertEqual("/inputs/original.bin", identity["requested_path"])
        self.loader.get_path.assert_not_called()

    def test_session_guards_prevent_side_effects_before_dispatch(self):
        command = WORKER.handlers.REGISTRY["set-comment"]
        with mock.patch.object(command, "handler") as mutate:
            for name, args, session in (
                ("set-comment", {}, "stale-session"),
                ("worker-command", {"cmd": "set-comment", "args": {}}, None),
                ("worker-command", {"cmd": "set-comment", "args": {}}, "stale-session"),
                ("worker-shutdown", {}, None),
                ("worker-shutdown", {}, "stale-session"),
                ("worker-identity", {}, "stale-session"),
            ):
                with self.subTest(command=name, session=session):
                    with self.assertRaises(WORKER.IDAError) as raised:
                        WORKER.handle_command(name, args, session)
                    self.assertEqual("SessionMismatch", raised.exception.error_type)
        mutate.assert_not_called()
        self.idapro.close_database.assert_not_called()
        self.loader.get_path.assert_not_called()
        self.assertEqual(3, WORKER._autosave["mutations"])
        self.assertFalse(WORKER._shutdown_requested.is_set())

    def test_guarded_wrapper_and_legacy_direct_commands_dispatch(self):
        command = WORKER.handlers.REGISTRY["set-comment"]
        with mock.patch.object(command, "handler", return_value={"applied": True}) as mutate:
            wrapped = WORKER.handle_command("worker-command", {
                "cmd": "set-comment", "args": {"comment": "guarded"},
            }, "current-session")
            direct = WORKER.handle_command("set-comment", {"comment": "direct"})
        self.assertEqual(wrapped, direct)
        self.assertEqual([mock.call({"comment": "guarded"}), mock.call({"comment": "direct"})], mutate.call_args_list)
        self.assertEqual(5, WORKER._autosave["mutations"])

    def test_wrapper_cannot_nest_control_rpcs(self):
        for command in ("worker-command", "worker-identity", "worker-shutdown"):
            with self.subTest(command=command):
                with self.assertRaises(WORKER.IDAError) as raised:
                    WORKER.handle_command("worker-command", {"cmd": command}, "current-session")
                self.assertEqual("UnknownCommand", raised.exception.error_type)
        self.idapro.close_database.assert_not_called()
        self.assertFalse(WORKER._shutdown_requested.is_set())

    def test_failed_save_leaves_worker_active_and_database_open(self):
        self.idapro.close_database.side_effect = OSError("disk full")
        with self.assertLogs("ida-worker", level="ERROR"):
            with self.assertRaises(WORKER.IDAError) as raised:
                WORKER.handle_command("worker-shutdown", {}, "current-session")
        self.assertEqual("CloseFailed", raised.exception.error_type)
        self.assertFalse(WORKER._shutdown_requested.is_set())
        self.assertEqual("ready", WORKER.handle_command("worker-identity", {})["state"])
        self.assertEqual("/analysis/current.i64", WORKER.ida_session.current_path)
        self.assertEqual({"decompiler": True}, WORKER.ida_session.capabilities)
        self.assertEqual(3, WORKER._autosave["mutations"])

    def test_queued_commands_cannot_reopen_or_mutate_after_shutdown(self):
        executor = WORKER.MainThreadExecutor()
        requests = [
            ("worker-shutdown", {}),
            ("open", {"file_path": "/other.bin"}),
            ("worker-command", {"cmd": "set-comment", "args": {}}),
            ("worker-identity", {}),
        ]
        jobs = [WORKER._Job(WORKER.handle_command, (name, args, "current-session"), {})
                for name, args in requests]
        command = WORKER.handlers.REGISTRY["set-comment"]
        with mock.patch.object(command, "handler") as mutate:
            for job in jobs:
                executor._jobs.put(job)
            executor.drain(timeout=0.02)
        self.idapro.close_database.assert_called_once_with(True)
        self.idapro.open_database.assert_not_called()
        mutate.assert_not_called()
        self.assertEqual("stopping", jobs[0].result["status"])
        self.assertEqual("WorkerStopping", jobs[1].error.error_type)
        self.assertEqual("WorkerStopping", jobs[2].error.error_type)
        self.assertEqual("stopping", jobs[3].result["state"])
        self.assertIsNone(jobs[3].result["current_path"])

    def test_failed_response_write_does_not_hold_shutdown_open(self):
        handler = object.__new__(WORKER.CommandHandler)
        handler.rfile = io.BytesIO(json.dumps({
            "cmd": "worker-shutdown", "args": {}, "session_id": "current-session",
        }).encode() + b"\n")
        handler.wfile = mock.Mock()
        handler.wfile.write.side_effect = BrokenPipeError("client disconnected")
        with mock.patch.object(WORKER, "call_ida", side_effect=lambda fn, *args: fn(*args)), \
                self.assertLogs("ida-worker", level="ERROR"):
            with self.assertRaises(BrokenPipeError):
                handler._handle_request()
        self.assertTrue(WORKER._shutdown_requested.is_set())
        self.assertTrue(WORKER._shutdown_response_complete.is_set())

    def test_non_rpc_shutdown_marks_stopping_before_draining_requests(self):
        executor = mock.Mock()
        executor.drain.side_effect = KeyboardInterrupt
        executor.pending.return_value = False
        server = mock.Mock(server_address=("127.0.0.1", 43123))

        def check_shutdown_guard():
            self.assertEqual("stopping", WORKER.handle_command("worker-identity", {})["state"])
            with self.assertRaises(WORKER.IDAError) as raised:
                WORKER.handle_command("open", {"file_path": "/other.bin"})
            self.assertEqual("WorkerStopping", raised.exception.error_type)

        server.shutdown.side_effect = check_shutdown_guard
        self.idapro.get_library_version = lambda: "test"
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(sys, "argv", ["worker.py", "--port-file", str(Path(directory) / "worker.port")]), \
                mock.patch.object(WORKER, "_setup_environment"), \
                mock.patch.object(WORKER, "_executor", None), \
                mock.patch.object(WORKER, "MainThreadExecutor", return_value=executor), \
                mock.patch.object(WORKER, "ThreadedTCPServer", return_value=server), \
                mock.patch.object(WORKER.signal, "signal"), \
                mock.patch.object(WORKER.ida_session, "current_path", None), \
                self.assertLogs("ida-worker", level="INFO"):
            WORKER.main()
        server.shutdown.assert_called_once()
        executor.drain.assert_called_once_with(timeout=1.0)
        self.idapro.open_database.assert_not_called()
        self.assertFalse(WORKER._shutdown_response_complete.is_set())


class WorkerShutdownTransportTests(unittest.TestCase):
    def test_port_publication_replaces_only_after_complete_write(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "worker.port"
            target.write_text("previous-owner")
            replace = os.replace

            def observe_replace(source, destination):
                self.assertEqual(target.parent, source.parent)
                self.assertEqual("previous-owner", target.read_text())
                self.assertEqual("43123", source.read_text())
                replace(source, destination)

            with mock.patch.object(WORKER.os, "replace", side_effect=observe_replace):
                WORKER._publish_port_file(target, 43123)
            self.assertEqual("43123", target.read_text())
            self.assertEqual([target], list(target.parent.iterdir()))

    def test_tcp_shutdown_acknowledges_and_exits_without_deleting_replacement_metadata(self):
        # Run the real server/main loop, with only the native IDA boundary faked.
        bootstrap = """
import sys
from types import SimpleNamespace
sys.path.insert(0, sys.argv.pop(1))
import worker
worker._setup_environment = lambda: None
worker._probe_capabilities = lambda: {}
sys.modules['idapro'] = SimpleNamespace(
    get_library_version=lambda: 'test', open_database=lambda *args: 0,
    close_database=lambda save: None)
sys.modules['ida_loader'] = SimpleNamespace(PATH_TYPE_IDB=1, get_path=lambda kind: '/analysis/test.i64')
worker.main()
"""
        with tempfile.TemporaryDirectory() as directory:
            port_file = Path(directory) / "worker.port"
            binary = Path(directory) / "input.bin"
            binary.write_bytes(b"fixture")
            process = subprocess.Popen([
                sys.executable, "-c", bootstrap, str(SCRIPT_DIR),
                "--port-file", str(port_file), "--binary", str(binary),
                "--session-id", "transport-session", "--idle-timeout", "2", "--autosave", "0",
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not port_file.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not port_file.exists():
                    _, stderr = process.communicate(timeout=5)
                    self.fail(f"worker did not become ready: {stderr.decode()}")
                port = int(port_file.read_text())

                def request(payload):
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                        connection.sendall(json.dumps(payload).encode() + b"\n")
                        with connection.makefile("rb") as stream:
                            return json.loads(stream.readline())

                identity = request({"cmd": "worker-identity", "args": {}})["result"]
                self.assertEqual(process.pid, identity["pid"])
                self.assertEqual(os.path.realpath(binary), identity["requested_path"])
                mismatch = request({"cmd": "worker-command", "args": {"cmd": "close"}, "session_id": "old-session"})
                self.assertEqual("SessionMismatch", mismatch["error_type"])
                self.assertEqual(os.path.realpath(binary), request({"cmd": "worker-identity"})["result"]["current_path"])
                # Another owner may already have replaced this port file.
                port_file.write_text("replacement-owner")
                with socket.create_connection(("127.0.0.1", port), timeout=3) as unfinished_request:
                    unfinished_request.sendall(b'{"cmd":')
                    reply = request({"cmd": "worker-shutdown", "args": {}, "session_id": "transport-session"})
                    self.assertEqual("ok", reply["status"])
                    self.assertEqual("stopping", reply["result"]["status"])
                    self.assertTrue(reply["result"]["close"]["saved"])
                    process.wait(timeout=4)
                self.assertEqual(0, process.returncode)
                self.assertEqual("replacement-owner", port_file.read_text())
            finally:
                # The fixture also exits on its short idle timeout after a test failure.
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
