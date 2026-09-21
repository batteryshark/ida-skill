from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location("ida_worker_test", SCRIPT_DIR / "worker.py")
assert SPEC and SPEC.loader
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)


class MainThreadExecutorTests(unittest.TestCase):
    def test_concurrent_submitters_receive_their_own_results(self):
        executor = WORKER.MainThreadExecutor()
        count = 12
        results: dict[int, int] = {}
        errors: list[BaseException] = []

        def submit(value: int) -> None:
            try:
                results[value] = executor.submit(lambda item: item, value)
            except BaseException as exc:
                errors.append(exc)

        threads = []
        for value in range(count):
            thread = threading.Thread(target=submit, args=(value,))
            thread.start()
            threads.append(thread)
            deadline = time.monotonic() + 2
            while executor._jobs.qsize() < value + 1 and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertEqual(value + 1, executor._jobs.qsize())

        executor.drain(timeout=1)
        for thread in threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

        self.assertEqual([], errors)
        self.assertEqual({value: value for value in range(count)}, results)

    def test_shutdown_fails_queued_submitters(self):
        executor = WORKER.MainThreadExecutor()
        errors: list[BaseException] = []

        def submit() -> None:
            try:
                executor.submit(lambda: "unreachable")
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=submit)
        thread.start()
        deadline = time.monotonic() + 2
        while executor._jobs.qsize() != 1 and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertEqual(1, executor._jobs.qsize())

        executor.shutdown()
        thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual(1, len(errors))
        self.assertIsInstance(errors[0], RuntimeError)
        self.assertIn("shutting down", str(errors[0]))


class WorkerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.multi_agent = WORKER.MULTI_AGENT
        self.autosave = dict(WORKER._autosave)

    def tearDown(self):
        WORKER.MULTI_AGENT = self.multi_agent
        WORKER._autosave.update(self.autosave)

    def test_multi_agent_mode_blocks_global_rollback(self):
        WORKER.MULTI_AGENT = True

        with self.assertRaises(WORKER.IDAError) as raised:
            WORKER.handle_command("undo", {})

        self.assertEqual("MultiAgentBlocked", raised.exception.error_type)

    def test_mutating_command_marks_database_unsaved(self):
        command = WORKER.handlers.REGISTRY["set-comment"]
        WORKER._autosave["mutations"] = 0

        with mock.patch.object(command, "requires_open", False), \
                mock.patch.object(command, "handler", return_value={"ok": True}):
            WORKER.handle_command("set-comment", {})

        self.assertEqual(1, WORKER._autosave["mutations"])

    def test_partial_script_failure_keeps_applied_edits_eligible_for_autosave(self):
        fixture = SimpleNamespace(changes=[])
        WORKER._autosave.update({"mutations": 0, "last_save": time.time() - 20})
        code = (
            "import ida_policy_test_fixture\n"
            "ida_policy_test_fixture.changes.append('applied edit')\n"
            "raise RuntimeError('failed after first edit')"
        )

        with mock.patch.dict(sys.modules, {"ida_policy_test_fixture": fixture}), \
                mock.patch.object(WORKER, "is_open", return_value=True), \
                mock.patch.object(WORKER, "cmd_save") as save:
            with self.assertRaises(WORKER.IDAError) as raised:
                WORKER.handle_command("run-script", {"code": code})
            WORKER._maybe_autosave(10, WORKER.ActivityTracker(), WORKER.MainThreadExecutor())

        self.assertEqual("ScriptError", raised.exception.error_type)
        self.assertEqual(["applied edit"], fixture.changes)
        self.assertEqual(1, WORKER._autosave["mutations"])
        save.assert_called_once_with({})

    def test_idc_expression_side_effect_marks_database_unsaved(self):
        writes = []

        def eval_idc(expression):
            writes.append(expression)
            return 1

        WORKER._autosave["mutations"] = 0
        expression = 'set_cmt(4096, "changed", 0)'
        with mock.patch.dict(sys.modules, {"idc": SimpleNamespace(eval_idc=eval_idc)}), \
                mock.patch.object(WORKER, "is_open", return_value=True):
            result = WORKER.handle_command("evaluate-expression", {"expression": expression})

        self.assertEqual([expression], writes)
        self.assertEqual(1, result["result"])
        self.assertEqual(1, WORKER._autosave["mutations"])

    def test_debugger_waits_that_resume_processes_are_side_effecting(self):
        from handlers import debug

        native = SimpleNamespace(
            WFNE_ANY=1, WFNE_CONT=2, DEC_TIMEOUT=-1,
            wait_for_next_event=mock.Mock(return_value=-1),
        )
        with mock.patch.object(WORKER, "is_open", return_value=True), \
                mock.patch.object(debug, "_ensure_ida"), \
                mock.patch.object(debug, "_require_debugger_loaded"), \
                mock.patch.object(debug, "ida_dbg", native), \
                mock.patch.object(debug, "_event_summary", return_value=None), \
                mock.patch.object(debug, "_status", return_value=SimpleNamespace(
                    current_ip=None, process_state="suspended")):
            for name, args in (
                ("debug-event-wait", {"continue_process": True}),
                ("debug-wait-until", {"event": "breakpoint", "timeout_seconds": 1}),
            ):
                with self.subTest(command=name):
                    WORKER._autosave["mutations"] = 0
                    WORKER.handle_command(name, args)
                    flags = native.wait_for_next_event.call_args.args[0]
                    self.assertTrue(flags & native.WFNE_CONT)
                    self.assertEqual(1, WORKER._autosave["mutations"])

    def test_process_listing_tracks_debugger_configuration_changes(self):
        from handlers import debug

        native = SimpleNamespace(
            load_debugger=mock.Mock(return_value=True),
            set_remote_debugger=mock.Mock(), get_processes=mock.Mock(return_value=0),
        )
        WORKER._autosave["mutations"] = 0
        with mock.patch.object(WORKER, "is_open", return_value=True), \
                mock.patch.object(debug, "_ensure_ida"), \
                mock.patch.object(debug, "ida_dbg", native), \
                mock.patch.object(debug, "ida_idd", SimpleNamespace(procinfo_vec_t=list)), \
                mock.patch.object(debug, "idaapi", SimpleNamespace(cvar=SimpleNamespace(batch_mode=False))):
            WORKER.handle_command("debug-process-list", {
                "debugger": "gdb", "remote": True, "target_host": "localhost",
            })

        native.load_debugger.assert_called_once_with("gdb", True)
        native.set_remote_debugger.assert_called_once_with("localhost", "", -1)
        self.assertEqual(1, WORKER._autosave["mutations"])

    def test_autosave_runs_only_after_mutations_age_past_interval(self):
        tracker = WORKER.ActivityTracker()
        executor = WORKER.MainThreadExecutor()
        WORKER._autosave.update({"mutations": 2, "last_save": time.time() - 20})

        with mock.patch.object(WORKER, "is_open", return_value=True), \
                mock.patch.object(WORKER, "cmd_save") as save:
            WORKER._maybe_autosave(10, tracker, executor)

        save.assert_called_once_with({})

    def test_autosave_defers_during_active_requests(self):
        tracker = WORKER.ActivityTracker()
        tracker.begin()
        executor = WORKER.MainThreadExecutor()
        WORKER._autosave.update({"mutations": 1, "last_save": time.time() - 15})

        with mock.patch.object(WORKER, "is_open", return_value=True), \
                mock.patch.object(WORKER, "cmd_save") as save:
            WORKER._maybe_autosave(10, tracker, executor)

        save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
