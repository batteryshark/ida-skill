from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location("ida_worker_lifecycle_test", SCRIPT_DIR / "worker.py")
assert SPEC and SPEC.loader
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)


class WorkerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.idapro = SimpleNamespace(
            close_database=mock.Mock(), open_database=mock.Mock(return_value=0),
        )
        self.loader = SimpleNamespace(
            PATH_TYPE_IDB=1, get_path=mock.Mock(return_value="/analysis/renamed.i64"),
        )
        patches = [
            mock.patch.dict(sys.modules, {"idapro": self.idapro, "ida_loader": self.loader}),
            mock.patch.object(WORKER.ida_session, "current_path", "/inputs/source.bin"),
            mock.patch.object(WORKER.ida_session, "capabilities", {"decompiler": True}),
            mock.patch.object(WORKER, "_autosave", {"mutations": 3, "last_save": 1}),
            mock.patch.object(WORKER, "_probe_capabilities", return_value={"decompiler": True}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_save_reopens_the_database_and_preserves_requested_path(self):
        result = WORKER.cmd_save({})

        self.loader.get_path.assert_called_once_with(self.loader.PATH_TYPE_IDB)
        self.idapro.close_database.assert_called_once_with(True)
        self.idapro.open_database.assert_called_once_with("/analysis/renamed.i64", False)
        self.assertEqual({"status": "saved", "path": "/inputs/source.bin"}, result)
        self.assertEqual("/inputs/source.bin", WORKER.ida_session.current_path)
        self.assertEqual({"decompiler": True}, WORKER.ida_session.capabilities)
        self.assertEqual(0, WORKER._autosave["mutations"])

    def test_failed_close_preserves_open_session_and_unsaved_work(self):
        self.idapro.close_database.side_effect = OSError("disk full")

        with self.assertRaises(WORKER.IDAError) as raised:
            WORKER.cmd_close({})

        self.assertEqual("CloseFailed", raised.exception.error_type)
        self.assertEqual("/inputs/source.bin", WORKER.ida_session.current_path)
        self.assertEqual({"decompiler": True}, WORKER.ida_session.capabilities)
        self.assertEqual({"mutations": 3, "last_save": 1}, WORKER._autosave)

    def test_failed_save_close_does_not_reopen_or_forget_unsaved_work(self):
        self.idapro.close_database.side_effect = OSError("disk full")

        with self.assertRaises(OSError):
            WORKER.cmd_save({})

        self.idapro.open_database.assert_not_called()
        self.assertEqual("/inputs/source.bin", WORKER.ida_session.current_path)
        self.assertEqual({"decompiler": True}, WORKER.ida_session.capabilities)
        self.assertEqual({"mutations": 3, "last_save": 1}, WORKER._autosave)

    def test_failed_reopen_leaves_saved_database_closed(self):
        self.idapro.open_database.return_value = 4

        with self.assertRaises(WORKER.IDAError) as raised:
            WORKER.cmd_save({})

        self.assertEqual("SaveReopenFailed", raised.exception.error_type)
        self.assertIsNone(WORKER.ida_session.current_path)
        self.assertEqual({}, WORKER.ida_session.capabilities)
        self.assertEqual(0, WORKER._autosave["mutations"])

    def test_missing_database_path_does_not_close(self):
        self.loader.get_path.return_value = ""

        with self.assertRaises(WORKER.IDAError) as raised:
            WORKER.cmd_save({})

        self.assertEqual("SaveFailed", raised.exception.error_type)
        self.idapro.close_database.assert_not_called()
        self.idapro.open_database.assert_not_called()
        self.assertEqual("/inputs/source.bin", WORKER.ida_session.current_path)

    def test_close_without_save_clears_session_after_success(self):
        result = WORKER.cmd_close({"save": False})

        self.idapro.close_database.assert_called_once_with(False)
        self.assertEqual({"status": "closed", "path": "/inputs/source.bin", "saved": False}, result)
        self.assertIsNone(WORKER.ida_session.current_path)
        self.assertEqual({}, WORKER.ida_session.capabilities)


if __name__ == "__main__":
    unittest.main()
