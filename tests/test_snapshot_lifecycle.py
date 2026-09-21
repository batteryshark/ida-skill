from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
from handlers import snapshots  # noqa: E402


class SnapshotLifecycleTests(unittest.TestCase):
    def setUp(self):
        snapshot = SimpleNamespace(
            id=17, desc="checkpoint", filename="snapshot.i64", children=[],
        )
        self.idapro = SimpleNamespace(
            close_database=mock.Mock(), open_database=mock.Mock(return_value=0),
        )
        modules = {
            "idapro": self.idapro,
            "ida_loader": SimpleNamespace(
                snapshot_t=lambda: snapshot, build_snapshot_tree=lambda _: True,
            ),
            "ida_hexrays": SimpleNamespace(init_hexrays_plugin=lambda: True),
            "ida_idp": SimpleNamespace(get_idp_name=lambda: "metapc"),
        }
        for patch in (
            mock.patch.dict(sys.modules, modules),
            mock.patch.object(snapshots.session, "current_path", "current.i64"),
            mock.patch.object(snapshots.session, "capabilities", {"assembler": True}),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def test_failed_open_reports_error_and_leaves_session_closed(self):
        self.idapro.open_database.return_value = 4

        with self.assertRaises(snapshots.IDAError) as raised:
            snapshots.restore_snapshot({"snapshot_id": "17"})

        self.assertEqual("SnapshotOpenFailed", raised.exception.error_type)
        self.assertIsNone(snapshots.session.current_path)
        self.assertEqual({}, snapshots.session.capabilities)

    def test_successful_restore_refreshes_capabilities(self):
        result = snapshots.restore_snapshot({"snapshot_id": "17"})

        self.idapro.close_database.assert_called_once_with(True)
        self.idapro.open_database.assert_called_once_with("snapshot.i64", False)
        self.assertEqual("restored", result["action"])
        self.assertEqual("snapshot.i64", snapshots.session.current_path)
        self.assertEqual({"decompiler": True, "assembler": True}, snapshots.session.capabilities)

    def test_close_failure_preserves_current_session(self):
        self.idapro.close_database.side_effect = OSError("save failed")

        with self.assertRaises(OSError):
            snapshots.restore_snapshot({"snapshot_id": "17"})

        self.idapro.open_database.assert_not_called()
        self.assertEqual("current.i64", snapshots.session.current_path)
        self.assertEqual({"assembler": True}, snapshots.session.capabilities)


if __name__ == "__main__":
    unittest.main()
