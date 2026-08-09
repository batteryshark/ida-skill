#!/usr/bin/env python3
"""snapshots — database snapshot (restore point) management tools.

Ported from re_mcp_ida/tools/snapshots.py.

Follows the handler contract (see handlers/functions.py):

  * All ``ida_*``/``idapro`` imports live INSIDE handler functions.
  * Each handler takes ``args: dict`` and returns a JSON-serializable dict.
  * Failures raise ``IDAError(msg, error_type=...)``.

``restore_snapshot`` reproduces the source's save/close/reopen dance using the
worker's ``idapro`` lifecycle and the shared ``session`` state object (the
worker's session has no ``open``/``close`` methods, so the logic is inlined).
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import IDAError, session


def _snapshot_to_dict(snap) -> dict:
    """Convert a snapshot_t to a serializable dict."""
    return {
        "id": str(snap.id),
        "description": snap.desc,
        "filename": snap.filename,
    }


def _collect_tree(node, depth: int = 0) -> list[dict]:
    """Recursively flatten the snapshot tree into a list."""
    entry = _snapshot_to_dict(node)
    entry["depth"] = depth
    items = [entry]
    if node.children:
        for child in node.children:
            items.extend(_collect_tree(child, depth + 1))
    return items


def _find_snapshot(node, snap_id: int):
    """Search the snapshot tree for a node with the given ID."""
    if node.id == snap_id:
        return node
    if node.children:
        for child in node.children:
            found = _find_snapshot(child, snap_id)
            if found is not None:
                return found
    return None


def take_snapshot(args: dict) -> dict:
    import ida_kernwin
    import ida_loader

    description = args.get("description", "") or ""
    snap = ida_loader.snapshot_t()
    if description:
        snap.desc = description

    result = ida_kernwin.take_database_snapshot(snap)
    success, error_msg = result
    if not success:
        raise IDAError(error_msg or "Failed to take snapshot", error_type="SnapshotFailed")

    return _snapshot_to_dict(snap)


def list_snapshots(args: dict) -> dict:
    import ida_loader

    root = ida_loader.snapshot_t()
    if not ida_loader.build_snapshot_tree(root):
        return {"snapshots": [], "count": 0}

    snapshots = _collect_tree(root)
    return {"snapshots": snapshots, "count": len(snapshots)}


def restore_snapshot(args: dict) -> dict:
    import ida_loader
    import idapro

    snapshot_id = args["snapshot_id"]
    try:
        sid = int(snapshot_id)
    except (ValueError, TypeError):
        raise IDAError(
            f"Invalid snapshot ID: {snapshot_id!r}", error_type="InvalidArgument"
        ) from None

    root = ida_loader.snapshot_t()
    if not ida_loader.build_snapshot_tree(root):
        raise IDAError("Failed to build snapshot tree", error_type="SnapshotFailed")

    target = _find_snapshot(root, sid)
    if target is None:
        raise IDAError(f"Snapshot with ID {snapshot_id} not found", error_type="NotFound")

    snap_file = target.filename
    if not snap_file:
        raise IDAError("Snapshot has no associated file", error_type="SnapshotFailed")

    desc = target.desc

    # Save + close the current database, then reopen the snapshot's file —
    # the only reliable approach in headless idalib mode.
    idapro.close_database(True)
    session.current_path = None
    session.capabilities = {}
    idapro.open_database(snap_file, False)
    session.current_path = snap_file

    return {
        "action": "restored",
        "snapshot_id": snapshot_id,
        "description": desc,
        "file": snap_file,
    }


COMMANDS = [
    Command(
        "take-snapshot", take_snapshot, "snapshots",
        "Create a persistent restore point (survives sessions; stronger than undo).",
        mutates=True,
        params=[
            Param("description", "str", default="",
                  help="Optional description for the snapshot."),
        ],
    ),
    Command(
        "list-snapshots", list_snapshots, "snapshots",
        "List all database snapshots (flattened tree with depth).",
    ),
    Command(
        "restore-snapshot", restore_snapshot, "snapshots",
        "Revert the database to a prior snapshot (destroys unsaved changes).",
        mutates=True,
        params=[
            Param("snapshot_id", "str", required=True, positional=True,
                  help="ID of the snapshot to restore (from list-snapshots)."),
        ],
    ),
]
