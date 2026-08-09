#!/usr/bin/env python3
"""dirtree — IDA directory tree (folder) tools for organizing functions, names, etc.

Ported from re_mcp_ida/tools/dirtree.py.

Follows the handler contract (see handlers/functions.py):

  * All ``ida_*`` imports live INSIDE handler functions.
  * Each handler takes ``args: dict`` and returns a JSON-serializable dict.
  * Failures raise ``IDAError(msg, error_type=...)``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import IDAError


def _tree_map() -> dict:
    """Lazy map of tree name -> IDA DIRTREE_* constant."""
    import ida_dirtree

    return {
        "funcs": ida_dirtree.DIRTREE_FUNCS,
        "names": ida_dirtree.DIRTREE_NAMES,
        "local_types": ida_dirtree.DIRTREE_LOCAL_TYPES,
        "imports": ida_dirtree.DIRTREE_IMPORTS,
    }


def _get_dirtree(tree: str):
    """Resolve a tree name to its dirtree object. Raises ``IDAError`` on failure."""
    import ida_dirtree

    tree_map = _tree_map()
    tree_id = tree_map.get(tree)
    if tree_id is None:
        raise IDAError(
            f"Invalid tree: {tree!r}",
            error_type="InvalidArgument",
            valid_trees=list(tree_map),
        )

    dt = ida_dirtree.get_std_dirtree(tree_id)
    if dt is None:
        raise IDAError("Failed to get directory tree", error_type="NotAvailable")

    return dt


def list_folders(args: dict) -> dict:
    import ida_dirtree

    tree = args.get("tree", "funcs") or "funcs"
    path = args.get("path", "/") or "/"
    dt = _get_dirtree(tree)

    entries = []
    it = ida_dirtree.dirtree_iterator_t()
    ok = dt.findfirst(it, path + "*" if path.endswith("/") else path + "/*")
    while ok:
        de = dt.resolve_cursor(it.cursor)
        name = dt.get_entry_name(de)
        abspath = dt.get_abspath(it.cursor)
        is_dir = dt.isdir(abspath)
        entries.append(
            {
                "name": name,
                "is_folder": bool(is_dir),
                "path": abspath,
            }
        )
        ok = dt.findnext(it)

    return {
        "tree": tree,
        "path": path,
        "count": len(entries),
        "entries": entries,
    }


def create_folder(args: dict) -> dict:
    tree = args["tree"]
    path = args["path"]
    dt = _get_dirtree(tree)

    code = dt.mkdir(path)
    if code != 0:
        raise IDAError(f"Failed to create folder: error {code}", error_type="CreateFailed")

    return {"tree": tree, "path": path, "old_path": None, "new_path": None}


def rename_folder(args: dict) -> dict:
    tree = args["tree"]
    old_path = args["old_path"]
    new_path = args["new_path"]
    dt = _get_dirtree(tree)

    code = dt.rename(old_path, new_path)
    if code != 0:
        raise IDAError(f"Failed to rename: error {code}", error_type="RenameFailed")

    return {"tree": tree, "old_path": old_path, "new_path": new_path, "path": new_path}


def delete_folder(args: dict) -> dict:
    tree = args["tree"]
    path = args["path"]
    dt = _get_dirtree(tree)

    code = dt.rmdir(path)
    if code != 0:
        raise IDAError(f"Failed to delete folder: error {code}", error_type="DeleteFailed")

    return {"tree": tree, "path": path, "old_path": None, "new_path": None}


COMMANDS = [
    Command(
        "list-folders", list_folders, "dirtree",
        "List folders and items in IDA's directory tree.",
        params=[
            Param("tree", "str", default="funcs",
                  help='"funcs", "names", "local_types", or "imports".'),
            Param("path", "str", default="/", help='Directory path (default "/").'),
        ],
    ),
    Command(
        "create-folder", create_folder, "dirtree",
        "Create a new folder in IDA's directory tree.", mutates=True,
        params=[
            Param("tree", "str", required=True, positional=True,
                  help='"funcs", "names", "local_types", or "imports".'),
            Param("path", "str", required=True, positional=True,
                  help='Full path to create (e.g. "/crypto/aes").'),
        ],
    ),
    Command(
        "rename-folder", rename_folder, "dirtree",
        "Rename or move a folder in IDA's directory tree.", mutates=True,
        params=[
            Param("tree", "str", required=True, positional=True,
                  help='"funcs", "names", "local_types", or "imports".'),
            Param("old_path", "str", required=True, positional=True,
                  help="Current path of the folder/item."),
            Param("new_path", "str", required=True, positional=True,
                  help="New path for the folder/item."),
        ],
    ),
    Command(
        "delete-folder", delete_folder, "dirtree",
        "Delete an empty folder from IDA's directory tree.", mutates=True,
        params=[
            Param("tree", "str", required=True, positional=True,
                  help='"funcs", "names", "local_types", or "imports".'),
            Param("path", "str", required=True, positional=True,
                  help="Path of the folder to delete."),
        ],
    ),
]
