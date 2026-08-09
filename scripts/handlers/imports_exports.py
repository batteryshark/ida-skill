#!/usr/bin/env python3
"""imports_exports — import/export/entry-point enumeration and import edits.

Ported from re_mcp_ida/tools/imports_exports.py. All ``ida_*`` imports live
inside the handler bodies; each handler takes ``args: dict`` and returns a
JSON-serializable dict.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    format_address,
    paginate,
    paginate_iter,
    resolve_address,
)


def get_imports(args: dict) -> dict:
    import ida_nalt

    module_filter = args.get("module_filter", "")
    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    all_imports = []
    current_module = ""

    def _import_cb(ea, name, ordinal):
        all_imports.append(
            {
                "module": current_module,
                "address": format_address(ea),
                "name": name or "",
                "ordinal": ordinal,
            }
        )
        return True  # continue enumeration

    filter_lower = module_filter.lower()
    for i in range(ida_nalt.get_import_module_qty()):
        current_module = ida_nalt.get_import_module_name(i) or ""
        if filter_lower and filter_lower not in current_module.lower():
            continue
        ida_nalt.enum_import_names(i, _import_cb)

    return paginate(all_imports, offset, limit)


def get_exports(args: dict) -> dict:
    import idautils

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    def _iter():
        for index, ordinal, ea, name in idautils.Entries():
            yield {
                "index": index,
                "ordinal": ordinal,
                "address": format_address(ea),
                "name": name or "",
            }

    return paginate_iter(_iter(), offset, limit)


def get_entry_points(args: dict) -> dict:
    import ida_entry

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    def _iter():
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal) or ""
            yield {
                "ordinal": ordinal,
                "address": format_address(ea),
                "name": name,
            }

    return paginate_iter(_iter(), offset, limit)


def set_import_name(args: dict) -> dict:
    import ida_loader

    modnode = int(args["modnode"])
    ea = resolve_address(args["address"])
    name = args["name"]
    ida_loader.set_import_name(modnode, ea, name)
    return {"modnode": modnode, "address": format_address(ea), "name": name}


def set_import_ordinal(args: dict) -> dict:
    import ida_loader

    modnode = int(args["modnode"])
    ea = resolve_address(args["address"])
    ordinal = int(args["ordinal"])
    ida_loader.set_import_ordinal(modnode, ea, ordinal)
    return {"modnode": modnode, "address": format_address(ea), "ordinal": ordinal}


COMMANDS = [
    Command(
        "get-imports", get_imports, "imports",
        "List all imported functions grouped by module.",
        params=[
            Param("module_filter", "str", default="",
                  help="Optional substring to filter module names (case-insensitive)."),
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Maximum number of import entries."),
        ],
        aliases=["imports"],
    ),
    Command(
        "get-exports", get_exports, "imports",
        "List all exported symbols.",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Maximum number of results."),
        ],
        aliases=["exports"],
    ),
    Command(
        "get-entry-points", get_entry_points, "imports",
        "List binary entry points (main/DllMain/exports).",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Maximum number of results."),
        ],
    ),
    Command(
        "set-import-name", set_import_name, "imports",
        "Set the name of an import entry in IDA's import module table.", mutates=True,
        params=[
            Param("modnode", "int", required=True,
                  help="Module node index (0-based internal IDA identifier)."),
            Param("address", "str", required=True, positional=True,
                  help="Linear address of the import entry."),
            Param("name", "str", required=True, help="Name to set for the import."),
        ],
    ),
    Command(
        "set-import-ordinal", set_import_ordinal, "imports",
        "Set the ordinal of an import entry in IDA's import module table.", mutates=True,
        params=[
            Param("modnode", "int", required=True,
                  help="Module node index (0-based internal IDA identifier)."),
            Param("address", "str", required=True, positional=True,
                  help="Linear address of the import entry."),
            Param("ordinal", "int", required=True, help="Ordinal number to set."),
        ],
    ),
]
