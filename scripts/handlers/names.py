#!/usr/bin/env python3
"""names — rename addresses and list named locations.

Ported from re_mcp_ida/tools/names.py. See handlers/functions.py for the
reference template conventions.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    compile_filter,
    format_address,
    paginate_iter,
    resolve_address,
)


def rename_address(args: dict) -> dict:
    import ida_name

    ea = resolve_address(args["address"])
    new_name = args["new_name"]

    old_name = ida_name.get_name(ea) or ""
    if not ida_name.set_name(ea, new_name, ida_name.SN_CHECK):
        raise IDAError(
            f"Failed to rename {format_address(ea)} to {new_name!r}", error_type="RenameFailed"
        )
    return {
        "address": format_address(ea),
        "old_name": old_name,
        "new_name": new_name,
    }


def list_names(args: dict) -> dict:
    import idautils

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))
    pattern = compile_filter(args.get("filter_pattern", ""))

    def _iter():
        for ea, name in idautils.Names():
            if pattern and not pattern.search(name):
                continue
            yield {"address": format_address(ea), "name": name}

    return paginate_iter(_iter(), offset, limit)


COMMANDS = [
    Command(
        "rename-address", rename_address, "names",
        "Rename ONE label (data, jump target, any non-function address).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or current name to rename."),
            Param("new_name", "str", required=True, positional=True,
                  help="New name. Empty string removes the name."),
        ],
        aliases=["rename"],
    ),
    Command(
        "list-names", list_names, "names",
        "List every named location (functions + globals + data labels), regex-filterable.",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Max results."),
            Param("filter_pattern", "str", default="", help="Regex over names."),
        ],
    ),
]
