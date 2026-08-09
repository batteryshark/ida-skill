#!/usr/bin/env python3
"""types — read the type/name at an address and apply inline C type strings.

Ported from re_mcp_ida/tools/types.py into the idalib worker handler format.
All ``ida_*``/``idc`` imports live inside handler bodies; each handler takes
``args: dict`` and returns a JSON-serializable dict.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import IDAError, format_address, resolve_address


def get_type_info(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    type_str = idc.get_type(ea) or ""
    name = idc.get_name(ea) or ""
    return {
        "address": format_address(ea),
        "name": name,
        "type": type_str,
    }


def set_type(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    type_string = args["type_string"]
    old_type = idc.get_type(ea) or ""
    success = idc.SetType(ea, type_string)
    if not success:
        raise IDAError(
            f"Failed to apply type {type_string!r} at {format_address(ea)}",
            error_type="SetTypeFailed",
        )
    return {
        "address": format_address(ea),
        "old_type": old_type,
        "type": type_string,
    }


COMMANDS = [
    Command(
        "get-type-info", get_type_info, "types",
        "Read the name and current IDA type string at an address.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or symbol name."),
        ],
    ),
    Command(
        "set-type", set_type, "types",
        "Apply an inline C type string at a data address.", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or symbol name."),
            Param("type_string", "str", required=True, positional=True,
                  help="C type declaration (e.g. \"int (*)(void *, int)\")."),
        ],
        aliases=["set_type"],
    ),
]
