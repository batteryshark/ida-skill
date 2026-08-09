#!/usr/bin/env python3
"""func_flags — function flag manipulation, hidden ranges, byte flags.

Ported from re_mcp_ida/tools/func_flags.py into the standalone idalib worker's
handler format: each handler takes ``args: dict`` and returns a
JSON-serializable dict; all ``ida_*`` imports live inside function bodies.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    get_func_name,
    paginate_iter,
    resolve_address,
    resolve_function,
)


def set_function_flags(args: dict) -> dict:
    import ida_funcs

    func = resolve_function(args["address"])
    library = args.get("library", None)
    thunk = args.get("thunk", None)
    noreturn = args.get("noreturn", None)
    hidden = args.get("hidden", None)

    old_flags = func.flags
    flags = func.flags
    flag_map = {
        "library": (library, ida_funcs.FUNC_LIB),
        "thunk": (thunk, ida_funcs.FUNC_THUNK),
        "noreturn": (noreturn, ida_funcs.FUNC_NORET),
        "hidden": (hidden, ida_funcs.FUNC_HIDDEN),
    }

    changed = {}
    for name, (value, bit) in flag_map.items():
        if value is None:
            continue
        if value:
            flags |= bit
        else:
            flags &= ~bit
        changed[name] = value

    if not changed:
        return {
            "address": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "changed": changed,
            "old_flags": old_flags,
            "flags": func.flags,
        }

    func.flags = flags
    if not ida_funcs.update_func(func):
        raise IDAError(
            f"Failed to update function flags at {format_address(func.start_ea)}",
            error_type="UpdateFailed",
        )

    return {
        "address": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "changed": changed,
        "old_flags": old_flags,
        "flags": func.flags,
    }


def get_byte_flags(args: dict) -> dict:
    import ida_bytes

    ea = resolve_address(args["address"])

    flags = ida_bytes.get_flags(ea)
    return {
        "address": format_address(ea),
        "raw_flags": f"0x{flags:X}",
        "is_code": ida_bytes.is_code(flags),
        "is_data": ida_bytes.is_data(flags),
        "is_tail": ida_bytes.is_tail(flags),
        "is_head": ida_bytes.is_head(flags),
        "is_loaded": ida_bytes.is_loaded(ea),
        "has_value": ida_bytes.has_value(flags),
        "has_xref": ida_bytes.has_xref(flags),
        "has_name": ida_bytes.has_name(flags),
        "has_dummy_name": ida_bytes.has_dummy_name(flags),
        "has_auto_name": ida_bytes.has_auto_name(flags),
        "has_user_name": ida_bytes.has_user_name(flags),
        "has_comment": ida_bytes.has_cmt(flags),
        "has_extra_comment": ida_bytes.has_extra_cmts(flags),
        "item_size": ida_bytes.get_item_size(ea),
    }


def add_hidden_range(args: dict) -> dict:
    import ida_bytes

    start = resolve_address(args["start_address"])
    end = resolve_address(args["end_address"])
    description = args.get("description", "") or ""

    if not ida_bytes.add_hidden_range(start, end, description, "", "", 0xFFFFFFFF):
        raise IDAError(
            f"Failed to add hidden range {format_address(start)}-{format_address(end)}",
            error_type="AddFailed",
        )
    return {
        "start": format_address(start),
        "end": format_address(end),
        "description": description,
    }


def delete_hidden_range(args: dict) -> dict:
    import ida_bytes

    ea = resolve_address(args["address"])

    hr = ida_bytes.get_hidden_range(ea)
    old_start = format_address(hr.start_ea) if hr else None
    old_end = format_address(hr.end_ea) if hr else None
    old_description = (hr.description or "") if hr else ""

    if not ida_bytes.del_hidden_range(ea):
        raise IDAError(
            f"Failed to delete hidden range at {format_address(ea)}", error_type="DeleteFailed"
        )
    return {
        "address": format_address(ea),
        "old_start": old_start,
        "old_end": old_end,
        "old_description": old_description,
    }


def get_hidden_ranges(args: dict) -> dict:
    import ida_bytes

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    def _iter():
        hr = ida_bytes.get_first_hidden_range()
        while hr is not None:
            yield {
                "start": format_address(hr.start_ea),
                "end": format_address(hr.end_ea),
                "description": hr.description or "",
                "size": hr.end_ea - hr.start_ea,
            }
            hr = ida_bytes.get_next_hidden_range(hr.end_ea)

    return paginate_iter(_iter(), offset, limit)


COMMANDS = [
    Command(
        "set-function-flags", set_function_flags, "func_flags",
        "Set or clear function flags (library, thunk, noreturn, hidden).", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("library", "bool", default=None, help="Mark/unmark as library function."),
            Param("thunk", "bool", default=None, help="Mark/unmark as thunk (wrapper) function."),
            Param("noreturn", "bool", default=None, help="Mark/unmark as non-returning."),
            Param("hidden", "bool", default=None,
                  help="Mark/unmark as hidden (collapsed in listing)."),
        ],
    ),
    Command(
        "get-byte-flags", get_byte_flags, "func_flags",
        "Get IDA internal flags for a byte (code/data/head/xref status).",
        params=[
            Param("address", "str", required=True, positional=True, help="Address to query."),
        ],
    ),
    Command(
        "add-hidden-range", add_hidden_range, "func_flags",
        "Create a hidden (collapsed) range in the disassembly listing.", mutates=True,
        params=[
            Param("start_address", "str", required=True, positional=True,
                  help="Start of the range."),
            Param("end_address", "str", required=True, positional=True,
                  help="End of the range (exclusive)."),
            Param("description", "str", default="",
                  help="Optional description shown when collapsed."),
        ],
    ),
    Command(
        "delete-hidden-range", delete_hidden_range, "func_flags",
        "Delete a hidden range that contains the given address.", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Any address within the hidden range."),
        ],
    ),
    Command(
        "get-hidden-ranges", get_hidden_ranges, "func_flags",
        "List all hidden (collapsed) ranges in the database.",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Max results."),
        ],
    ),
]
