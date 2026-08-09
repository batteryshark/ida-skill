#!/usr/bin/env python3
"""nalt — source line numbers and per-address analysis flags.

Ported from re_mcp_ida/tools/nalt.py. See handlers/functions.py for the
reference template conventions.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    is_bad_addr,
    resolve_address,
)


def _valid_linnum(linnum: int) -> int | None:
    """Return linnum if it's a real source line number, else None."""
    return linnum if not is_bad_addr(linnum) and linnum >= 0 else None


def get_source_line_number(args: dict) -> dict:
    import ida_nalt

    ea = resolve_address(args["address"])
    linnum = ida_nalt.get_source_linnum(ea)
    return {"address": format_address(ea), "line_number": _valid_linnum(linnum)}


def set_source_line_number(args: dict) -> dict:
    import ida_nalt

    ea = resolve_address(args["address"])
    line_number = int(args["line_number"])

    if line_number < 0:
        raise IDAError("line_number must be non-negative", error_type="InvalidArgument")

    old_linnum = ida_nalt.get_source_linnum(ea)
    ida_nalt.set_source_linnum(ea, line_number)
    return {
        "address": format_address(ea),
        "old_line_number": _valid_linnum(old_linnum),
        "line_number": line_number,
    }


def get_address_info(args: dict) -> dict:
    import ida_nalt

    ea = resolve_address(args["address"])
    flags = ida_nalt.get_aflags(ea)
    linnum = ida_nalt.get_source_linnum(ea)

    return {
        "address": format_address(ea),
        "no_return": bool(ida_nalt.is_noret(ea)),
        "is_library_item": bool(ida_nalt.is_libitem(ea)),
        "is_hidden": bool(ida_nalt.is_hidden_item(ea)),
        "type_guessed_by_ida": bool(ida_nalt.is_type_guessed_by_ida(ea)),
        "type_guessed_by_hexrays": bool(ida_nalt.is_type_guessed_by_hexrays(ea)),
        "type_determined_by_hexrays": bool(ida_nalt.is_type_determined_by_hexrays(ea)),
        "func_guessed_by_hexrays": bool(ida_nalt.is_func_guessed_by_hexrays(ea)),
        "fixed_sp_delta": bool(ida_nalt.is_fixed_spd(ea)),
        "source_line_number": _valid_linnum(linnum),
        "raw_aflags": flags,
    }


def set_library_item(args: dict) -> dict:
    import ida_nalt

    ea = resolve_address(args["address"])
    is_library = bool(args["is_library"])

    old_value = bool(ida_nalt.is_libitem(ea))
    if is_library:
        ida_nalt.set_libitem(ea)
    else:
        ida_nalt.clr_libitem(ea)

    return {
        "address": format_address(ea),
        "old_is_library_item": old_value,
        "is_library_item": is_library,
    }


COMMANDS = [
    Command(
        "get-source-line-number", get_source_line_number, "nalt",
        "Get the DWARF/debug source line number at an address (null if unmapped).",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address to query.")],
    ),
    Command(
        "set-source-line-number", set_source_line_number, "nalt",
        "Set the source file line number for an address.",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address to annotate."),
            Param("line_number", "int", required=True, positional=True,
                  help="Source line number (1-based)."),
        ],
    ),
    Command(
        "get-address-info", get_address_info, "nalt",
        "Get IDA's analysis flags and metadata for an address.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address to query.")],
    ),
    Command(
        "set-library-item", set_library_item, "nalt",
        "Mark or unmark an address as a library item.",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address to mark."),
            Param("is_library", "bool", required=True,
                  help="True to mark as library item, False to clear."),
        ],
    ),
]
