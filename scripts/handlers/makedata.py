#!/usr/bin/env python3
"""makedata — define primitive data, strings, and arrays at addresses.

Ported from re_mcp_ida/tools/makedata.py. Follows the handler template in
handlers/functions.py: all ``ida_*`` imports live inside handler bodies, each
handler takes ``args: dict`` and returns a JSON-serializable dict, failures
raise ``IDAError(msg, error_type=...)``, and a module-level ``COMMANDS`` list
registers each handler with its schema.

The ``ida_bytes.*_flag`` lookups that were module-level constants in the source
are lazy helpers here so the manifest imports without an IDA runtime.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    get_old_item_info,
    resolve_address,
)

_MAX_COUNT = 1_000_000


def _data_type_map() -> dict:
    import ida_bytes

    return {
        "byte": (ida_bytes.byte_flag, 1),
        "word": (ida_bytes.word_flag, 2),
        "dword": (ida_bytes.dword_flag, 4),
        "qword": (ida_bytes.qword_flag, 8),
        "float": (ida_bytes.float_flag, 4),
        "double": (ida_bytes.double_flag, 8),
    }


def _size_to_flag() -> dict:
    import ida_bytes

    return {
        1: ida_bytes.byte_flag,
        2: ida_bytes.word_flag,
        4: ida_bytes.dword_flag,
        8: ida_bytes.qword_flag,
    }


def _create_typed_data(ea: int, flag_fn, elem_size: int, count: int) -> bool:
    """Create a data item (or array) using the correct create_data signature.

    ``create_data(ea, flags, total_size, tid)`` — *tid* is a type ID
    (e.g. structure ID); for basic types it must be BADADDR. *count* must
    be >= 1.
    """
    import ida_bytes
    import ida_idaapi

    total = elem_size * count
    return ida_bytes.create_data(ea, flag_fn(), total, ida_idaapi.BADADDR)


def _validate_count(count: int) -> None:
    if count < 1:
        raise IDAError(f"Count must be >= 1, got {count}", error_type="InvalidArgument")
    if count > _MAX_COUNT:
        raise IDAError(f"Count too large ({count}), max {_MAX_COUNT}", error_type="InvalidArgument")


def _make_data(ea: int, type_name: str, flag_fn, elem_size: int, count: int) -> dict:
    """Shared implementation for the make_data tool."""
    _validate_count(count)
    old_item_type, old_item_size = get_old_item_info(ea)
    if not _create_typed_data(ea, flag_fn, elem_size, count):
        raise IDAError(
            f"Failed to define {type_name}(s) at {format_address(ea)}",
            error_type="MakeDataFailed",
        )
    return {
        "address": format_address(ea),
        "old_item_type": old_item_type,
        "old_item_size": old_item_size,
        "size": elem_size * count,
    }


def make_data(args: dict) -> dict:
    data_type = args["data_type"]
    count = int(args.get("count", 1))

    type_map = _data_type_map()
    entry = type_map.get(data_type)
    if entry is None:
        raise IDAError(
            f"Invalid data type: {data_type!r}",
            error_type="InvalidArgument",
            valid_types=list(type_map),
        )
    flag_fn, elem_size = entry
    return _make_data(resolve_address(args["address"]), data_type, flag_fn, elem_size, count)


def make_string(args: dict) -> dict:
    import ida_bytes
    import ida_nalt

    ea = resolve_address(args["address"])
    length = int(args.get("length", 0))
    string_type = args.get("string_type", "c")

    type_map = {
        "c": ida_nalt.STRTYPE_C,
        "utf16": ida_nalt.STRTYPE_C_16,
        "utf32": ida_nalt.STRTYPE_C_32,
    }
    strtype = type_map.get(string_type)
    if strtype is None:
        raise IDAError(
            f"Invalid string type: {string_type!r}",
            error_type="InvalidArgument",
            valid_types=list(type_map),
        )

    old_item_type, old_item_size = get_old_item_info(ea)
    if not ida_bytes.create_strlit(ea, length, strtype):
        raise IDAError(
            f"Failed to define string at {format_address(ea)}", error_type="MakeDataFailed"
        )
    return {
        "address": format_address(ea),
        "old_item_type": old_item_type,
        "old_item_size": old_item_size,
        "length": length,
        "string_type": string_type,
    }


def make_array(args: dict) -> dict:
    ea = resolve_address(args["address"])
    element_size = int(args["element_size"])
    count = int(args["count"])
    _validate_count(count)

    flag_fn = _size_to_flag().get(element_size)
    if flag_fn is None:
        raise IDAError(
            f"Invalid element size: {element_size}. Must be 1, 2, 4, or 8.",
            error_type="InvalidArgument",
        )

    old_item_type, old_item_size = get_old_item_info(ea)
    if not _create_typed_data(ea, flag_fn, element_size, count):
        raise IDAError(
            f"Failed to create array at {format_address(ea)}", error_type="MakeDataFailed"
        )
    return {
        "address": format_address(ea),
        "old_item_type": old_item_type,
        "old_item_size": old_item_size,
        "element_size": element_size,
        "count": count,
        "total_size": element_size * count,
    }


COMMANDS = [
    Command(
        "make-data", make_data, "makedata",
        "Mark bytes as a primitive data type (byte/word/dword/qword/float/double).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address to define."),
            Param("data_type", "str", required=True,
                  help="byte|word|dword|qword|float|double."),
            Param("count", "int", default=1, help="Number of elements (>1 creates an array)."),
        ],
    ),
    Command(
        "make-string", make_string, "makedata",
        "Mark bytes as a C/Pascal/Unicode string (auto-sized if length omitted).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address of the string."),
            Param("length", "int", default=0,
                  help="String length in bytes (0 = auto null-terminated)."),
            Param("string_type", "str", default="c",
                  help='Encoding: "c" (ASCII), "utf16", "utf32".'),
        ],
    ),
    Command(
        "make-array", make_array, "makedata",
        "Mark a contiguous run of bytes as an array of an already-defined typed element.",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address of the array start."),
            Param("element_size", "int", required=True,
                  help="Size of each element in bytes (1, 2, 4, or 8)."),
            Param("count", "int", required=True, help="Number of elements in the array."),
        ],
    ),
]
