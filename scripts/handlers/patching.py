#!/usr/bin/env python3
"""patching — patch bytes, create functions/code, undefine items.

Ported from re_mcp_ida/tools/patching.py. Follows the handler template in
handlers/functions.py: all ``ida_*`` imports live inside handler bodies, each
handler takes ``args: dict`` and returns a JSON-serializable dict, failures
raise ``IDAError(msg, error_type=...)``, and a module-level ``COMMANDS`` list
registers each handler with its schema.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    get_func_name,
    get_old_item_info,
    resolve_address,
)

_MAX_PATCH_HEX_LEN = 2 * 1024 * 1024  # 1 MB of data = 2M hex chars


def patch_bytes(args: dict) -> dict:
    import ida_bytes
    import ida_undo

    ea = resolve_address(args["address"])
    hex_bytes = args["hex_bytes"]

    cleaned = hex_bytes.replace(" ", "")
    if not cleaned:
        raise IDAError("Empty hex string", error_type="InvalidArgument")
    if len(cleaned) > _MAX_PATCH_HEX_LEN:
        raise IDAError(
            f"Patch data too large ({len(cleaned)} hex chars, max {_MAX_PATCH_HEX_LEN})",
            error_type="InvalidArgument",
        )
    try:
        new_bytes = bytes.fromhex(cleaned)
    except ValueError:
        raise IDAError(
            f"Invalid hex string: {hex_bytes!r}", error_type="InvalidArgument"
        ) from None

    # Read old bytes for the response
    old_bytes = ida_bytes.get_bytes(ea, len(new_bytes))

    # Create an undo point so the patch can be reverted
    ida_undo.create_undo_point("patch_bytes", "patch_bytes")

    # Patch atomically
    ida_bytes.patch_bytes(ea, new_bytes)

    return {
        "address": format_address(ea),
        "size": len(new_bytes),
        "old_bytes": old_bytes.hex() if old_bytes else "",
        "new_bytes": new_bytes.hex(),
    }


def create_function(args: dict) -> dict:
    import ida_funcs

    ea = resolve_address(args["address"])

    success = ida_funcs.add_func(ea)
    if not success:
        raise IDAError(
            f"Failed to create function at {format_address(ea)}", error_type="CreateFailed"
        )

    func = ida_funcs.get_func(ea)
    name = get_func_name(ea)
    return {
        "address": format_address(ea),
        "name": name,
        "end": format_address(func.end_ea) if func else "",
        "size": func.size() if func else 0,
    }


def make_code(args: dict) -> dict:
    import ida_ua

    ea = resolve_address(args["address"])

    old_item_type, old_item_size = get_old_item_info(ea)

    length = ida_ua.create_insn(ea)
    if length == 0:
        raise IDAError(
            f"Failed to create instruction at {format_address(ea)}", error_type="CreateFailed"
        )

    return {
        "address": format_address(ea),
        "old_item_type": old_item_type,
        "old_item_size": old_item_size,
        "size": length,
    }


def undefine(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    size = int(args.get("size", 1))

    old_item_type, old_item_size = get_old_item_info(ea)

    success = idc.del_items(ea, 0, size)
    if not success:
        raise IDAError(
            f"Failed to undefine {size} bytes at {format_address(ea)}",
            error_type="UndefineFailed",
        )
    return {
        "address": format_address(ea),
        "old_item_type": old_item_type,
        "old_item_size": old_item_size,
        "size": size,
    }


COMMANDS = [
    Command(
        "patch-bytes", patch_bytes, "patching",
        "Overwrite raw bytes in the IDB with a hex string (atomic, destructive).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address to patch."),
            Param("hex_bytes", "hex", required=True,
                  help='Hex bytes to write (e.g. "90 90 90" or "909090").'),
        ],
    ),
    Command(
        "create-function", create_function, "patching",
        "Define a new function at an address (IDA auto-detects bounds).",
        mutates=True,
        params=[Param("address", "str", required=True, positional=True,
                      help="Start address for the new function.")],
    ),
    Command(
        "make-code", make_code, "patching",
        "Force bytes to be disassembled as code (single instruction, no function).",
        mutates=True,
        params=[Param("address", "str", required=True, positional=True,
                      help="Address to convert to code.")],
    ),
    Command(
        "undefine", undefine, "patching",
        "Revert code/data definitions back to raw undefined bytes (byte values unchanged).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address to undefine."),
            Param("size", "int", default=1, help="Number of bytes to undefine."),
        ],
    ),
]
