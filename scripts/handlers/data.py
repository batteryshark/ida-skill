#!/usr/bin/env python3
"""data — raw byte reads, segment listing, and pointer-table reads.

Ported from re_mcp_ida/tools/data.py. All ``ida_*`` imports live inside the
handler bodies; each handler takes ``args: dict`` and returns a
JSON-serializable dict.
"""
from __future__ import annotations

import struct

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    decode_string,
    format_address,
    format_permissions,
    is_bad_addr,
    paginate,
    resolve_address,
    segment_bitness,
)


def read_bytes(args: dict) -> dict:
    import ida_bytes

    ea = resolve_address(args["address"])
    size = int(args.get("size", 16))

    size = max(1, min(size, 4096))
    data = ida_bytes.get_bytes(ea, size)
    if data is None:
        raise IDAError(
            f"Cannot read {size} bytes at {format_address(ea)}", error_type="ReadError"
        )

    # Format as hex dump with ASCII
    hex_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append(f"{format_address(ea + i)}  {hex_part:<48s}  {ascii_part}")

    return {
        "address": format_address(ea),
        "size": len(data),
        "hex": data.hex(),
        "dump": "\n".join(hex_lines),
    }


def get_segments(args: dict) -> dict:
    import ida_segment

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 50))

    segments = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if seg is None:
            continue
        segments.append(
            {
                "name": ida_segment.get_segm_name(seg),
                "start": format_address(seg.start_ea),
                "end": format_address(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "class": ida_segment.get_segm_class(seg),
                "permissions": format_permissions(seg.perm),
                "bitness": segment_bitness(seg.bitness),
            }
        )

    return paginate(segments, offset, limit)


def read_pointer_table(args: dict) -> dict:
    import ida_bytes
    import ida_ida
    import ida_nalt
    import ida_name

    ea = resolve_address(args["address"])
    count = int(args["count"])
    dereference = bool(args.get("dereference", True))

    ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    fmt = "<Q" if ptr_size == 8 else "<I"
    total_bytes = count * ptr_size

    data = ida_bytes.get_bytes(ea, total_bytes)
    if data is None or len(data) < total_bytes:
        raise IDAError(
            f"Cannot read {total_bytes} bytes at {format_address(ea)}",
            error_type="ReadError",
        )

    entries: list[dict] = []
    for i in range(count):
        offset = i * ptr_size
        (ptr_val,) = struct.unpack_from(fmt, data, offset)
        entry = {
            "index": i,
            "address": format_address(ea + offset),
            "value": format_address(ptr_val),
            "target_name": "",
            "target_string": "",
        }

        if dereference and not is_bad_addr(ptr_val):
            name = ida_name.get_name(ptr_val)
            if name:
                entry["target_name"] = name
            # Try to read a string at the target
            flags = ida_bytes.get_flags(ptr_val)
            if ida_bytes.is_strlit(flags):
                ti = ida_nalt.opinfo_t()
                if ida_bytes.get_opinfo(ti, ptr_val, 0, flags):
                    str_type = ti.strtype
                else:
                    str_type = ida_nalt.STRTYPE_C
                length = ida_bytes.get_max_strlit_length(
                    ptr_val, str_type, ida_bytes.ALOPT_IGNCLT
                )
                if length > 0:
                    s = decode_string(ptr_val, length, str_type)
                    if s:
                        entry["target_string"] = s

        entries.append(entry)

    return {
        "entries": entries,
        "pointer_size": ptr_size,
        "base_address": format_address(ea),
    }


COMMANDS = [
    Command(
        "read-bytes", read_bytes, "data",
        "Read raw bytes from the database at a given address.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address to read from (hex string or symbol name)."),
            Param("size", "int", default=16, help="Number of bytes to read (max 4096)."),
        ],
    ),
    Command(
        "get-segments", get_segments, "data",
        "List all segments (memory layout, permissions, address ranges).",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=50, help="Maximum number of results."),
        ],
        aliases=["segments"],
    ),
    Command(
        "read-pointer-table", read_pointer_table, "data",
        "Read an array of pointers (vtable, dispatch table) with optional dereference.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Start address of the pointer table."),
            Param("count", "int", required=True,
                  help="Number of pointers to read (max 4096)."),
            Param("dereference", "bool", default=True,
                  help="Resolve names and strings at target addresses."),
        ],
    ),
]
