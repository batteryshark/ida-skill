#!/usr/bin/env python3
"""load_data — load additional binaries / bytes into the database.

Ported from re_mcp_ida/tools/load_data.py. Follows the handler template in
handlers/functions.py: all ``ida_*`` imports live inside handler bodies, each
handler takes ``args: dict`` and returns a JSON-serializable dict, failures
raise ``IDAError(msg, error_type=...)``, and a module-level ``COMMANDS`` list
registers each handler with its schema.
"""
from __future__ import annotations

import os

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    resolve_address,
)

_MAX_HEX_LEN = 2 * 1024 * 1024  # 1 MB of data = 2M hex chars


def _validate_and_open(file_path: str, file_offset: int):
    """Validate a file path and offset, then open it as an IDA linput.

    Returns ``(resolved_path, file_size, linput)``. The caller **must** close
    the linput via ``ida_diskio.close_linput(li)`` when done.
    """
    import ida_diskio

    path = os.path.expanduser(file_path)
    if not os.path.isfile(path):
        raise IDAError(f"File not found: {path}", error_type="FileNotFoundError")

    file_size = os.path.getsize(path)
    if file_offset >= file_size:
        raise IDAError("File offset beyond file size", error_type="InvalidArgument")

    li = ida_diskio.open_linput(path, False)
    if li is None:
        raise IDAError(f"Failed to open file: {path}", error_type="OpenFailed")

    return path, file_size, li


def load_additional_binary(args: dict) -> dict:
    import ida_diskio
    import ida_loader

    ea = resolve_address(args["load_address"])
    file_path = args["file_path"]
    file_offset = int(args.get("file_offset", 0))
    size = int(args.get("size", 0))

    path, _, li = _validate_and_open(file_path, file_offset)

    basepara = ea >> 4
    binoff = ea & 0xF

    try:
        result = ida_loader.load_binary_file(path, li, 0, file_offset, basepara, binoff, size)
    finally:
        ida_diskio.close_linput(li)

    if not result:
        raise IDAError("Failed to load binary file into database", error_type="LoadFailed")

    return {
        "file": path,
        "load_address": format_address(ea),
        "file_offset": file_offset,
        "size": size,
    }


def load_bytes_from_file(args: dict) -> dict:
    import ida_bytes
    import ida_diskio
    import ida_loader

    ea = resolve_address(args["target_address"])
    file_path = args["file_path"]
    file_offset = int(args.get("file_offset", 0))
    size = int(args.get("size", 0))

    path, file_size, li = _validate_and_open(file_path, file_offset)

    try:
        if size == 0:
            size = file_size - file_offset

        # Read old bytes before overwriting (cap preview at 256 bytes)
        preview_size = min(size, 256)
        old_bytes_data = ida_bytes.get_bytes(ea, preview_size)

        result = ida_loader.file2base(li, file_offset, ea, ea + size, 1)
    finally:
        ida_diskio.close_linput(li)

    if not result:
        raise IDAError("Failed to load bytes into database", error_type="LoadFailed")

    return {
        "file": path,
        "target_address": format_address(ea),
        "file_offset": file_offset,
        "size": size,
        "old_bytes": old_bytes_data.hex() if old_bytes_data else "",
    }


def load_bytes_from_memory(args: dict) -> dict:
    import ida_bytes
    import ida_loader

    ea = resolve_address(args["target_address"])
    data = args["data"]

    data = data.strip().replace(" ", "")
    if len(data) > _MAX_HEX_LEN:
        raise IDAError(
            f"Hex data too large ({len(data)} chars, max {_MAX_HEX_LEN})",
            error_type="InvalidArgument",
        )
    try:
        raw = bytes.fromhex(data)
    except ValueError:
        raise IDAError("Invalid hex data", error_type="InvalidArgument") from None

    old_bytes_data = ida_bytes.get_bytes(ea, len(raw))

    result = ida_loader.mem2base(raw, ea, -1)
    if result != 1:
        raise IDAError("Failed to load bytes into database", error_type="LoadFailed")

    return {
        "target_address": format_address(ea),
        "size": len(raw),
        "old_bytes": old_bytes_data.hex() if old_bytes_data else "",
    }


COMMANDS = [
    Command(
        "load-additional-binary", load_additional_binary, "load_data",
        "Load a binary file into a new auto-created segment (firmware, overlays, etc.).",
        mutates=True,
        params=[
            Param("file_path", "str", required=True, positional=True,
                  help="Absolute path to the binary file to load."),
            Param("load_address", "str", required=True, positional=True,
                  help="Address where the file is loaded (a new segment is created)."),
            Param("file_offset", "int", default=0,
                  help="Offset within the file to start reading from."),
            Param("size", "int", default=0,
                  help="Number of bytes to load (0 = rest of file from offset)."),
        ],
    ),
    Command(
        "load-bytes-from-file", load_bytes_from_file, "load_data",
        "Overwrite bytes in an existing segment from a file (segment must already exist).",
        mutates=True,
        params=[
            Param("file_path", "str", required=True, positional=True,
                  help="Absolute path to the file to load bytes from."),
            Param("target_address", "str", required=True, positional=True,
                  help="Address in the database to load bytes to."),
            Param("file_offset", "int", default=0,
                  help="Offset within the file to start reading from."),
            Param("size", "int", default=0,
                  help="Number of bytes to load (0 = rest of file from offset)."),
        ],
    ),
    Command(
        "load-bytes-from-memory", load_bytes_from_memory, "load_data",
        "Write hex-encoded bytes directly into an existing segment.",
        mutates=True,
        params=[
            Param("target_address", "str", required=True, positional=True,
                  help="Address in the database to load bytes to."),
            Param("data", "hex", required=True,
                  help='Hex-encoded bytes to load (e.g. "90909090" for NOPs).'),
        ],
    ),
]
