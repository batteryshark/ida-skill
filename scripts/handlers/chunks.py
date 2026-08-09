#!/usr/bin/env python3
"""chunks — function chunk/tail management.

Ported from re_mcp_ida/tools/chunks.py into the standalone idalib worker's
handler format: each handler takes ``args: dict`` and returns a
JSON-serializable dict; all ``ida_*`` imports live inside function bodies.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    resolve_address,
    resolve_function,
)


def list_function_chunks(args: dict) -> dict:
    import idautils

    func = resolve_function(args["address"])

    chunks = []
    for start, end in idautils.Chunks(func.start_ea):
        chunks.append(
            {
                "start": format_address(start),
                "end": format_address(end),
                "size": end - start,
            }
        )

    return {
        "function": format_address(func.start_ea),
        "chunk_count": len(chunks),
        "chunks": chunks,
    }


def append_function_tail(args: dict) -> dict:
    import ida_funcs

    func = resolve_function(args["function_address"])
    ea1 = resolve_address(args["start"])
    ea2 = resolve_address(args["end"])

    success = ida_funcs.append_func_tail(func, ea1, ea2)
    if not success:
        raise IDAError(
            f"Failed to append tail [{format_address(ea1)}, {format_address(ea2)}) "
            f"to function at {format_address(func.start_ea)}",
            error_type="AppendFailed",
        )

    return {
        "function": format_address(func.start_ea),
        "tail_start": format_address(ea1),
        "tail_end": format_address(ea2),
    }


def remove_function_tail(args: dict) -> dict:
    import ida_funcs

    func = resolve_function(args["function_address"])
    tail_ea = resolve_address(args["tail_address"])

    success = ida_funcs.remove_func_tail(func, tail_ea)
    if not success:
        raise IDAError(
            f"Failed to remove tail at {format_address(tail_ea)} "
            f"from function at {format_address(func.start_ea)}",
            error_type="RemoveFailed",
        )

    return {
        "function": format_address(func.start_ea),
        "removed_tail_at": format_address(tail_ea),
    }


def set_tail_owner(args: dict) -> dict:
    import ida_funcs

    tail_ea = resolve_address(args["tail_address"])
    owner_ea = resolve_address(args["new_owner_address"])

    fnt = ida_funcs.get_fchunk(tail_ea)
    if fnt is None:
        raise IDAError(f"No function chunk at {format_address(tail_ea)}", error_type="NotFound")

    old_owner_func = ida_funcs.get_func(tail_ea)
    old_owner = format_address(old_owner_func.start_ea) if old_owner_func else None
    success = ida_funcs.set_tail_owner(fnt, owner_ea)
    if not success:
        raise IDAError(
            f"Failed to set tail owner at {format_address(tail_ea)} "
            f"to {format_address(owner_ea)}",
            error_type="SetOwnerFailed",
        )

    return {
        "tail_address": format_address(tail_ea),
        "old_owner": old_owner,
        "new_owner": format_address(owner_ea),
    }


COMMANDS = [
    Command(
        "list-function-chunks", list_function_chunks, "chunks",
        "List all chunks (contiguous regions) of a function.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or symbol name of the function."),
        ],
    ),
    Command(
        "append-function-tail", append_function_tail, "chunks",
        "Append a tail (non-contiguous chunk) to a function.", mutates=True,
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the owning function."),
            Param("start", "str", required=True, positional=True,
                  help="Start address of the tail region."),
            Param("end", "str", required=True, positional=True,
                  help="End address of the tail region (exclusive)."),
        ],
    ),
    Command(
        "remove-function-tail", remove_function_tail, "chunks",
        "Remove a tail (non-contiguous chunk) from a function.", mutates=True,
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the owning function."),
            Param("tail_address", "str", required=True, positional=True,
                  help="Any address within the tail chunk to remove."),
        ],
    ),
    Command(
        "set-tail-owner", set_tail_owner, "chunks",
        "Reassign a function tail chunk to a different owning function.", mutates=True,
        params=[
            Param("tail_address", "str", required=True, positional=True,
                  help="Any address within the tail chunk."),
            Param("new_owner_address", "str", required=True, positional=True,
                  help="Address or name of the new owning function."),
        ],
    ),
]
