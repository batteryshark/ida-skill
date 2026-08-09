#!/usr/bin/env python3
"""functions — listing, querying, decompilation, disassembly, rename, bounds.

Ported from re_mcp_ida/tools/functions.py. This module is the reference
template for all handler modules:

  * All ``ida_*`` imports live INSIDE handler functions (never at module top),
    so the manifest imports cleanly without an IDA runtime.
  * Each handler takes ``args: dict`` and returns a JSON-serializable dict.
  * Failures raise ``IDAError(msg, error_type=...)``.
  * A module-level ``COMMANDS`` list registers each handler with its schema.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    clean_disasm_line,
    compile_filter,
    decompile_at,
    format_address,
    get_func_name,
    paginate_iter,
    resolve_address,
    resolve_function,
)

_VALID_FILTER_TYPES = {"thunk", "library", "noreturn", "user", ""}


def _passes_type_filter(func, filter_type: str) -> bool:
    import ida_funcs

    if not filter_type:
        return True
    if filter_type == "thunk":
        return bool(func.flags & ida_funcs.FUNC_THUNK)
    if filter_type == "library":
        return bool(func.flags & ida_funcs.FUNC_LIB)
    if filter_type == "noreturn":
        return bool(func.flags & ida_funcs.FUNC_NORET)
    if filter_type == "user":
        return not (func.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB))
    return False


def list_functions(args: dict) -> dict:
    import ida_funcs

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))
    filter_type = args.get("filter_type", "") or ""
    if filter_type not in _VALID_FILTER_TYPES:
        raise IDAError(
            f"Invalid filter_type: {filter_type!r}",
            error_type="InvalidArgument",
            valid_types=sorted(_VALID_FILTER_TYPES - {""}),
        )
    pattern = compile_filter(args.get("filter_pattern", "") or args.get("filter", ""))

    def _iter():
        for i in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(i)
            if func is None:
                continue
            if not _passes_type_filter(func, filter_type):
                continue
            name = get_func_name(func.start_ea)
            if pattern and not pattern.search(name):
                continue
            yield {
                "name": name,
                "start": format_address(func.start_ea),
                "end": format_address(func.end_ea),
                "size": func.size(),
            }

    return paginate_iter(_iter(), offset, limit)


def get_function(args: dict) -> dict:
    import ida_funcs
    import idautils

    func = resolve_function(args["address"])
    name = get_func_name(func.start_ea)
    regular_cmt = ida_funcs.get_func_cmt(func, False) or ""
    repeatable_cmt = ida_funcs.get_func_cmt(func, True) or ""
    chunks = list(idautils.Chunks(func.start_ea))
    return {
        "name": name,
        "start": format_address(func.start_ea),
        "end": format_address(func.end_ea),
        "size": func.size(),
        "flags": func.flags,
        "does_return": not (func.flags & ida_funcs.FUNC_NORET),
        "is_library": bool(func.flags & ida_funcs.FUNC_LIB),
        "is_thunk": bool(func.flags & ida_funcs.FUNC_THUNK),
        "comment": regular_cmt,
        "repeatable_comment": repeatable_cmt,
        "chunks": [
            {"start": format_address(s), "end": format_address(e), "size": e - s}
            for s, e in chunks
        ]
        if len(chunks) > 1
        else None,
    }


def decompile_function(args: dict) -> dict:
    import ida_lines

    target = args.get("address") or args.get("name")
    if not target:
        raise IDAError("Provide either address or name", error_type="InvalidArgument")
    cfunc, func = decompile_at(target)
    sv = cfunc.get_pseudocode()
    lines = [ida_lines.tag_remove(sv[i].line) for i in range(sv.size())]
    return {
        "address": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "pseudocode": "\n".join(lines),
    }


def disassemble_function(args: dict) -> dict:
    import idautils

    func = resolve_function(args["address"])
    instructions = [
        {"address": format_address(item_ea), "disasm": clean_disasm_line(item_ea)}
        for item_ea in idautils.FuncItems(func.start_ea)
    ]
    return {
        "address": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "instruction_count": len(instructions),
        "instructions": instructions,
    }


def rename_function(args: dict) -> dict:
    import ida_name

    func = resolve_function(args["address"])
    new_name = args["new_name"]
    old_name = get_func_name(func.start_ea)
    if not ida_name.set_name(func.start_ea, new_name, ida_name.SN_CHECK):
        raise IDAError(f"Failed to rename function to {new_name!r}", error_type="RenameFailed")
    return {
        "address": format_address(func.start_ea),
        "old_name": old_name,
        "new_name": new_name,
    }


def delete_function(args: dict) -> dict:
    import ida_funcs

    func = resolve_function(args["address"])
    start_ea, end_ea = func.start_ea, func.end_ea
    name = get_func_name(start_ea)
    if not ida_funcs.del_func(start_ea):
        raise IDAError(
            f"Failed to delete function {name} at {format_address(start_ea)}",
            error_type="DeleteFailed",
        )
    return {"address": format_address(start_ea), "name": name, "old_end": format_address(end_ea)}


def set_function_bounds(args: dict) -> dict:
    import ida_funcs

    func = resolve_function(args["address"])
    end_ea = resolve_address(args["new_end"])
    old_end = func.end_ea
    if not ida_funcs.set_func_end(func.start_ea, end_ea):
        raise IDAError(
            f"Failed to set function end to {format_address(end_ea)}",
            error_type="SetBoundsFailed",
        )
    return {
        "address": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "old_end": format_address(old_end),
        "end": format_address(end_ea),
    }


COMMANDS = [
    Command(
        "list-functions", list_functions, "functions",
        "List functions with regex/flag filtering and pagination.",
        params=[
            Param("offset", "int", default=0, help="Pagination start index."),
            Param("limit", "int", default=100, help="Max results."),
            Param("filter_pattern", "str", default="", help="Regex over function names."),
            Param("filter_type", "str", default="",
                  help="thunk|library|noreturn|user (empty = all)."),
        ],
        aliases=["functions"],
    ),
    Command(
        "get-function", get_function, "functions",
        "Function metadata: bounds, size, flags, comments, chunks.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
    Command(
        "decompile-function", decompile_function, "functions",
        "Decompile ONE function to Hex-Rays pseudocode.",
        params=[
            Param("address", "str", default="", positional=True,
                  help="Address or symbol of the function."),
            Param("name", "str", default="", help="Function name (alternative to address)."),
        ],
        aliases=["decompile"],
    ),
    Command(
        "disassemble-function", disassemble_function, "functions",
        "Disassemble the entire function containing an address.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
    Command(
        "rename-function", rename_function, "functions",
        "Rename ONE function (propagates through xrefs).", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or current name of the function."),
            Param("new_name", "str", required=True, positional=True, help="New name."),
        ],
    ),
    Command(
        "delete-function", delete_function, "functions",
        "Remove a function definition (code bytes remain).", mutates=True,
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
    Command(
        "set-function-bounds", set_function_bounds, "functions",
        "Change a function's end address (exclusive).", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("new_end", "str", required=True, positional=True,
                  help="New end address (exclusive)."),
        ],
    ),
]
