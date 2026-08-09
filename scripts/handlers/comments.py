#!/usr/bin/env python3
"""comments — read/set/append disassembly and function comments.

Ported from re_mcp_ida/tools/comments.py. See handlers/functions.py for the
reference template conventions (ida_* imports inside handlers, args: dict in,
JSON-serializable dict out, IDAError on failure, module-level COMMANDS list).
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    resolve_address,
    resolve_function,
)


def get_comment(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    return {
        "address": format_address(ea),
        "comment": idc.get_cmt(ea, False) or "",
        "repeatable_comment": idc.get_cmt(ea, True) or "",
    }


def set_comment(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    comment = args["comment"]
    repeatable = bool(args.get("repeatable", False))

    old_comment = idc.get_cmt(ea, repeatable) or ""
    if not idc.set_cmt(ea, comment, repeatable):
        raise IDAError(
            f"Failed to set comment at {format_address(ea)}", error_type="SetCommentFailed"
        )
    return {
        "address": format_address(ea),
        "old_comment": old_comment,
        "comment": comment,
        "repeatable": repeatable,
    }


def get_function_comment(args: dict) -> dict:
    import ida_funcs

    func = resolve_function(args["address"])
    return {
        "address": format_address(func.start_ea),
        "comment": ida_funcs.get_func_cmt(func, False) or "",
        "repeatable_comment": ida_funcs.get_func_cmt(func, True) or "",
    }


def append_comment(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    comment = args["comment"]
    repeatable = bool(args.get("repeatable", False))
    separator = args.get("separator", "\n")

    existing = idc.get_cmt(ea, repeatable) or ""

    if comment in existing:
        return {
            "address": format_address(ea),
            "old_comment": existing,
            "comment": existing,
            "repeatable": repeatable,
            "appended": False,
        }

    new_comment = f"{existing}{separator}{comment}" if existing else comment
    if not idc.set_cmt(ea, new_comment, repeatable):
        raise IDAError(
            f"Failed to set comment at {format_address(ea)}", error_type="SetCommentFailed"
        )
    return {
        "address": format_address(ea),
        "old_comment": existing,
        "comment": new_comment,
        "repeatable": repeatable,
        "appended": True,
    }


def set_function_comment(args: dict) -> dict:
    import ida_funcs

    func = resolve_function(args["address"])
    comment = args["comment"]
    repeatable = bool(args.get("repeatable", True))

    old_comment = ida_funcs.get_func_cmt(func, repeatable) or ""
    if not ida_funcs.set_func_cmt(func, comment, repeatable):
        raise IDAError(
            f"Failed to set function comment at {format_address(func.start_ea)}",
            error_type="SetCommentFailed",
        )
    return {
        "address": format_address(func.start_ea),
        "old_comment": old_comment,
        "comment": comment,
        "repeatable": repeatable,
    }


COMMANDS = [
    Command(
        "get-comment", get_comment, "comments",
        "Read both disassembly comments (regular + repeatable) at ONE address.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or symbol name.")],
    ),
    Command(
        "set-comment", set_comment, "comments",
        "Set a disassembly-view comment at an instruction or data address.",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or symbol name."),
            Param("comment", "str", required=True, positional=True,
                  help="Comment text to set. Empty string deletes."),
            Param("repeatable", "bool", default=False,
                  help="Set as repeatable (propagates to xref sites)."),
        ],
        aliases=["set_comment"],
    ),
    Command(
        "get-function-comment", get_function_comment, "comments",
        "Read the function-header comment (shown above the prototype).",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
    Command(
        "append-comment", append_comment, "comments",
        "Append to an existing disassembly comment without overwriting.",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or symbol name."),
            Param("comment", "str", required=True, positional=True,
                  help="Comment text to append."),
            Param("repeatable", "bool", default=False,
                  help="Append to the repeatable comment."),
            Param("separator", "str", default="\n",
                  help="Separator between existing and new text."),
        ],
    ),
    Command(
        "set-function-comment", set_function_comment, "comments",
        "Set the function-header comment (shown above the prototype).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("comment", "str", required=True, positional=True,
                  help="Comment text to set. Empty string deletes."),
            Param("repeatable", "bool", default=True,
                  help="Show at call sites too (default True)."),
        ],
    ),
]
