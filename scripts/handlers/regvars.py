#!/usr/bin/env python3
"""regvars — register variable tools (map physical registers to names).

Ported from re_mcp_ida/tools/regvars.py. All ``ida_*`` imports live inside
handler bodies; each handler takes ``args: dict`` and returns a plain dict.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    get_func_name,
    resolve_address,
    resolve_function,
)


def _regvar_errors() -> dict:
    import ida_frame

    return {
        ida_frame.REGVAR_ERROR_OK: "ok",
        ida_frame.REGVAR_ERROR_ARG: "invalid_argument",
        ida_frame.REGVAR_ERROR_RANGE: "invalid_range",
        ida_frame.REGVAR_ERROR_NAME: "invalid_name",
    }


def _resolve_regvar(function_address, address, register_name):
    """Resolve a register variable by function, address, and register name.

    Returns ``(func, rv)``. Raises :class:`IDAError` on failure.
    """
    import ida_frame

    func = resolve_function(function_address)
    ea = resolve_address(address)
    rv = ida_frame.find_regvar(func, ea, register_name)
    if rv is None:
        raise IDAError(
            f"No register variable for {register_name!r} at {format_address(ea)}",
            error_type="NotFound",
        )
    return func, rv


def add_regvar(args: dict) -> dict:
    import ida_frame

    func = resolve_function(args["function_address"])
    start = resolve_address(args["start_address"])
    end = resolve_address(args["end_address"])
    register_name = args["register_name"]
    user_name = args["user_name"]
    comment = args.get("comment", "") or ""

    rc = ida_frame.add_regvar(func, start, end, register_name, user_name, comment)
    if rc != ida_frame.REGVAR_ERROR_OK:
        raise IDAError(
            f"add_regvar failed: {_regvar_errors().get(rc, f'code {rc}')}",
            error_type="OperationFailed",
        )
    return {
        "function": format_address(func.start_ea),
        "start": format_address(start),
        "end": format_address(end),
        "register_name": register_name,
        "name": user_name,
    }


def delete_regvar(args: dict) -> dict:
    import ida_frame

    func = resolve_function(args["function_address"])
    start = resolve_address(args["start_address"])
    end = resolve_address(args["end_address"])
    register_name = args["register_name"]

    # Read old values before deletion
    rv = ida_frame.find_regvar(func, start, register_name)
    old_name = (rv.user or "") if rv else ""
    old_comment = (rv.cmt or "") if rv else ""

    rc = ida_frame.del_regvar(func, start, end, register_name)
    if rc != ida_frame.REGVAR_ERROR_OK:
        raise IDAError(
            f"del_regvar failed: {_regvar_errors().get(rc, f'code {rc}')}",
            error_type="OperationFailed",
        )
    return {
        "function": format_address(func.start_ea),
        "start": format_address(start),
        "end": format_address(end),
        "register_name": register_name,
        "old_name": old_name,
        "old_comment": old_comment,
    }


def get_regvar(args: dict) -> dict:
    func, rv = _resolve_regvar(
        args["function_address"], args["address"], args["register_name"]
    )
    return {
        "function": format_address(func.start_ea),
        "start": format_address(rv.start_ea),
        "end": format_address(rv.end_ea),
        "register_name": rv.canon,
        "name": rv.user,
        "comment": rv.cmt or "",
    }


def list_regvars(args: dict) -> dict:
    import ida_frame
    import idautils

    func = resolve_function(args["function_address"])

    seen: set = set()
    regvars = []
    for ea in idautils.FuncItems(func.start_ea):
        if not ida_frame.has_regvar(func, ea):
            continue
        rv = ida_frame.find_regvar(func, ea, None)
        if rv is None:
            continue
        key = (rv.start_ea, rv.end_ea, rv.canon)
        if key in seen:
            continue
        seen.add(key)
        regvars.append(
            {
                "start": format_address(rv.start_ea),
                "end": format_address(rv.end_ea),
                "register_name": rv.canon,
                "name": rv.user,
                "comment": rv.cmt or "",
            }
        )

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "count": len(regvars),
        "regvars": regvars,
    }


def rename_regvar(args: dict) -> dict:
    import ida_frame

    func, rv = _resolve_regvar(
        args["function_address"], args["address"], args["register_name"]
    )
    new_name = args["new_name"]
    register_name = args["register_name"]

    old_name = rv.user or ""
    rc = ida_frame.rename_regvar(func, rv, new_name)
    if rc != ida_frame.REGVAR_ERROR_OK:
        raise IDAError(
            f"rename_regvar failed: {_regvar_errors().get(rc, f'code {rc}')}",
            error_type="OperationFailed",
        )
    return {
        "function": format_address(func.start_ea),
        "register_name": register_name,
        "old_name": old_name,
        "name": new_name,
    }


def set_regvar_comment(args: dict) -> dict:
    import ida_frame

    func, rv = _resolve_regvar(
        args["function_address"], args["address"], args["register_name"]
    )
    comment = args["comment"]
    register_name = args["register_name"]

    old_comment = rv.cmt or ""
    rc = ida_frame.set_regvar_cmt(func, rv, comment)
    if rc != ida_frame.REGVAR_ERROR_OK:
        raise IDAError(
            f"set_regvar_cmt failed: {_regvar_errors().get(rc, f'code {rc}')}",
            error_type="OperationFailed",
        )
    return {
        "function": format_address(func.start_ea),
        "register_name": register_name,
        "old_comment": old_comment,
        "comment": comment,
    }


COMMANDS = [
    Command(
        "add-regvar", add_regvar, "regvars",
        "Define a register variable (map a register to a name over a range).",
        mutates=True,
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the containing function."),
            Param("start_address", "str", required=True, positional=True,
                  help="Start of the range where this mapping applies."),
            Param("end_address", "str", required=True, positional=True,
                  help="End of the range (exclusive)."),
            Param("register_name", "str", required=True, positional=True,
                  help="Canonical register name (e.g. 'eax', 'rbx')."),
            Param("user_name", "str", required=True, positional=True,
                  help="Name to display instead of the register."),
            Param("comment", "str", default="", help="Optional comment for this definition."),
        ],
    ),
    Command(
        "delete-regvar", delete_regvar, "regvars",
        "Delete a register variable definition over a range.",
        mutates=True,
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the containing function."),
            Param("start_address", "str", required=True, positional=True,
                  help="Start of the range."),
            Param("end_address", "str", required=True, positional=True,
                  help="End of the range (exclusive)."),
            Param("register_name", "str", required=True, positional=True,
                  help="Canonical register name (e.g. 'eax', 'rbx')."),
        ],
    ),
    Command(
        "get-regvar", get_regvar, "regvars",
        "Get the register variable definition at an address for a register.",
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the containing function."),
            Param("address", "str", required=True, positional=True,
                  help="Address to query."),
            Param("register_name", "str", required=True, positional=True,
                  help="Canonical register name (e.g. 'eax', 'rbx')."),
        ],
    ),
    Command(
        "list-regvars", list_regvars, "regvars",
        "List all register variable definitions in a function.",
        params=[Param("function_address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
    Command(
        "rename-regvar", rename_regvar, "regvars",
        "Rename a regvar alias (register-scoped, per-range).",
        mutates=True,
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the containing function."),
            Param("address", "str", required=True, positional=True,
                  help="Any address within the regvar's range."),
            Param("register_name", "str", required=True, positional=True,
                  help="Canonical register name (e.g. 'eax', 'rbx')."),
            Param("new_name", "str", required=True, positional=True,
                  help="New user-defined name."),
        ],
    ),
    Command(
        "set-regvar-comment", set_regvar_comment, "regvars",
        "Set the comment on a register variable definition.",
        mutates=True,
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the containing function."),
            Param("address", "str", required=True, positional=True,
                  help="Any address within the regvar's range."),
            Param("register_name", "str", required=True, positional=True,
                  help="Canonical register name (e.g. 'eax', 'rbx')."),
            Param("comment", "str", required=True, positional=True, help="New comment text."),
        ],
    ),
]
