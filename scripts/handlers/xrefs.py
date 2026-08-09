#!/usr/bin/env python3
"""xrefs — cross-reference analysis (to/from) and call-graph traversal.

Ported from re_mcp_ida/tools/xrefs.py. All ``ida_*`` imports live inside the
handler bodies; each handler takes ``args: dict`` and returns a
JSON-serializable dict.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    format_address,
    get_func_name,
    paginate_iter,
    resolve_address,
    resolve_function,
    xref_type_name,
)


def get_xrefs_to(args: dict) -> dict:
    import idautils

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))
    ea = resolve_address(args["address"])

    result = paginate_iter(
        (
            {
                "from": format_address(xref.frm),
                "from_name": get_func_name(xref.frm),
                "type": xref_type_name(xref.type),
                "is_code": xref.iscode,
            }
            for xref in idautils.XrefsTo(ea)
        ),
        offset,
        limit,
    )
    return {"address": format_address(ea), **result}


def get_xrefs_from(args: dict) -> dict:
    import idautils

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))
    ea = resolve_address(args["address"])

    result = paginate_iter(
        (
            {
                "to": format_address(xref.to),
                "to_name": get_func_name(xref.to),
                "type": xref_type_name(xref.type),
                "is_code": xref.iscode,
            }
            for xref in idautils.XrefsFrom(ea)
        ),
        offset,
        limit,
    )
    return {"address": format_address(ea), **result}


def get_call_graph(args: dict) -> dict:
    import ida_funcs
    import idautils

    func = resolve_function(args["address"])
    depth = int(args.get("depth", 1))

    def _get_callees(func_ea: int, current_depth: int, visited: set | None = None) -> list:
        if current_depth <= 0:
            return []
        if visited is None:
            visited = set()
        if func_ea in visited:
            return []
        visited.add(func_ea)
        callees = set()
        f = ida_funcs.get_func(func_ea)
        if f is None:
            return []
        for item_ea in idautils.FuncItems(f.start_ea):
            for ref in idautils.CodeRefsFrom(item_ea, False):
                callee_func = ida_funcs.get_func(ref)
                if callee_func and callee_func.start_ea != func_ea:
                    callees.add(callee_func.start_ea)

        result = []
        for callee_ea in sorted(callees):
            entry = {
                "address": format_address(callee_ea),
                "name": get_func_name(callee_ea),
            }
            if current_depth > 1:
                entry["callees"] = _get_callees(callee_ea, current_depth - 1, visited)
            result.append(entry)
        return result

    def _get_callers(func_ea: int, current_depth: int, visited: set | None = None) -> list:
        if current_depth <= 0:
            return []
        if visited is None:
            visited = set()
        if func_ea in visited:
            return []
        visited.add(func_ea)
        callers = set()
        for ref in idautils.CodeRefsTo(func_ea, False):
            caller_func = ida_funcs.get_func(ref)
            if caller_func and caller_func.start_ea != func_ea:
                callers.add(caller_func.start_ea)

        result = []
        for caller_ea in sorted(callers):
            entry = {
                "address": format_address(caller_ea),
                "name": get_func_name(caller_ea),
            }
            if current_depth > 1:
                entry["callers"] = _get_callers(caller_ea, current_depth - 1, visited)
            result.append(entry)
        return result

    return {
        "function": {
            "address": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
        },
        "callers": _get_callers(func.start_ea, depth),
        "callees": _get_callees(func.start_ea, depth),
    }


COMMANDS = [
    Command(
        "get-xrefs-to", get_xrefs_to, "xrefs",
        "List all cross-references pointing TO an address.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Target address or symbol name."),
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Maximum number of results."),
        ],
        aliases=["xrefs-to"],
    ),
    Command(
        "get-xrefs-from", get_xrefs_from, "xrefs",
        "List all cross-references originating FROM an address.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Source address or symbol name."),
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Maximum number of results."),
        ],
        aliases=["xrefs-from"],
    ),
    Command(
        "get-call-graph", get_call_graph, "xrefs",
        "Get the call graph for a function (callers and callees).",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("depth", "int", default=1,
                  help="How many levels deep to traverse (1-3)."),
        ],
        aliases=["call-graph"],
    ),
]
