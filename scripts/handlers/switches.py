#!/usr/bin/env python3
"""switches — switch/jump table analysis tools.

Ported from re_mcp_ida/tools/switches.py.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    get_func_name,
    is_bad_addr,
    paginate_iter,
    resolve_address,
)


def get_switch_info(args: dict) -> dict:
    import ida_nalt
    import idaapi

    ea = resolve_address(args["address"])

    si = ida_nalt.get_switch_info(ea)
    if si is None:
        raise IDAError(f"No switch info at {format_address(ea)}", error_type="NotFound")

    cases = []
    results = idaapi.calc_switch_cases(ea, si)
    if results:
        for i in range(len(results.cases)):
            cur_case = results.cases[i]
            vals = [cur_case[j] for j in range(len(cur_case))]
            target = results.targets[i] if i < len(results.targets) else None
            if vals:
                cases.append(
                    {
                        "case_values": vals,
                        "target": format_address(target) if target is not None else None,
                    }
                )

    return {
        "address": format_address(ea),
        "jump_table": format_address(si.jumps),
        "element_size": si.get_jtable_element_size(),
        "num_cases": si.get_jtable_size(),
        "default_target": format_address(si.defjump) if not is_bad_addr(si.defjump) else None,
        "start_value": si.lowcase,
        "cases": cases,
    }


def list_switches(args: dict) -> dict:
    import ida_funcs
    import ida_nalt
    import idautils

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    def _iter():
        for i in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(i)
            if func is None:
                continue
            for head in idautils.FuncItems(func.start_ea):
                si = ida_nalt.get_switch_info(head)
                if si is not None:
                    yield {
                        "address": format_address(head),
                        "function": get_func_name(func.start_ea),
                        "num_cases": si.get_jtable_size(),
                    }

    return paginate_iter(_iter(), offset, limit)


COMMANDS = [
    Command(
        "get-switch-info", get_switch_info, "switches",
        "Get switch/jump table structure at an indirect jump (targets, cases, default).",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address of the switch/indirect jump instruction.")],
    ),
    Command(
        "list-switches", list_switches, "switches",
        "Find all switch/jump tables in the database (may be slow on large binaries).",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Maximum number of results."),
        ],
    ),
]
