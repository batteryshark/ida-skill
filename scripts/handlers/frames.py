#!/usr/bin/env python3
"""frames — stack frame and local variable analysis.

Ported from re_mcp_ida/tools/frames.py.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    decompile_at,
    format_address,
    get_func_name,
    resolve_function,
)


def get_stack_frame(args: dict) -> dict:
    import ida_typeinf
    import idc

    func = resolve_function(args["address"])

    frame_tif = ida_typeinf.tinfo_t()
    if not frame_tif.get_func_frame(func):
        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "frame": None,
        }

    udt = ida_typeinf.udt_type_data_t()
    frame_tif.get_udt_details(udt)

    members = []
    for udm in udt:
        if udm.is_gap():
            continue
        byte_offset = udm.offset // 8
        members.append(
            {
                "offset": byte_offset,
                "name": udm.name or f"var_{byte_offset:X}",
                "size": udm.size // 8,
            }
        )

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "frame": {
            "frame_size": idc.get_func_attr(func.start_ea, idc.FUNCATTR_FRSIZE),
            "local_size": func.frsize,
            "saved_regs_size": func.frregs,
            "args_size": func.argsize,
            "member_count": len(members),
            "members": members,
        },
    }


def get_function_vars(args: dict) -> dict:
    cfunc, func = decompile_at(args["address"])

    variables = [
        {
            "name": lvar.name,
            "type": str(lvar.type()),
            "is_arg": lvar.is_arg_var,
            "is_result": lvar.is_result_var,
            "width": lvar.width,
        }
        for lvar in cfunc.lvars
    ]

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "variable_count": len(variables),
        "variables": variables,
    }


COMMANDS = [
    Command(
        "get-stack-frame", get_stack_frame, "frames",
        "Get the stack frame layout of a function (offsets, sizes, no Hex-Rays needed).",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
    Command(
        "get-function-vars", get_function_vars, "frames",
        "Get typed locals/params via Hex-Rays decompilation.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
]
