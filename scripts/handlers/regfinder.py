#!/usr/bin/env python3
"""regfinder — register value tracking tools.

Ported from re_mcp_ida/tools/regfinder.py.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    resolve_address,
)


def find_register_value(args: dict) -> dict:
    import ida_idp
    import ida_regfinder

    ea = resolve_address(args["address"])
    register = args["register"]

    # Resolve register name to number.
    # IDA's register list uses short base names (e.g. "ax", "di") but
    # users will often use the full x86-64 names ("rax", "rdi", "edi").
    # Strip common prefixes to match the base name.
    reg_names = ida_idp.ph_get_regnames()
    reg_num = None
    reg_lower = register.lower()
    # Also try stripping e/r prefix for x86 (e.g. rax->ax, edi->di)
    stripped = reg_lower[1:] if len(reg_lower) > 2 and reg_lower[0] in ("e", "r") else None
    if reg_names:
        fallback = None
        for i, name in enumerate(reg_names):
            name_lower = name.lower()
            if name_lower == reg_lower:
                reg_num = i
                break
            if stripped and fallback is None and name_lower == stripped:
                fallback = i
        if reg_num is None:
            reg_num = fallback

    if reg_num is None:
        raise IDAError(
            f"Unknown register: {register!r}",
            error_type="InvalidArgument",
            available_registers=list(reg_names) if reg_names else [],
        )

    rvi = ida_regfinder.reg_value_info_t()
    found = ida_regfinder.find_reg_value_info(rvi, ea, reg_num)
    if not found or not rvi.is_known():
        return {
            "address": format_address(ea),
            "register_name": register,
            "found": False,
            "reason": "Register tracker not supported or value unknown",
            "value": None,
        }

    if (rvi.is_num() or rvi.is_spd()) and len(rvi) > 0:
        val = int(rvi[0].val)
    else:
        return {
            "address": format_address(ea),
            "register_name": register,
            "found": False,
            "reason": "Value is not a simple constant or SP delta",
            "value": None,
        }

    return {
        "address": format_address(ea),
        "register_name": register,
        "found": True,
        "reason": None,
        "value": format_address(val),
    }


def find_stack_pointer_value(args: dict) -> dict:
    import ida_regfinder

    ea = resolve_address(args["address"])

    try:
        sp_val = ida_regfinder.find_sp_value(ea)
    except Exception as e:
        raise IDAError(f"Stack pointer tracking failed: {e}", error_type="NotSupported") from e
    return {
        "address": format_address(ea),
        "sp_value": sp_val,
    }


COMMANDS = [
    Command(
        "find-register-value", find_register_value, "regfinder",
        "Trace a register value at an address using IDA's backwards register tracker.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address at which to find the register value."),
            Param("register", "str", required=True, positional=True,
                  help='Register name (e.g. "rax", "eax", "r8", "ecx").'),
        ],
    ),
    Command(
        "find-stack-pointer-value", find_stack_pointer_value, "regfinder",
        "Get the stack pointer offset (relative to function entry) at an address.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address at which to find the SP value.")],
    ),
]
