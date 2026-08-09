#!/usr/bin/env python3
"""function_type — function prototype and calling convention tools.

Ported from re_mcp_ida/tools/function_type.py into the standalone idalib
worker's handler format: each handler takes ``args: dict`` and returns a
JSON-serializable dict; all ``ida_*`` imports live inside function bodies.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    get_func_name,
    resolve_function,
)

# Calling-convention name lookup, keyed by the CM_CC_* constant. Populated
# lazily inside handlers (the ida_typeinf constants aren't available at import
# time on a non-IDA Python).
_CC_NAME_KEYS = ("cdecl", "stdcall", "pascal", "fastcall", "thiscall")


def _cc_maps():
    import ida_typeinf

    cc_names = {
        ida_typeinf.CM_CC_CDECL: "cdecl",
        ida_typeinf.CM_CC_STDCALL: "stdcall",
        ida_typeinf.CM_CC_PASCAL: "pascal",
        ida_typeinf.CM_CC_FASTCALL: "fastcall",
        ida_typeinf.CM_CC_THISCALL: "thiscall",
    }
    cc_map = {v: k for k, v in cc_names.items()}
    return cc_names, cc_map


def get_function_type(args: dict) -> dict:
    import ida_nalt
    import ida_typeinf
    import idc

    cc_names, _cc_map = _cc_maps()

    func = resolve_function(args["address"])

    tinfo = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tinfo, func.start_ea) and not ida_typeinf.guess_tinfo(
        tinfo, func.start_ea
    ):
        type_str = idc.get_type(func.start_ea) or ""
        return {
            "address": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "type": type_str,
            "details": None,
        }

    # Extract function details
    fi = ida_typeinf.func_type_data_t()
    if tinfo.get_func_details(fi):
        params = []
        for i in range(fi.size()):
            param = fi[i]
            params.append(
                {
                    "name": param.name or f"arg{i}",
                    "type": str(param.type),
                }
            )

        return {
            "address": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "type": str(tinfo),
            "details": {
                "return_type": str(fi.rettype),
                "calling_convention": cc_names.get(
                    fi.get_cc() & 0xF0, f"cc_{fi.get_cc():#x}"
                ),
                "parameters": params,
            },
        }

    return {
        "address": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "type": str(tinfo),
        "details": None,
    }


def set_function_type(args: dict) -> dict:
    import idc

    func = resolve_function(args["address"])
    type_string = args["type_string"]

    old_type = idc.get_type(func.start_ea) or ""
    success = idc.SetType(func.start_ea, type_string)
    if not success:
        raise IDAError("Failed to set function type", error_type="SetTypeFailed")

    return {
        "address": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "old_type": old_type,
        "type": type_string,
    }


def set_function_calling_convention(args: dict) -> dict:
    import ida_nalt
    import ida_typeinf

    cc_names, cc_map = _cc_maps()

    func = resolve_function(args["address"])
    convention = args["convention"]

    cc_val = cc_map.get(convention.lower())
    if cc_val is None:
        raise IDAError(
            f"Unknown calling convention: {convention!r}",
            error_type="InvalidArgument",
            valid_conventions=list(cc_map),
        )

    tinfo = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tinfo, func.start_ea) and not ida_typeinf.guess_tinfo(
        tinfo, func.start_ea
    ):
        raise IDAError(
            "Cannot determine function type to change convention", error_type="NoType"
        )

    fi = ida_typeinf.func_type_data_t()
    if not tinfo.get_func_details(fi):
        raise IDAError("Cannot get function details", error_type="NoType")

    old_convention = cc_names.get(fi.get_cc() & 0xF0, f"cc_{fi.get_cc():#x}")
    fi.set_cc((fi.get_cc() & 0x0F) | cc_val)
    new_tinfo = ida_typeinf.tinfo_t()
    if not new_tinfo.create_func(fi):
        raise IDAError("Failed to create new function type", error_type="CreateFailed")

    success = ida_typeinf.apply_tinfo(func.start_ea, new_tinfo, ida_typeinf.TINFO_DEFINITE)
    if not success:
        raise IDAError(
            f"Failed to apply calling convention {convention!r}", error_type="ApplyFailed"
        )
    return {
        "address": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "old_convention": old_convention,
        "convention": convention,
    }


COMMANDS = [
    Command(
        "get-function-type", get_function_type, "function_type",
        "Get the full type signature (prototype) of a function.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or name of the function."),
        ],
    ),
    Command(
        "set-function-type", set_function_type, "function_type",
        "Set a function's full C prototype (return + args + calling convention).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("type_string", "str", required=True, positional=True,
                  help='C function declaration, e.g. "int __cdecl foo(int a, char *b)".'),
        ],
    ),
    Command(
        "set-function-calling-convention", set_function_calling_convention, "function_type",
        "Change the calling convention of a function.", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("convention", "str", required=True, positional=True,
                  help="cdecl|stdcall|fastcall|thiscall|pascal."),
        ],
    ),
]
