#!/usr/bin/env python3
"""operand_repr — change how operands display in disassembly.

Ported from re_mcp_ida/tools/operand_repr.py. All ``ida_*``/``idc`` imports
live inside handler bodies so the manifest imports cleanly without an IDA
runtime.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    decode_insn_at,
    format_address,
    resolve_address,
    resolve_enum,
    resolve_struct,
    validate_operand_num,
)


def _get_operand_format(ea: int, n: int) -> str:
    """Read the current display format of an operand."""
    import ida_bytes

    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_numop(flags, n):
        return "numeric"
    return "default"


def _set_operand_repr(ea: int, operand_num: int, fmt_name: str, idc_func) -> dict:
    """Shared implementation for set_operand_<format> tools."""
    validate_operand_num(operand_num)
    old_format = _get_operand_format(ea, operand_num)
    if not idc_func(ea, operand_num):
        raise IDAError(
            f"Failed to set operand {operand_num} to {fmt_name} at {format_address(ea)}",
            error_type="SetOperandFailed",
        )
    return {
        "address": format_address(ea),
        "operand": operand_num,
        "old_format": old_format,
        "format": fmt_name,
    }


def _format_dispatch() -> dict:
    import idc

    return {
        "hex": idc.op_hex,
        "decimal": idc.op_dec,
        "binary": idc.op_bin,
        "octal": idc.op_oct,
        "char": idc.op_chr,
    }


def set_operand_format(args: dict) -> dict:
    address = args["address"]
    operand_num = int(args["operand_num"])
    display_format = args["display_format"]

    dispatch = _format_dispatch()
    if display_format not in dispatch:
        raise IDAError(
            f"Invalid display_format: {display_format!r}",
            error_type="InvalidArgument",
            valid_formats=sorted(dispatch),
        )
    idc_func = dispatch[display_format]
    return _set_operand_repr(resolve_address(address), operand_num, display_format, idc_func)


def set_operand_offset(args: dict) -> dict:
    import idc

    address = args["address"]
    operand_num = int(args["operand_num"])
    base = int(args.get("base", 0))

    validate_operand_num(operand_num)
    ea = resolve_address(address)

    old_format = _get_operand_format(ea, operand_num)
    if not idc.op_plain_offset(ea, operand_num, base):
        raise IDAError(
            f"Failed to set operand {operand_num} to offset at {format_address(ea)}",
            error_type="SetOperandFailed",
        )
    return {
        "address": format_address(ea),
        "operand": operand_num,
        "old_format": old_format,
        "format": "offset",
        "base": format_address(base),
    }


def set_operand_enum(args: dict) -> dict:
    import idc

    address = args["address"]
    operand_num = int(args["operand_num"])
    enum_name = args["enum_name"]

    validate_operand_num(operand_num)
    ea = resolve_address(address)

    eid = resolve_enum(enum_name)

    old_format = _get_operand_format(ea, operand_num)
    if not idc.op_enum(ea, operand_num, eid, 0):
        raise IDAError(
            f"Failed to apply enum {enum_name!r} to operand {operand_num} at {format_address(ea)}",
            error_type="SetOperandFailed",
        )
    return {
        "address": format_address(ea),
        "operand": operand_num,
        "old_format": old_format,
        "enum": enum_name,
    }


def set_operand_struct_offset(args: dict) -> dict:
    import ida_bytes

    address = args["address"]
    operand_num = int(args["operand_num"])
    struct_name = args["struct_name"]

    validate_operand_num(operand_num)
    ea = resolve_address(address)

    sid = resolve_struct(struct_name)

    insn = decode_insn_at(ea)
    old_format = _get_operand_format(ea, operand_num)
    if not ida_bytes.op_stroff(insn, operand_num, [sid], 0):
        raise IDAError(
            f"Failed to apply struct {struct_name!r} to operand {operand_num} at {format_address(ea)}",
            error_type="SetOperandFailed",
        )
    return {
        "address": format_address(ea),
        "operand": operand_num,
        "old_format": old_format,
        "struct": struct_name,
    }


COMMANDS = [
    Command(
        "set-operand-format", set_operand_format, "operand_repr",
        "Change an operand's numeric base (hex/dec/bin/oct/char).", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Instruction address."),
            Param("operand_num", "int", required=True, positional=True,
                  help="Operand index (0-based)."),
            Param("display_format", "str", required=True,
                  help="hex|decimal|binary|octal|char."),
        ],
    ),
    Command(
        "set-operand-offset", set_operand_offset, "operand_repr",
        "Reinterpret a numeric operand as a flat pointer/offset (creates an xref).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Instruction address."),
            Param("operand_num", "int", required=True, positional=True,
                  help="Operand index (0-based)."),
            Param("base", "int", default=0,
                  help="Base address for the offset calculation (0 for flat)."),
        ],
    ),
    Command(
        "set-operand-enum", set_operand_enum, "operand_repr",
        "Display a numeric operand as an enum member name.", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Instruction address."),
            Param("operand_num", "int", required=True, positional=True,
                  help="Operand index (0-based)."),
            Param("enum_name", "str", required=True, positional=True,
                  help="Name of the enum to apply."),
        ],
    ),
    Command(
        "set-operand-struct-offset", set_operand_struct_offset, "operand_repr",
        "Reinterpret an operand as a struct field offset (creates the struct xref).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Instruction address."),
            Param("operand_num", "int", required=True, positional=True,
                  help="Operand index (0-based)."),
            Param("struct_name", "str", required=True, positional=True,
                  help="Name of the structure."),
        ],
    ),
]
