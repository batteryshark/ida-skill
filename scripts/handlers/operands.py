#!/usr/bin/env python3
"""operands — instruction and operand analysis: decode instructions and operands.

Ported from re_mcp_ida/tools/operands.py.
"""
from __future__ import annotations

import logging

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    clean_disasm_line,
    decode_insn_at,
    format_address,
    resolve_address,
    validate_operand_num,
)

_OPERAND_TYPE_NAMES = {
    0: "void",  # o_void
    1: "reg",  # o_reg
    2: "mem",  # o_mem
    3: "phrase",  # o_phrase (base+index)
    4: "displ",  # o_displ (base+index+displacement)
    5: "imm",  # o_imm
    6: "far",  # o_far
    7: "near",  # o_near
}

log = logging.getLogger(__name__)


def _get_max_operands():
    """Return the max number of operands IDA supports per instruction."""
    import ida_ida

    try:
        return ida_ida.UA_MAXOP
    except AttributeError:
        return 8


def _reg_name(reg, dtype):
    """Get register name, with fallback."""
    import ida_idp

    try:
        name = ida_idp.get_reg_name(reg, dtype)
        if name:
            return name
    except Exception:
        log.warning("Failed to get register name for reg=%s dtype=%s", reg, dtype)
    return f"reg{reg}"


def decode_instruction(args: dict) -> dict:
    import ida_ua

    ea = resolve_address(args["address"])

    insn = decode_insn_at(ea)

    operands = []
    for i in range(_get_max_operands()):
        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            break
        op_info = {
            "index": i,
            "type": _OPERAND_TYPE_NAMES.get(op.type, f"unknown({op.type})"),
            "type_id": op.type,
            "register_name": None,
            "value": None,
            "address": None,
            "displacement": None,
        }
        if op.type == ida_ua.o_reg:
            op_info["register_name"] = _reg_name(op.reg, op.dtype)
        elif op.type == ida_ua.o_imm:
            op_info["value"] = format_address(op.value)
        elif op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
            op_info["address"] = format_address(op.addr)
        elif op.type == ida_ua.o_displ:
            op_info["displacement"] = op.addr
            op_info["register_name"] = _reg_name(op.reg, op.dtype)
        elif op.type == ida_ua.o_phrase:
            op_info["register_name"] = _reg_name(op.reg, op.dtype)

        operands.append(op_info)

    return {
        "address": format_address(ea),
        "disasm": clean_disasm_line(ea),
        "mnemonic": insn.get_canon_mnem(),
        "size": insn.size,
        "operand_count": len(operands),
        "operands": operands,
    }


def decode_instructions(args: dict) -> dict:
    import ida_ua

    ea = resolve_address(args["address"])
    count = int(args.get("count", 20))

    instructions = []
    current = ea

    for _ in range(count):
        insn = ida_ua.insn_t()
        length = ida_ua.decode_insn(insn, current)
        if length == 0:
            break
        instructions.append(
            {
                "address": format_address(current),
                "disasm": clean_disasm_line(current),
                "mnemonic": insn.get_canon_mnem(),
                "size": insn.size,
            }
        )
        current += insn.size

    return {
        "start": format_address(ea),
        "instruction_count": len(instructions),
        "instructions": instructions,
    }


def get_operand_value(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    operand_index = int(args.get("operand_index", 0))

    validate_operand_num(operand_index)

    op_type = idc.get_operand_type(ea, operand_index)
    if op_type == 0:  # o_void
        raise IDAError(
            f"No operand {operand_index} at {format_address(ea)}", error_type="InvalidArgument"
        )

    value = idc.get_operand_value(ea, operand_index)

    return {
        "address": format_address(ea),
        "operand_index": operand_index,
        "type": _OPERAND_TYPE_NAMES.get(op_type, f"unknown({op_type})"),
        "value": format_address(value) if value is not None else None,
    }


COMMANDS = [
    Command(
        "decode-instruction", decode_instruction, "operands",
        "Decode ONE instruction at an address (mnemonic, operands, size).",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address of the instruction.")],
    ),
    Command(
        "decode-instructions", decode_instructions, "operands",
        "Decode N sequential instructions from any address (not bounded by function limits).",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Starting address."),
            Param("count", "int", default=20, help="Number of instructions to decode (max 200)."),
        ],
    ),
    Command(
        "get-operand-value", get_operand_value, "operands",
        "Get the resolved value of an instruction operand.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address of the instruction."),
            Param("operand_index", "int", default=0, help="Which operand (0-based)."),
        ],
    ),
]
