#!/usr/bin/env python3
"""processor — processor and architecture information tools.

Ported from re_mcp_ida/tools/processor.py.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    decode_insn_at,
    format_address,
    resolve_address,
)


def get_processor_info(args: dict) -> dict:
    import ida_ida
    import ida_idp

    reg_names = ida_idp.ph_get_regnames()

    return {
        "processor": ida_idp.get_idp_name(),
        "bitness": ida_ida.inf_get_app_bitness(),
        "is_64bit": ida_ida.inf_is_64bit(),
        "register_names": list(reg_names) if reg_names else [],
    }


def get_register_name(args: dict) -> dict:
    import ida_ida
    import ida_idp

    register_number = int(args["register_number"])
    width = int(args.get("width", 0))
    if width == 0:
        width = 8 if ida_ida.inf_is_64bit() else 4

    name = ida_idp.get_reg_name(register_number, width)
    return {
        "register_number": register_number,
        "width": width,
        "name": name or "",
    }


def is_call_instruction(args: dict) -> dict:
    import ida_idp

    ea = resolve_address(args["address"])

    insn = decode_insn_at(ea)

    return {
        "address": format_address(ea),
        "is_call": bool(ida_idp.is_call_insn(insn)),
    }


def is_return_instruction(args: dict) -> dict:
    import ida_idp

    ea = resolve_address(args["address"])

    insn = decode_insn_at(ea)

    return {
        "address": format_address(ea),
        "is_return": bool(ida_idp.is_ret_insn(insn)),
    }


def is_alignment_instruction(args: dict) -> dict:
    import ida_idp

    ea = resolve_address(args["address"])

    align_size = ida_idp.is_align_insn(ea)
    return {
        "address": format_address(ea),
        "is_alignment": align_size > 0,
        "alignment_size": max(0, align_size),
    }


def get_instruction_list(args: dict) -> dict:
    import ida_idp
    import idautils

    mnemonics = list(idautils.GetInstructionList())
    return {
        "processor": ida_idp.get_idp_name(),
        "count": len(mnemonics),
        "instructions": mnemonics,
    }


COMMANDS = [
    Command(
        "get-processor-info", get_processor_info, "processor",
        "Get processor/architecture info (name, registers, bitness).",
    ),
    Command(
        "get-register-name", get_register_name, "processor",
        "Get the name of a register by its number and width.",
        params=[
            Param("register_number", "int", required=True, positional=True,
                  help="The register number (processor-specific)."),
            Param("width", "int", default=0, help="Register width in bytes (0 for default)."),
        ],
    ),
    Command(
        "is-call-instruction", is_call_instruction, "processor",
        "Check whether the instruction at an address is a call.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address of the instruction.")],
    ),
    Command(
        "is-return-instruction", is_return_instruction, "processor",
        "Check whether the instruction at an address is a return.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address of the instruction.")],
    ),
    Command(
        "is-alignment-instruction", is_alignment_instruction, "processor",
        "Check whether an instruction is alignment padding (NOP sled, etc.).",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address of the instruction.")],
    ),
    Command(
        "get-instruction-list", get_instruction_list, "processor",
        "Get all instruction mnemonics recognized by the current processor.",
    ),
]
