#!/usr/bin/env python3
"""assemble — assemble instructions (dry-run) and patch assembly into the IDB.

Ported from re_mcp_ida/tools/assemble.py. Follows the handler template in
handlers/functions.py: all ``ida_*``/``idautils`` imports live inside handler
bodies, each handler takes ``args: dict`` and returns a JSON-serializable dict,
failures raise ``IDAError(msg, error_type=...)``, and a module-level
``COMMANDS`` list registers each handler with its schema.

The assembler is only available for the ``metapc`` processor. When the current
database lacks it, both tools raise ``IDAError("assembler not available for
this processor", error_type="Unsupported")``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    resolve_address,
    session,
)


def _require_assembler() -> None:
    if not session.capabilities.get("assembler"):
        raise IDAError(
            "assembler not available for this processor",
            error_type="Unsupported",
        )


def _assemble_at(ea: int, instruction: str) -> bytes:
    """Assemble *instruction* at *ea*. Raises :class:`IDAError` on failure."""
    import idautils

    result = idautils.Assemble(ea, instruction)
    if isinstance(result, str):
        raise IDAError(result, error_type="AssemblyFailed")

    success, assembled_bytes = result
    if not success:
        raise IDAError(f"Failed to assemble: {instruction!r}", error_type="AssemblyFailed")
    return assembled_bytes


def assemble_instruction(args: dict) -> dict:
    import ida_bytes

    _require_assembler()
    ea = resolve_address(args["address"])
    instruction = args["instruction"]
    assembled_bytes = _assemble_at(ea, instruction)

    old_bytes_data = ida_bytes.get_bytes(ea, len(assembled_bytes))
    return {
        "address": format_address(ea),
        "instruction": instruction,
        "old_bytes": old_bytes_data.hex() if old_bytes_data else "",
        "bytes": assembled_bytes.hex(),
        "length": len(assembled_bytes),
    }


def patch_asm(args: dict) -> dict:
    import ida_bytes
    import ida_undo

    _require_assembler()
    ea = resolve_address(args["address"])
    instruction = args["instruction"]
    assembled_bytes = _assemble_at(ea, instruction)

    old_bytes_data = ida_bytes.get_bytes(ea, len(assembled_bytes))

    ida_undo.create_undo_point("patch_asm", "patch_asm")
    ida_bytes.patch_bytes(ea, assembled_bytes)

    return {
        "address": format_address(ea),
        "instruction": instruction,
        "old_bytes": old_bytes_data.hex() if old_bytes_data else "",
        "new_bytes": assembled_bytes.hex(),
        "length": len(assembled_bytes),
        "patched": True,
    }


COMMANDS = [
    Command(
        "assemble-instruction", assemble_instruction, "assemble",
        "Assemble an instruction at an address without patching (dry-run).",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address where the instruction should be assembled."),
            Param("instruction", "str", required=True,
                  help='Assembly text (e.g. "nop", "mov eax, 1").'),
        ],
    ),
    Command(
        "patch-asm", patch_asm, "assemble",
        "Assemble and patch an instruction into the database in one step.",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address where the instruction is assembled and patched."),
            Param("instruction", "str", required=True,
                  help='Assembly text (e.g. "nop", "mov eax, 1").'),
        ],
    ),
]
