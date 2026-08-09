#!/usr/bin/env python3
"""decompiler — Hex-Rays interaction: rename/retype vars, microcode, comments.

Ported from re_mcp_ida/tools/decompiler.py. All ``ida_*`` imports live inside
handler bodies so the manifest imports cleanly without an IDA runtime.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    decompile_at,
    format_address,
    get_func_name,
    parse_type,
    resolve_address,
    resolve_function,
)


def _maturity_map() -> dict:
    import ida_hexrays

    return {
        "MMAT_GENERATED": ida_hexrays.MMAT_GENERATED,
        "MMAT_PREOPTIMIZED": ida_hexrays.MMAT_PREOPTIMIZED,
        "MMAT_LOCOPT": ida_hexrays.MMAT_LOCOPT,
        "MMAT_CALLS": ida_hexrays.MMAT_CALLS,
        "MMAT_GLBOPT1": ida_hexrays.MMAT_GLBOPT1,
        "MMAT_GLBOPT2": ida_hexrays.MMAT_GLBOPT2,
        "MMAT_GLBOPT3": ida_hexrays.MMAT_GLBOPT3,
        "MMAT_LVARS": ida_hexrays.MMAT_LVARS,
    }


def rename_decompiler_variable(args: dict) -> dict:
    import ida_hexrays

    function_address = args["function_address"]
    old_name = args["old_name"]
    new_name = args["new_name"]

    cfunc, func = decompile_at(function_address)

    available = [lvar.name for lvar in cfunc.lvars]
    if old_name not in available:
        raise IDAError(
            f"Variable not found: {old_name!r}",
            error_type="NotFound",
            available_variables=available,
        )

    # IDA 9.x: rename_lvar(func_ea, old_name, new_name) — all strings
    success = ida_hexrays.rename_lvar(cfunc.entry_ea, old_name, new_name)
    if not success:
        raise IDAError(
            f"Failed to rename variable {old_name!r} to {new_name!r}", error_type="RenameFailed"
        )
    return {
        "function": format_address(func.start_ea),
        "old_name": old_name,
        "new_name": new_name,
    }


def retype_decompiler_variable(args: dict) -> dict:
    import ida_hexrays

    function_address = args["function_address"]
    variable_name = args["variable_name"]
    new_type = args["new_type"]

    cfunc, func = decompile_at(function_address)

    tinfo = parse_type(new_type)

    # IDA 9.x: use modify_user_lvar_info() — cfuncptr_t has no set_lvar_type().
    for lvar in cfunc.lvars:
        if lvar.name == variable_name:
            old_type = str(lvar.type())
            info = ida_hexrays.lvar_saved_info_t()
            info.ll = lvar
            info.type = tinfo
            success = ida_hexrays.modify_user_lvar_info(
                cfunc.entry_ea, ida_hexrays.MLI_TYPE, info
            )
            if not success:
                raise IDAError(
                    f"Failed to set type on {variable_name!r}", error_type="RetypeFailed"
                )
            return {
                "function": format_address(func.start_ea),
                "variable": variable_name,
                "old_type": old_type,
                "new_type": str(tinfo),
            }

    available = [lvar.name for lvar in cfunc.lvars]
    raise IDAError(
        f"Variable not found: {variable_name!r}",
        error_type="NotFound",
        available_variables=available,
    )


def get_microcode(args: dict) -> dict:
    import ida_hexrays

    function_address = args["function_address"]
    maturity = args.get("maturity", "MMAT_LVARS") or "MMAT_LVARS"

    func = resolve_function(function_address)

    maturity_map = _maturity_map()
    mat_val = maturity_map.get(maturity)
    if mat_val is None:
        raise IDAError(
            f"Invalid maturity level: {maturity!r}",
            error_type="InvalidArgument",
            valid_levels=list(maturity_map),
        )

    try:
        mbr = ida_hexrays.mba_ranges_t(func)
        mba = ida_hexrays.gen_microcode(
            mbr,
            None,  # hf
            None,  # retlist
            0,  # decomp_flags
            mat_val,
        )
    except Exception as e:
        raise IDAError(f"Microcode generation failed: {e}", error_type="MicrocodeFailed") from e

    if mba is None:
        raise IDAError("Microcode generation returned no result", error_type="MicrocodeFailed")

    _MAX_INSNS_PER_BLOCK = 50_000
    blocks = []
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        lines = []
        insn = blk.head
        safety = 0
        while insn is not None and safety < _MAX_INSNS_PER_BLOCK:
            lines.append(insn.dstr())
            insn = insn.next if insn.next != insn else None
            safety += 1
        blocks.append(
            {
                "block_index": i,
                "start": format_address(blk.start),
                "end": format_address(blk.end),
                "instruction_count": len(lines),
                "instructions": lines,
            }
        )

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "maturity": maturity,
        "block_count": len(blocks),
        "blocks": blocks,
    }


def set_decompiler_comment(args: dict) -> dict:
    import ida_hexrays

    address = args["address"]
    comment = args.get("comment", "") or ""
    function_address = args.get("function_address", "") or ""

    ea = resolve_address(address)

    cfunc, func = decompile_at(function_address or address)
    func_ea = func.start_ea

    # Find the treeloc for the address
    tl = ida_hexrays.treeloc_t()
    tl.ea = ea
    tl.itp = ida_hexrays.ITP_SEMI

    old_comment = cfunc.get_user_cmt(tl, ida_hexrays.RETRIEVE_ALWAYS) or ""

    cfunc.set_user_cmt(tl, comment)
    cfunc.save_user_cmts()

    return {
        "address": format_address(ea),
        "function": format_address(func_ea),
        "old_comment": old_comment,
        "comment": comment,
    }


def get_decompiler_comments(args: dict) -> dict:
    import ida_hexrays

    function_address = args["function_address"]
    cfunc, func = decompile_at(function_address)

    comments = []
    cmts = cfunc.user_cmts
    if cmts is not None:
        it = ida_hexrays.user_cmts_begin(cmts)
        while it != ida_hexrays.user_cmts_end(cmts):
            tl = ida_hexrays.user_cmts_first(it)
            cmt = ida_hexrays.user_cmts_second(it)
            comments.append(
                {
                    "address": format_address(tl.ea),
                    "comment": str(cmt),
                }
            )
            it = ida_hexrays.user_cmts_next(it)

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "comments": comments,
    }


def list_decompiler_variables(args: dict) -> dict:
    import ida_idp

    function_address = args["function_address"]
    cfunc, func = decompile_at(function_address)

    variables = []
    for lvar in cfunc.lvars:
        var = {
            "name": lvar.name,
            "type": str(lvar.type()),
            "is_arg": lvar.is_arg_var,
            "is_stk_var": lvar.is_stk_var(),
            "is_reg_var": lvar.is_reg_var(),
            "register_name": ida_idp.get_reg_name(lvar.get_reg1(), lvar.width)
            if lvar.is_reg_var()
            else None,
            "stack_offset": lvar.get_stkoff() if lvar.is_stk_var() else None,
        }
        variables.append(var)

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "variable_count": len(variables),
        "variables": variables,
    }


COMMANDS = [
    Command(
        "rename-decompiler-variable", rename_decompiler_variable, "decompiler",
        "Rename ONE Hex-Rays local or parameter (pseudocode scope).", mutates=True,
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("old_name", "str", required=True, positional=True,
                  help="Current variable name in the pseudocode."),
            Param("new_name", "str", required=True, positional=True,
                  help="New name to assign to the variable."),
        ],
    ),
    Command(
        "retype-decompiler-variable", retype_decompiler_variable, "decompiler",
        "Retype ONE Hex-Rays local or parameter.", mutates=True,
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("variable_name", "str", required=True, positional=True,
                  help="Name of the variable to retype."),
            Param("new_type", "str", required=True, positional=True,
                  help="C type string to apply (e.g. \"int *\")."),
        ],
    ),
    Command(
        "get-microcode", get_microcode, "decompiler",
        "Get Hex-Rays microcode for a function at a maturity level.",
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("maturity", "str", default="MMAT_LVARS",
                  help="Maturity level (MMAT_GENERATED..MMAT_LVARS)."),
        ],
    ),
    Command(
        "set-decompiler-comment", set_decompiler_comment, "decompiler",
        "Attach a comment to a pseudocode line (Hex-Rays view only).", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Instruction address where the comment should appear."),
            Param("comment", "str", default="",
                  help="Comment text to set (empty string to delete)."),
            Param("function_address", "str", default="",
                  help="Address or name of the containing function (auto-detected if empty)."),
        ],
    ),
    Command(
        "get-decompiler-comments", get_decompiler_comments, "decompiler",
        "List Hex-Rays pseudocode comments for ONE function.",
        params=[Param("function_address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
    Command(
        "list-decompiler-variables", list_decompiler_variables, "decompiler",
        "List Hex-Rays locals/params for ONE function.",
        params=[Param("function_address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
]
