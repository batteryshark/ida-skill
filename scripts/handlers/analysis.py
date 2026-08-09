#!/usr/bin/env python3
"""analysis — auto-analysis control, problems, fixups, exceptions, sregs.

Ported from re_mcp_ida/tools/analysis.py. See handlers/functions.py for the
reference template conventions.
"""
from __future__ import annotations

import time

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    build_strlist,
    format_address,
    get_func_name,
    is_bad_addr,
    paginate_iter,
    resolve_address,
    resolve_function,
)


def _problem_types():
    import ida_problems

    return [
        (ida_problems.PR_NOBASE, "no_base"),
        (ida_problems.PR_NONAME, "no_name"),
        (ida_problems.PR_NOCMT, "no_comment"),
        (ida_problems.PR_NOXREFS, "no_xrefs"),
        (ida_problems.PR_JUMP, "jump"),
        (ida_problems.PR_DISASM, "disasm"),
        (ida_problems.PR_HEAD, "head"),
        (ida_problems.PR_ILLADDR, "illegal_address"),
        (ida_problems.PR_MANYLINES, "many_lines"),
        (ida_problems.PR_BADSTACK, "bad_stack"),
        (ida_problems.PR_ATTN, "attention"),
        (ida_problems.PR_FINAL, "final"),
        (ida_problems.PR_ROLLED, "rolled"),
        (ida_problems.PR_COLLISION, "collision"),
    ]


def _fixup_types():
    import ida_fixup

    return {
        ida_fixup.FIXUP_OFF8: "off8",
        ida_fixup.FIXUP_OFF16: "off16",
        ida_fixup.FIXUP_SEG16: "seg16",
        ida_fixup.FIXUP_OFF32: "off32",
        ida_fixup.FIXUP_OFF64: "off64",
        ida_fixup.FIXUP_CUSTOM: "custom",
    }


def reanalyze_range(args: dict) -> dict:
    import ida_auto

    start = resolve_address(args["start_address"])
    end = resolve_address(args["end_address"])

    ida_auto.plan_and_wait(start, end)

    return {
        "start": format_address(start),
        "end": format_address(end),
        "status": "analysis_complete",
    }


def wait_for_analysis(args: dict) -> dict:
    import ida_auto
    import ida_entry
    import ida_funcs
    import ida_ida
    import ida_segment

    start_time = time.monotonic()

    # Ensure the auto-analyzer is enabled — open_database may have been called
    # with run_auto_analysis=False, leaving queued work unprocessed.
    # enable_auto is cheap and idempotent.
    ida_auto.enable_auto(True)
    ida_auto.auto_wait()

    string_count = build_strlist()
    return {
        "status": "analysis_complete",
        "function_count": ida_funcs.get_func_qty(),
        "segment_count": ida_segment.get_segm_qty(),
        "entry_point_count": ida_entry.get_entry_qty(),
        "string_count": string_count,
        "min_address": format_address(ida_ida.inf_get_min_ea()),
        "max_address": format_address(ida_ida.inf_get_max_ea()),
        "elapsed_seconds": round(time.monotonic() - start_time, 1),
    }


def get_analysis_problems(args: dict) -> dict:
    import ida_problems

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    def _iter_problems():
        for ptype, pname in _problem_types():
            ea = ida_problems.get_problem(ptype, 0)
            while not is_bad_addr(ea):
                yield {
                    "address": format_address(ea),
                    "type": pname,
                    "function": get_func_name(ea),
                }
                ea = ida_problems.get_problem(ptype, ea + 1)

    return paginate_iter(_iter_problems(), offset, limit)


def get_fixups(args: dict) -> dict:
    import ida_fixup
    import ida_ida

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))
    start_address = args.get("start_address", "") or ""
    end_address = args.get("end_address", "") or ""

    start = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
    end = resolve_address(end_address) if end_address else ida_ida.inf_get_max_ea()

    fixup_types = _fixup_types()

    def _iter():
        ea = ida_fixup.get_first_fixup_ea()
        while not is_bad_addr(ea):
            if ea < start:
                ea = ida_fixup.get_next_fixup_ea(ea)
                continue
            if ea >= end:
                break

            fd = ida_fixup.fixup_data_t()
            if ida_fixup.get_fixup(fd, ea):
                yield {
                    "address": format_address(ea),
                    "type": fixup_types.get(fd.get_type() & 0xF, f"type_{fd.get_type()}"),
                    "target": format_address(fd.off),
                }

            ea = ida_fixup.get_next_fixup_ea(ea)

    return paginate_iter(_iter(), offset, limit)


def get_exception_handlers(args: dict) -> dict:
    import ida_range
    import ida_tryblks

    func = resolve_function(args["address"])

    tryblks = ida_tryblks.tryblks_t()
    func_range = ida_range.range_t(func.start_ea, func.end_ea)
    count = ida_tryblks.get_tryblks(tryblks, func_range)

    blocks = []
    for i in range(count):
        tb = tryblks[i]
        catches = []
        for j in range(tb.size()):
            catch = tb[j]
            catches.append(
                {
                    "start": format_address(catch.start_ea),
                    "end": format_address(catch.end_ea),
                }
            )

        blocks.append(
            {
                "try_start": format_address(tb.start_ea),
                "try_end": format_address(tb.end_ea),
                "catches": catches,
            }
        )

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "tryblock_count": len(blocks),
        "tryblocks": blocks,
    }


def get_segment_registers(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])

    regs = {}
    for reg_name in ["cs", "ds", "es", "fs", "gs", "ss"]:
        val = idc.get_sreg(ea, reg_name)
        if val is not None and val != -1:
            regs[reg_name] = format_address(val)

    return {
        "address": format_address(ea),
        "registers": regs,
    }


def set_segment_register(args: dict) -> dict:
    import idc

    start = resolve_address(args["start_address"])
    register = args["register"]
    value = int(args["value"])

    old_sreg = idc.get_sreg(start, register)
    old_value = format_address(old_sreg) if old_sreg is not None and old_sreg != -1 else None
    if not idc.split_sreg_range(start, register, value, idc.SR_user):
        raise IDAError(
            f"Failed to set {register} = {value:#x} at {args['start_address']}",
            error_type="SetFailed",
        )

    return {
        "address": format_address(start),
        "register": register,
        "old_value": old_value,
        "value": format_address(value),
    }


COMMANDS = [
    Command(
        "reanalyze-range", reanalyze_range, "analysis",
        "Reanalyze an address range synchronously (blocks until done).",
        mutates=True,
        params=[
            Param("start_address", "str", required=True, positional=True,
                  help="Start of the range."),
            Param("end_address", "str", required=True, positional=True,
                  help="End of the range (exclusive)."),
        ],
    ),
    Command(
        "wait-for-analysis", wait_for_analysis, "analysis",
        "Wait for IDA's auto-analysis to complete; returns a DB summary.",
        mutates=True,
        params=[],
    ),
    Command(
        "get-analysis-problems", get_analysis_problems, "analysis",
        "List analysis problems/conflicts found by IDA.",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Max results."),
        ],
    ),
    Command(
        "get-fixups", get_fixups, "analysis",
        "List relocation/fixup records in the binary.",
        params=[
            Param("start_address", "str", default="",
                  help="Start of range (default: database start)."),
            Param("end_address", "str", default="",
                  help="End of range (default: database end)."),
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Max results."),
        ],
    ),
    Command(
        "get-exception-handlers", get_exception_handlers, "analysis",
        "Get exception handling (try/catch) blocks for a function.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
    Command(
        "get-segment-registers", get_segment_registers, "analysis",
        "Get segment register values at an address.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address to query.")],
    ),
    Command(
        "set-segment-register", set_segment_register, "analysis",
        "Set a segment register value starting at an address (e.g. fs/gs for TLS).",
        mutates=True,
        params=[
            Param("start_address", "str", required=True, positional=True,
                  help="Address where the new register value starts."),
            Param("register", "str", required=True, positional=True,
                  help="Register name (e.g. fs, gs, ds)."),
            Param("value", "int", required=True, positional=True,
                  help="Value to set for the register."),
        ],
    ),
]
