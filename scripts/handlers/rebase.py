#!/usr/bin/env python3
"""rebase — segment moving and program rebasing.

Ported from re_mcp_ida/tools/rebase.py. Follows the handler contract (see
handlers/functions.py): ``ida_*`` imports live inside functions, each handler
takes ``args: dict`` and returns a JSON-serializable dict, failures raise
``IDAError``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    parse_address,
    resolve_address,
    resolve_segment,
)


def move_segment(args: dict) -> dict:
    import ida_segment

    seg = resolve_segment(args["address"])
    to = resolve_address(args["new_start"])

    old_start = seg.start_ea
    name = ida_segment.get_segm_name(seg)
    code = ida_segment.move_segm(seg, to)

    if code != 0:
        error_msg = ida_segment.move_segm_strerror(code)
        raise IDAError(
            f"Failed to move segment: {error_msg}",
            error_type="MoveFailed",
            error_code=int(code),
        )

    return {
        "segment": name,
        "old_start": format_address(old_start),
        "new_start": format_address(to),
    }


def rebase_program(args: dict) -> dict:
    import ida_ida
    import ida_segment

    delta = args["delta"]
    try:
        delta_val = -parse_address(delta[1:]) if delta.startswith("-") else parse_address(delta)
    except ValueError as e:
        raise IDAError(str(e), error_type="InvalidAddress") from e

    old_base = ida_ida.inf_get_min_ea()
    code = ida_segment.rebase_program(delta_val, ida_segment.MSF_FIXONCE)
    if code != 0:
        raise IDAError(
            f"Rebase failed with code {code}",
            error_type="RebaseFailed",
            error_code=int(code),
        )

    return {
        "old_base": format_address(old_base),
        "delta": format_address(delta_val) if delta_val >= 0 else f"-{format_address(-delta_val)}",
    }


COMMANDS = [
    Command(
        "move-segment", move_segment, "rebase",
        "Relocate ONE segment to a new start address and fix up references.",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Any address within the segment to move."),
            Param("new_start", "str", required=True, positional=True,
                  help="New starting address for the segment."),
        ],
    ),
    Command(
        "rebase-program", rebase_program, "rebase",
        "Shift EVERY address by a delta (destructive, global).", mutates=True,
        params=[Param("delta", "str", required=True, positional=True,
                      help="Address delta to shift by (e.g. 0x1000 or -0x1000).")],
    ),
]
