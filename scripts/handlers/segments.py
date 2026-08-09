#!/usr/bin/env python3
"""segments — segment creation and modification.

Ported from re_mcp_ida/tools/segments.py. Follows the handler contract (see
handlers/functions.py): ``ida_*`` imports live inside functions, each handler
takes ``args: dict`` and returns a JSON-serializable dict, failures raise
``IDAError``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    format_permissions,
    parse_permissions,
    resolve_address,
    resolve_segment,
)


def create_segment(args: dict) -> dict:
    import ida_segment

    name = args["name"]
    segment_class = args.get("segment_class", "DATA")
    bitness = int(args.get("bitness", 0))
    permissions = args.get("permissions", "RW-")

    start = resolve_address(args["start_address"])
    end = resolve_address(args["end_address"])

    perm = parse_permissions(permissions)

    seg = ida_segment.segment_t()
    seg.start_ea = start
    seg.end_ea = end
    seg.perm = perm
    seg.bitness = bitness

    if not ida_segment.add_segm_ex(seg, name, segment_class, 0):
        raise IDAError(f"Failed to create segment {name!r}", error_type="CreateFailed")

    return {
        "name": name,
        "start": format_address(start),
        "end": format_address(end),
        "class": segment_class,
        "bitness": bitness,
        "permissions": permissions,
    }


def delete_segment(args: dict) -> dict:
    import ida_segment

    seg = resolve_segment(args["address"])

    name = ida_segment.get_segm_name(seg)
    start = seg.start_ea
    old_end = format_address(seg.end_ea)
    old_permissions = format_permissions(seg.perm)
    old_class = ida_segment.get_segm_class(seg) or ""
    if not ida_segment.del_segm(start, ida_segment.SEGMOD_KILL):
        raise IDAError(f"Failed to delete segment {name!r}", error_type="DeleteFailed")
    return {
        "name": name,
        "start": format_address(start),
        "old_end": old_end,
        "old_permissions": old_permissions,
        "old_class": old_class,
    }


def set_segment_name(args: dict) -> dict:
    import ida_segment

    seg = resolve_segment(args["address"])
    new_name = args["new_name"]

    old_name = ida_segment.get_segm_name(seg)
    if not ida_segment.set_segm_name(seg, new_name):
        raise IDAError(
            f"Failed to rename segment {old_name!r} to {new_name!r}", error_type="RenameFailed"
        )
    return {"old_name": old_name, "new_name": new_name}


def set_segment_permissions(args: dict) -> dict:
    import ida_segment

    seg = resolve_segment(args["address"])
    permissions = args["permissions"]

    perm = parse_permissions(permissions)

    old_perm = seg.perm
    seg.perm = perm
    seg_name = ida_segment.get_segm_name(seg)
    if not seg.update():
        raise IDAError(
            f"Failed to set permissions on segment {seg_name!r}", error_type="UpdateFailed"
        )
    return {
        "segment": seg_name,
        "old_permissions": format_permissions(old_perm),
        "permissions": permissions,
    }


def set_segment_bitness(args: dict) -> dict:
    import ida_segment

    seg = resolve_segment(args["address"])
    bitness = int(args["bitness"])

    if bitness not in (0, 1, 2):
        raise IDAError(
            f"Invalid bitness: {bitness} (must be 0, 1, or 2)", error_type="InvalidArgument"
        )

    old_bitness = seg.bitness
    seg_name = ida_segment.get_segm_name(seg)
    if not ida_segment.set_segm_addressing(seg, bitness):
        raise IDAError(
            f"Failed to set bitness on segment {seg_name!r}", error_type="UpdateFailed"
        )
    return {"segment": seg_name, "old_bitness": old_bitness, "bitness": bitness}


def set_segment_class(args: dict) -> dict:
    import ida_segment

    seg = resolve_segment(args["address"])
    segment_class = args["segment_class"]

    seg_name = ida_segment.get_segm_name(seg)
    old_class = ida_segment.get_segm_class(seg) or ""
    if not ida_segment.set_segm_class(seg, segment_class):
        raise IDAError(
            f"Failed to set class on segment {seg_name!r}", error_type="UpdateFailed"
        )
    return {"segment": seg_name, "old_class": old_class, "class": segment_class}


COMMANDS = [
    Command(
        "create-segment", create_segment, "segments",
        "Create a new segment in the database.", mutates=True,
        params=[
            Param("name", "str", required=True, positional=True,
                  help="Name for the segment (e.g. .mydata)."),
            Param("start_address", "str", required=True, positional=True,
                  help="Start address of the segment."),
            Param("end_address", "str", required=True, positional=True,
                  help="End address of the segment (exclusive)."),
            Param("segment_class", "str", default="DATA",
                  help="Segment class: CODE|DATA|BSS|STACK|etc."),
            Param("bitness", "int", default=0,
                  help="Address size: 0=16-bit, 1=32-bit, 2=64-bit."),
            Param("permissions", "str", default="RW-",
                  help="Permission string like RWX, R--, RW-."),
        ],
    ),
    Command(
        "delete-segment", delete_segment, "segments",
        "Delete the segment containing the given address.", mutates=True,
        params=[Param("address", "str", required=True, positional=True,
                      help="Any address within the segment to delete.")],
    ),
    Command(
        "set-segment-name", set_segment_name, "segments",
        "Rename a segment.", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Any address within the segment."),
            Param("new_name", "str", required=True, positional=True,
                  help="New name for the segment."),
        ],
    ),
    Command(
        "set-segment-permissions", set_segment_permissions, "segments",
        "Change segment permissions (e.g. RWX, R-X, RW-).", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Any address within the segment."),
            Param("permissions", "str", required=True, positional=True,
                  help="Permission string like RWX, R-X, RW-."),
        ],
    ),
    Command(
        "set-segment-bitness", set_segment_bitness, "segments",
        "Change the addressing mode of a segment (16/32/64-bit).", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Any address within the segment."),
            Param("bitness", "int", required=True, positional=True,
                  help="Address size: 0=16-bit, 1=32-bit, 2=64-bit."),
        ],
    ),
    Command(
        "set-segment-class", set_segment_class, "segments",
        "Change the class of a segment (CODE/DATA/BSS/STACK/etc.).", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Any address within the segment."),
            Param("segment_class", "str", required=True, positional=True,
                  help="New class: CODE|DATA|BSS|STACK|etc."),
        ],
    ),
]
