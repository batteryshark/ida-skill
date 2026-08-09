#!/usr/bin/env python3
"""colors — address, function, and segment background coloring tools.

Ported from re_mcp_ida/tools/colors.py.

Follows the handler contract (see handlers/functions.py):

  * All ``ida_*``/``idc`` imports live INSIDE handler functions.
  * Each handler takes ``args: dict`` and returns a JSON-serializable dict.
  * Failures raise ``IDAError(msg, error_type=...)``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import IDAError, format_address, resolve_address


def _what_map() -> dict:
    """Lazy map of color-target name -> IDA CIC_* constant."""
    import idc

    return {
        "item": idc.CIC_ITEM,
        "func": idc.CIC_FUNC,
        "segm": idc.CIC_SEGM,
    }


def _swap_rb(color: int) -> int:
    """Swap red and blue channels (RGB <-> BGR)."""
    return ((color & 0xFF) << 16) | (color & 0xFF00) | ((color >> 16) & 0xFF)


def set_color(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    color = args.get("color", "")
    what = args.get("what", "item") or "item"

    what_val_map = _what_map()
    what_val = what_val_map.get(what)
    if what_val is None:
        raise IDAError(
            f"Invalid 'what' value: {what!r}",
            error_type="InvalidArgument",
            valid_values=list(what_val_map),
        )

    if color == "":
        color_val = 0xFFFFFFFF  # DEFCOLOR — removes color
    else:
        color = color.removeprefix("#")
        if len(color) != 6:
            raise IDAError(
                f"Color must be 6 hex digits (RRGGBB), got {color!r}",
                error_type="InvalidArgument",
            )
        try:
            rgb = int(color, 16)
        except ValueError:
            raise IDAError(f"Invalid color: {color!r}", error_type="InvalidArgument") from None
        # IDA uses BGR format internally
        color_val = _swap_rb(rgb)

    old_color_val = idc.get_color(ea, what_val)
    old_color = None if old_color_val == 0xFFFFFFFF else f"{_swap_rb(old_color_val):06X}"

    result = idc.set_color(ea, what_val, color_val)
    # CIC_ITEM always succeeds (void C function, returns None).
    # CIC_FUNC/CIC_SEGM return False when the address has no function/segment.
    if result is False:
        raise IDAError(
            f"Failed to set color at {format_address(ea)}", error_type="SetColorFailed"
        )
    return {
        "address": format_address(ea),
        "old_color": old_color,
        "color": color or "default",
        "what": what,
    }


def get_color(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    what = args.get("what", "item") or "item"

    what_val_map = _what_map()
    what_val = what_val_map.get(what)
    if what_val is None:
        raise IDAError(
            f"Invalid 'what' value: {what!r}",
            error_type="InvalidArgument",
            valid_values=list(what_val_map),
        )

    color_val = idc.get_color(ea, what_val)
    if color_val == 0xFFFFFFFF:
        return {
            "address": format_address(ea),
            "what": what,
            "color": None,
            "has_color": False,
        }

    # Convert from IDA BGR to RGB
    rgb = f"{_swap_rb(color_val):06X}"

    return {
        "address": format_address(ea),
        "what": what,
        "color": rgb,
        "has_color": True,
    }


COMMANDS = [
    Command(
        "set-color", set_color, "colors",
        "Set the background color of an address, function, or segment.",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="The address to colorize."),
            Param("color", "str", default="",
                  help='Hex RGB (e.g. "FF0000"); empty string removes color.'),
            Param("what", "str", default="item",
                  help='"item" (address), "func" (function), or "segm" (segment).'),
        ],
    ),
    Command(
        "get-color", get_color, "colors",
        "Get the background color of an address, function, or segment.",
        params=[
            Param("address", "str", required=True, positional=True,
                  help="The address to query."),
            Param("what", "str", default="item",
                  help='"item", "func", or "segm".'),
        ],
    ),
]
