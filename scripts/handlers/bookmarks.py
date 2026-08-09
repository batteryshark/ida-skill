#!/usr/bin/env python3
"""bookmarks — marked position (bookmark) tools.

Ported from re_mcp_ida/tools/bookmarks.py.

Follows the handler contract (see handlers/functions.py):

  * All ``ida_*``/``idc`` imports live INSIDE handler functions.
  * Each handler takes ``args: dict`` and returns a JSON-serializable dict.
  * Failures raise ``IDAError(msg, error_type=...)``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    is_bad_addr,
    paginate_iter,
    resolve_address,
)

# IDA supports bookmark slots 1..1024.
_MAX_BOOKMARK_SLOT = 1024


def set_bookmark(args: dict) -> dict:
    import idc

    ea = resolve_address(args["address"])
    description = args.get("description", "") or ""
    slot = int(args.get("slot", -1))

    if slot != -1 and (slot < 1 or slot > _MAX_BOOKMARK_SLOT):
        raise IDAError(
            f"Bookmark slot {slot} out of range (1..{_MAX_BOOKMARK_SLOT})",
            error_type="InvalidArgument",
        )

    if slot == -1:
        # Find first free slot
        for i in range(1, _MAX_BOOKMARK_SLOT + 1):
            bm = idc.get_bookmark(i)
            if bm is None or is_bad_addr(bm):
                slot = i
                break
        else:
            raise IDAError("No free bookmark slots", error_type="NoSlot")

    old_ea = idc.get_bookmark(slot)
    old_description = ""
    if old_ea is not None and not is_bad_addr(old_ea):
        old_description = idc.get_bookmark_desc(slot) or ""

    idc.put_bookmark(ea, 0, 0, 0, slot, description)
    return {
        "address": format_address(ea),
        "slot": slot,
        "old_description": old_description,
        "description": description,
    }


def get_bookmarks(args: dict) -> dict:
    import idc

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    def _iter():
        for i in range(1, _MAX_BOOKMARK_SLOT + 1):
            ea = idc.get_bookmark(i)
            if ea is not None and not is_bad_addr(ea):
                desc = idc.get_bookmark_desc(i)
                yield {
                    "slot": i,
                    "address": format_address(ea),
                    "description": desc or "",
                }

    return paginate_iter(_iter(), offset, limit)


def delete_bookmark(args: dict) -> dict:
    import idc

    slot = int(args["slot"])
    if slot < 1 or slot > _MAX_BOOKMARK_SLOT:
        raise IDAError(
            f"Bookmark slot {slot} out of range (1..{_MAX_BOOKMARK_SLOT})",
            error_type="InvalidArgument",
        )

    ea = idc.get_bookmark(slot)
    if ea is None or is_bad_addr(ea):
        raise IDAError(f"No bookmark in slot {slot}", error_type="NotFound")

    old_description = idc.get_bookmark_desc(slot) or ""
    idc.put_bookmark(0, 0, 0, 0, slot, "")
    return {
        "slot": slot,
        "address": format_address(ea),
        "old_description": old_description,
    }


COMMANDS = [
    Command(
        "set-bookmark", set_bookmark, "bookmarks",
        "Set a bookmark (marked position) at an address.", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address to bookmark."),
            Param("description", "str", default="", help="Bookmark description."),
            Param("slot", "int", default=-1,
                  help="Slot 1-1024, or -1 to auto-assign first free slot."),
        ],
    ),
    Command(
        "get-bookmarks", get_bookmarks, "bookmarks",
        "List all bookmarks (marked positions) in the database.",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Max results."),
        ],
    ),
    Command(
        "delete-bookmark", delete_bookmark, "bookmarks",
        "Delete a bookmark by slot number.", mutates=True,
        params=[
            Param("slot", "int", required=True, positional=True,
                  help="Bookmark slot number to delete."),
        ],
    ),
]
