#!/usr/bin/env python3
"""entry_manip — entry point manipulation.

Ported from re_mcp_ida/tools/entry_manip.py. Follows the handler contract (see
handlers/functions.py): ``ida_*`` imports live inside functions, each handler
takes ``args: dict`` and returns a JSON-serializable dict, failures raise
``IDAError``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import IDAError, format_address, resolve_address


def _resolve_entry(ordinal: int) -> int:
    """Resolve an entry point ordinal to its address. Raises on miss."""
    import ida_entry

    ea = ida_entry.get_entry(ordinal)
    if ea is None or ea == 0:
        raise IDAError(f"Entry point not found at ordinal {ordinal}", error_type="NotFound")
    return ea


def add_entry_point(args: dict) -> dict:
    import ida_entry

    ea = resolve_address(args["address"])
    name = args["name"]
    ordinal = int(args.get("ordinal", 0))
    make_code = bool(args.get("make_code", True))

    success = ida_entry.add_entry(ordinal, ea, name, make_code)
    if not success:
        raise IDAError(
            f"Failed to add entry point at {format_address(ea)}", error_type="AddFailed"
        )

    return {
        "address": format_address(ea),
        "name": name,
        "ordinal": ordinal,
    }


def rename_entry_point(args: dict) -> dict:
    import ida_entry

    ordinal = int(args["ordinal"])
    name = args["name"]
    ea = _resolve_entry(ordinal)

    old_name = ida_entry.get_entry_name(ordinal) or ""
    success = ida_entry.rename_entry(ordinal, name)
    if not success:
        raise IDAError(
            f"Failed to rename entry point at ordinal {ordinal}", error_type="RenameFailed"
        )

    return {
        "ordinal": ordinal,
        "address": format_address(ea),
        "old_name": old_name,
        "new_name": name,
    }


def set_entry_forwarder(args: dict) -> dict:
    import ida_entry

    ordinal = int(args["ordinal"])
    name = args["name"]
    ea = _resolve_entry(ordinal)

    old_forwarder = ida_entry.get_entry_forwarder(ordinal) or ""
    success = ida_entry.set_entry_forwarder(ordinal, name)
    if not success:
        raise IDAError(
            f"Failed to set forwarder for entry point at ordinal {ordinal}",
            error_type="SetFailed",
        )

    return {
        "ordinal": ordinal,
        "address": format_address(ea),
        "old_forwarder": old_forwarder,
        "forwarder": name,
    }


def get_entry_forwarder(args: dict) -> dict:
    import ida_entry

    ordinal = int(args["ordinal"])
    ea = _resolve_entry(ordinal)

    forwarder = ida_entry.get_entry_forwarder(ordinal) or ""
    return {
        "ordinal": ordinal,
        "address": format_address(ea),
        "name": ida_entry.get_entry_name(ordinal) or "",
        "forwarder": forwarder,
    }


COMMANDS = [
    Command(
        "add-entry-point", add_entry_point, "entry",
        "Register a new entry point at an address (does not rename existing).",
        mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address of the entry point."),
            Param("name", "str", required=True, positional=True,
                  help="Name for the entry point."),
            Param("ordinal", "int", default=0, help="Ordinal number (0 to auto-assign)."),
            Param("make_code", "bool", default=True,
                  help="Whether to mark the address as code."),
        ],
    ),
    Command(
        "rename-entry-point", rename_entry_point, "entry",
        "Rename an entry point's symbol by ordinal.", mutates=True,
        params=[
            Param("ordinal", "int", required=True, positional=True,
                  help="Ordinal number of the entry point."),
            Param("name", "str", required=True, positional=True,
                  help="New name for the entry point."),
        ],
    ),
    Command(
        "set-entry-forwarder", set_entry_forwarder, "entry",
        "Set a forwarder name for an entry point.", mutates=True,
        params=[
            Param("ordinal", "int", required=True, positional=True,
                  help="Ordinal number of the entry point."),
            Param("name", "str", required=True, positional=True,
                  help="Forwarder name string."),
        ],
    ),
    Command(
        "get-entry-forwarder", get_entry_forwarder, "entry",
        "Get the forwarder name for an entry point.",
        params=[Param("ordinal", "int", required=True, positional=True,
                      help="Ordinal number of the entry point.")],
    ),
]
