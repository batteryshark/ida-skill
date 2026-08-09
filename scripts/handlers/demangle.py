#!/usr/bin/env python3
"""demangle — C++ symbol demangling and demangled-name listing.

Ported from re_mcp_ida/tools/demangle.py. See handlers/functions.py for the
reference template conventions.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    compile_filter,
    format_address,
    paginate_iter,
    resolve_address,
)


def demangle_name(args: dict) -> dict:
    import ida_name

    name = args["name"]
    disable_mask = int(args.get("disable_mask", 0))

    result = ida_name.demangle_name(name, disable_mask)
    if result is None or result == name:
        return {
            "name": name,
            "demangled": None,
            "is_mangled": False,
        }
    return {
        "name": name,
        "demangled": result,
        "is_mangled": True,
    }


def demangle_at_address(args: dict) -> dict:
    import ida_name

    ea = resolve_address(args["address"])

    name = ida_name.get_name(ea)
    if not name:
        return {
            "address": format_address(ea),
            "name": None,
            "demangled": None,
            "is_mangled": False,
        }

    demangled = ida_name.demangle_name(name, 0)
    return {
        "address": format_address(ea),
        "name": name,
        "demangled": demangled if demangled and demangled != name else None,
        "is_mangled": demangled is not None and demangled != name,
    }


def list_demangled_names(args: dict) -> dict:
    import ida_name
    import idautils

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))
    pattern = compile_filter(args.get("filter_pattern", ""))

    def _iter():
        for ea, name in idautils.Names():
            demangled = ida_name.demangle_name(name, 0)
            if not demangled or demangled == name:
                continue
            if pattern and not pattern.search(demangled):
                continue
            yield {
                "address": format_address(ea),
                "mangled": name,
                "demangled": demangled,
            }

    return paginate_iter(_iter(), offset, limit)


COMMANDS = [
    Command(
        "demangle-name", demangle_name, "demangle",
        "Demangle a C++ symbol name to readable form.",
        params=[
            Param("name", "str", required=True, positional=True,
                  help="The mangled symbol name."),
            Param("disable_mask", "int", default=0,
                  help="Bitmask of demangler features to disable (0 default)."),
        ],
    ),
    Command(
        "demangle-at-address", demangle_at_address, "demangle",
        "Demangle the symbol name at a given address.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or symbol name to demangle.")],
    ),
    Command(
        "list-demangled-names", list_demangled_names, "demangle",
        "List named addresses with demangled forms (C++ only), regex-filterable.",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Max results."),
            Param("filter_pattern", "str", default="",
                  help="Regex over demangled names."),
        ],
    ),
]
