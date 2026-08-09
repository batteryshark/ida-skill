#!/usr/bin/env python3
"""typeinf — local type library management: list/get/parse/delete/apply types.

Ported from re_mcp_ida/tools/typeinf.py into the idalib worker handler format.
All ``ida_*`` imports live inside handler bodies; each handler takes
``args: dict`` and returns a JSON-serializable dict. Paginated listings use
``paginate_iter``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    paginate_iter,
    resolve_address,
    safe_type_size,
)


def list_local_types(args: dict) -> dict:
    import ida_typeinf

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    def _iter():
        til = ida_typeinf.get_idati()
        count = ida_typeinf.get_ordinal_count(til)
        for ordinal in range(1, count + 1):
            name = ida_typeinf.get_numbered_type_name(til, ordinal)
            if not name:
                continue
            tinfo = ida_typeinf.tinfo_t()
            if tinfo.get_numbered_type(til, ordinal):
                yield {
                    "ordinal": ordinal,
                    "name": name,
                    "type": str(tinfo),
                    "size": safe_type_size(tinfo.get_size()),
                    "is_struct": tinfo.is_struct(),
                    "is_union": tinfo.is_union(),
                    "is_enum": tinfo.is_enum(),
                    "is_typedef": tinfo.is_typedef(),
                }

    return paginate_iter(_iter(), offset, limit)


def get_local_type(args: dict) -> dict:
    import ida_typeinf

    name = args["name"]
    til = ida_typeinf.get_idati()
    ordinal = ida_typeinf.get_type_ordinal(til, name)
    if ordinal == 0:
        raise IDAError(f"Type not found: {name}", error_type="NotFound")

    tinfo = ida_typeinf.tinfo_t()
    if not tinfo.get_numbered_type(til, ordinal):
        raise IDAError(f"Cannot load type: {name}", error_type="LoadFailed")

    is_struct = tinfo.is_struct()
    is_union = tinfo.is_union()

    members = None
    if is_struct or is_union:
        udt = ida_typeinf.udt_type_data_t()
        if tinfo.get_udt_details(udt):
            members = [
                {
                    "name": udt[i].name,
                    "type": str(udt[i].type),
                    "offset_bits": udt[i].offset,
                    "size_bits": udt[i].size,
                }
                for i in range(udt.size())
            ]

    return {
        "name": name,
        "ordinal": ordinal,
        "declaration": str(tinfo),
        "size": safe_type_size(tinfo.get_size()),
        "is_struct": is_struct,
        "is_union": is_union,
        "is_enum": tinfo.is_enum(),
        "members": members,
    }


def parse_type_declaration(args: dict) -> dict:
    import ida_typeinf

    declaration = args["declaration"]
    til = ida_typeinf.get_idati()

    # parse_decls saves named types (structs, enums, typedefs) to the TIL.
    # It returns the number of errors (0 = success).
    count_before = ida_typeinf.get_ordinal_count(til)
    num_errors = ida_typeinf.parse_decls(til, declaration, None, ida_typeinf.HTI_DCL)
    if num_errors:
        # Fall back: try parse_decl for anonymous/simple type expressions
        tinfo = ida_typeinf.tinfo_t()
        result = ida_typeinf.parse_decl(tinfo, til, declaration, ida_typeinf.PT_TYP)
        if result is None:
            raise IDAError("Failed to parse declaration", error_type="ParseError")
        return {
            "name": None,
            "ordinal": None,
            "declaration": str(tinfo),
            "size": safe_type_size(tinfo.get_size()),
            "saved": False,
            "message": "Anonymous type parsed but not saved to local types",
            "types": None,
        }

    # Find any newly added named types
    count_after = ida_typeinf.get_ordinal_count(til)
    new_types = []
    for ordinal in range(count_before + 1, count_after + 1):
        name = ida_typeinf.get_numbered_type_name(til, ordinal)
        if name:
            tinfo = ida_typeinf.tinfo_t()
            tinfo.get_numbered_type(til, ordinal)
            new_types.append(
                {
                    "name": name,
                    "ordinal": ordinal,
                    "declaration": str(tinfo),
                    "size": safe_type_size(tinfo.get_size()),
                }
            )

    if len(new_types) == 1:
        nt = new_types[0]
        return {
            "name": nt["name"],
            "ordinal": nt["ordinal"],
            "declaration": nt["declaration"],
            "size": nt["size"],
            "saved": True,
            "message": None,
            "types": None,
        }
    if new_types:
        return {
            "name": None,
            "ordinal": None,
            "declaration": None,
            "size": None,
            "saved": True,
            "message": None,
            "types": new_types,
        }

    # No new ordinals — type may have been merged with existing
    tinfo = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(tinfo, til, declaration, ida_typeinf.PT_TYP)
    return {
        "name": None,
        "ordinal": None,
        "declaration": str(tinfo),
        "size": safe_type_size(tinfo.get_size()),
        "saved": True,
        "message": "Parsed and saved (type may have merged with existing)",
        "types": None,
    }


def delete_local_type(args: dict) -> dict:
    import ida_typeinf

    name = args["name"]
    til = ida_typeinf.get_idati()
    ordinal = ida_typeinf.get_type_ordinal(til, name)
    if ordinal == 0:
        raise IDAError(f"Type not found: {name}", error_type="NotFound")

    tinfo = ida_typeinf.tinfo_t()
    old_declaration = ""
    if tinfo.get_numbered_type(til, ordinal):
        old_declaration = str(tinfo)

    if not ida_typeinf.del_numbered_type(til, ordinal):
        raise IDAError(f"Failed to delete type: {name}", error_type="DeleteFailed")
    return {
        "name": name,
        "ordinal": ordinal,
        "old_declaration": old_declaration,
    }


def delete_local_type_by_ordinal(args: dict) -> dict:
    import ida_typeinf

    ordinal = int(args["ordinal"])
    til = ida_typeinf.get_idati()
    count = ida_typeinf.get_ordinal_count(til)
    if ordinal < 1 or ordinal > count:
        raise IDAError(f"Ordinal {ordinal} out of range (1-{count})", error_type="NotFound")

    name = ida_typeinf.get_numbered_type_name(til, ordinal) or ""
    tinfo = ida_typeinf.tinfo_t()
    old_declaration = ""
    if tinfo.get_numbered_type(til, ordinal):
        old_declaration = str(tinfo)

    if not ida_typeinf.del_numbered_type(til, ordinal):
        raise IDAError(f"Failed to delete type at ordinal {ordinal}", error_type="DeleteFailed")
    return {
        "name": name,
        "ordinal": ordinal,
        "old_declaration": old_declaration,
    }


def apply_type_at_address(args: dict) -> dict:
    import ida_nalt
    import ida_typeinf

    ea = resolve_address(args["address"])
    type_name = args["type_name"]

    til = ida_typeinf.get_idati()
    tinfo = ida_typeinf.tinfo_t()

    # Try to find the type by name
    ordinal = ida_typeinf.get_type_ordinal(til, type_name)
    if ordinal == 0:
        raise IDAError(f"Type not found: {type_name}", error_type="NotFound")

    if not tinfo.get_numbered_type(til, ordinal):
        raise IDAError(f"Cannot load type: {type_name}", error_type="LoadFailed")

    old_tinfo = ida_typeinf.tinfo_t()
    old_type = ""
    if ida_nalt.get_tinfo(old_tinfo, ea):
        old_type = str(old_tinfo)

    if not ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE):
        raise IDAError(
            f"Failed to apply type {type_name!r} at {format_address(ea)}",
            error_type="ApplyTypeFailed",
        )
    return {
        "address": format_address(ea),
        "old_type": old_type,
        "type_name": type_name,
    }


COMMANDS = [
    Command(
        "list-local-types", list_local_types, "typeinf",
        "List Local Types (typedefs/enums/structs/funcs) with pagination.",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Maximum number of results."),
        ],
    ),
    Command(
        "get-local-type", get_local_type, "typeinf",
        "Get a local type's full declaration (members, sizes, kind) by name.",
        params=[
            Param("name", "str", required=True, positional=True,
                  help="Name of the local type."),
        ],
    ),
    Command(
        "parse-type-declaration", parse_type_declaration, "typeinf",
        "Parse a C declaration and register it as a Local Type.", mutates=True,
        params=[
            Param("declaration", "str", required=True, positional=True,
                  help="C type declaration (e.g. \"struct foo { int x; };\")."),
        ],
    ),
    Command(
        "delete-local-type", delete_local_type, "typeinf",
        "Delete a named local type from the database.", mutates=True,
        params=[
            Param("name", "str", required=True, positional=True,
                  help="Name of the local type to delete."),
        ],
    ),
    Command(
        "delete-local-type-by-ordinal", delete_local_type_by_ordinal, "typeinf",
        "Delete a Local Type by ordinal (for unnamed/anonymous types).", mutates=True,
        params=[
            Param("ordinal", "int", required=True, positional=True,
                  help="Ordinal number of the type to delete."),
        ],
    ),
    Command(
        "apply-type-at-address", apply_type_at_address, "typeinf",
        "Apply an already-defined local type at an address.", mutates=True,
        params=[
            Param("address", "str", required=True, positional=True,
                  help="Address to apply the type at."),
            Param("type_name", "str", required=True, positional=True,
                  help="Name of a type in the local type library."),
        ],
    ),
]
