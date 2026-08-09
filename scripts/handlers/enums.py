#!/usr/bin/env python3
"""enums — enum creation and management.

Ported from re_mcp_ida/tools/enums.py into the standalone idalib worker's
handler format: each handler takes ``args: dict`` and returns a
JSON-serializable dict; all ``ida_*`` imports live inside function bodies.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    is_bad_addr,
    paginate,
    paginate_iter,
)


def _get_enum_tif(name: str):
    """Load enum tinfo_t and enum_type_data_t by name.

    Raises :class:`IDAError` if the enum is not found or cannot be loaded.
    """
    import ida_typeinf

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        raise IDAError(f"Enum not found: {name}", error_type="NotFound")
    if not tif.is_enum():
        raise IDAError(f"Not an enum: {name}", error_type="NotFound")
    edt = ida_typeinf.enum_type_data_t()
    if not tif.get_enum_details(edt):
        raise IDAError(f"Cannot get enum details: {name}", error_type="InternalError")
    return tif, edt


def _find_member_by_value(edt, value: int, enum_name: str) -> int:
    """Find an enum member index by value.  Raises :class:`IDAError` if not found."""
    idx = next((i for i in range(len(edt)) if edt[i].value == value), -1)
    if idx == -1:
        raise IDAError(f"No member with value {value} in {enum_name}", error_type="NotFound")
    return idx


def _save_enum(tif, edt, name: str) -> None:
    """Rebuild tif from modified edt and save.  Raises :class:`IDAError` on failure."""
    import ida_typeinf

    is_bf = edt.is_bf()
    if not tif.create_enum(edt):
        raise IDAError("Failed to rebuild enum type", error_type="InternalError")
    if is_bf:
        tif.set_enum_is_bitmask(ida_typeinf.tinfo_t.ENUMBM_ON)
    result = tif.set_named_type(None, name, ida_typeinf.NTF_REPLACE)
    if result != ida_typeinf.TERR_OK:
        raise IDAError(f"Failed to save enum (error {result})", error_type="SaveFailed")


def list_enums(args: dict) -> dict:
    import ida_typeinf

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    def _iter():
        limit_ord = ida_typeinf.get_ordinal_limit()
        for ordinal in range(1, limit_ord):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(None, ordinal) and tif.is_enum():
                name = tif.get_type_name() or ""
                edt = ida_typeinf.enum_type_data_t()
                bitfield = tif.get_enum_details(edt) and edt.is_bf()
                yield {
                    "ordinal": ordinal,
                    "name": name,
                    "member_count": tif.get_enum_nmembers(),
                    "bitfield": bool(bitfield),
                }

    return paginate_iter(_iter(), offset, limit)


def create_enum(args: dict) -> dict:
    import ida_typeinf

    name = args["name"]
    bitfield = bool(args.get("bitfield", False))

    existing = ida_typeinf.get_named_type_tid(name)
    if not is_bad_addr(existing):
        raise IDAError(f"Type already exists: {name}", error_type="AlreadyExists")

    edt = ida_typeinf.enum_type_data_t()
    tid = ida_typeinf.create_enum_type(name, edt, 0, ida_typeinf.no_sign, bitfield)
    if is_bad_addr(tid):
        raise IDAError(f"Failed to create enum: {name}", error_type="CreateFailed")

    return {"name": name, "bitfield": bitfield}


def delete_enum(args: dict) -> dict:
    import ida_typeinf

    name = args["name"]
    tif, edt = _get_enum_tif(name)

    old_member_count = len(edt)
    ordinal = tif.get_ordinal()
    if not ida_typeinf.del_numbered_type(None, ordinal):
        raise IDAError(f"Failed to delete enum: {name}", error_type="DeleteFailed")
    return {"name": name, "old_member_count": old_member_count}


def add_enum_member(args: dict) -> dict:
    import ida_typeinf

    enum_name = args["enum_name"]
    member_name = args["member_name"]
    value = int(args["value"])

    tif, edt = _get_enum_tif(enum_name)

    for i in range(len(edt)):
        if edt[i].name == member_name:
            raise IDAError(f"Member already exists: {member_name}", error_type="AlreadyExists")

    edt.push_back(ida_typeinf.edm_t(member_name, value))

    _save_enum(tif, edt, enum_name)
    return {"enum": enum_name, "member": member_name, "value": value}


def get_enum_members(args: dict) -> dict:
    enum_name = args["enum_name"]
    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    _tif, edt = _get_enum_tif(enum_name)

    members = [{"name": edt[i].name or "", "value": edt[i].value} for i in range(len(edt))]
    return paginate(members, offset, limit)


def rename_enum(args: dict) -> dict:
    import ida_typeinf

    old_name = args["old_name"]
    new_name = args["new_name"]

    tif, _edt = _get_enum_tif(old_name)

    result = tif.rename_type(new_name)
    if result != ida_typeinf.TERR_OK:
        raise IDAError(
            f"Failed to rename enum {old_name!r} to {new_name!r}", error_type="RenameFailed"
        )
    return {"old_name": old_name, "new_name": new_name}


def delete_enum_member(args: dict) -> dict:
    import ida_typeinf

    enum_name = args["enum_name"]
    value = int(args["value"])

    tif, edt = _get_enum_tif(enum_name)

    idx = _find_member_by_value(edt, value, enum_name)

    member_name = edt[idx].name or ""
    # Python SWIG doesn't support C++ iterator arithmetic; rebuild without the member.
    new_edt = ida_typeinf.enum_type_data_t()
    for i in range(len(edt)):
        if i != idx:
            new_edt.push_back(edt[i])
    edt = new_edt

    _save_enum(tif, edt, enum_name)
    return {"enum": enum_name, "member": member_name, "value": value}


def rename_enum_member(args: dict) -> dict:
    enum_name = args["enum_name"]
    value = int(args["value"])
    new_name = args["new_name"]

    tif, edt = _get_enum_tif(enum_name)

    idx = _find_member_by_value(edt, value, enum_name)

    old_name = edt[idx].name or ""
    edt[idx].name = new_name

    _save_enum(tif, edt, enum_name)
    return {"enum": enum_name, "old_name": old_name, "new_name": new_name, "value": value}


def set_enum_member_comment(args: dict) -> dict:
    enum_name = args["enum_name"]
    value = int(args["value"])
    comment = args["comment"]

    tif, edt = _get_enum_tif(enum_name)

    idx = _find_member_by_value(edt, value, enum_name)

    old_comment = edt[idx].cmt or ""
    edt[idx].cmt = comment

    _save_enum(tif, edt, enum_name)
    return {"enum": enum_name, "value": value, "old_comment": old_comment, "comment": comment}


COMMANDS = [
    Command(
        "list-enums", list_enums, "enums",
        "List all enums (names, member counts, bitfield status).",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Max results."),
        ],
    ),
    Command(
        "create-enum", create_enum, "enums",
        "Create a new enum type (optionally as a bitfield).", mutates=True,
        params=[
            Param("name", "str", required=True, positional=True, help="Name for the enum."),
            Param("bitfield", "bool", default=False, help="Create as bitfield enum."),
        ],
    ),
    Command(
        "delete-enum", delete_enum, "enums",
        "Delete an enum by name.", mutates=True,
        params=[
            Param("name", "str", required=True, positional=True,
                  help="Name of the enum to delete."),
        ],
    ),
    Command(
        "add-enum-member", add_enum_member, "enums",
        "Add a member to an enum.", mutates=True,
        params=[
            Param("enum_name", "str", required=True, positional=True, help="Name of the enum."),
            Param("member_name", "str", required=True, positional=True,
                  help="Name for the new member."),
            Param("value", "int", required=True, positional=True,
                  help="Integer value for the member."),
        ],
    ),
    Command(
        "get-enum-members", get_enum_members, "enums",
        "List all members of an enum.",
        params=[
            Param("enum_name", "str", required=True, positional=True, help="Name of the enum."),
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Max results."),
        ],
    ),
    Command(
        "rename-enum", rename_enum, "enums",
        "Rename an enum.", mutates=True,
        params=[
            Param("old_name", "str", required=True, positional=True,
                  help="Current name of the enum."),
            Param("new_name", "str", required=True, positional=True,
                  help="New name for the enum."),
        ],
    ),
    Command(
        "delete-enum-member", delete_enum_member, "enums",
        "Delete a member from an enum by its value.", mutates=True,
        params=[
            Param("enum_name", "str", required=True, positional=True, help="Name of the enum."),
            Param("value", "int", required=True, positional=True,
                  help="Integer value of the member to delete."),
        ],
    ),
    Command(
        "rename-enum-member", rename_enum_member, "enums",
        "Rename an enum member.", mutates=True,
        params=[
            Param("enum_name", "str", required=True, positional=True, help="Name of the enum."),
            Param("value", "int", required=True, positional=True,
                  help="Integer value of the member to rename."),
            Param("new_name", "str", required=True, positional=True,
                  help="New name for the member."),
        ],
    ),
    Command(
        "set-enum-member-comment", set_enum_member_comment, "enums",
        "Set a comment on an enum member.", mutates=True,
        params=[
            Param("enum_name", "str", required=True, positional=True, help="Name of the enum."),
            Param("value", "int", required=True, positional=True,
                  help="Integer value of the member."),
            Param("comment", "str", required=True, positional=True, help="Comment text."),
        ],
    ),
]
