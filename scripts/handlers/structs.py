#!/usr/bin/env python3
"""structs — structure/union creation, inspection, and member modification.

Ported from re_mcp_ida/tools/structs.py into the idalib worker handler format.
All ``ida_*``/``idc``/``idautils`` imports live inside handler bodies; each
handler takes ``args: dict`` and returns a JSON-serializable dict. Paginated
listings use ``paginate_iter``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    is_bad_addr,
    paginate_iter,
    parse_type,
    resolve_struct,
)


def _resolve_member_offset(sid: int, member_name: str) -> int:
    """Find a struct member by name.  Raises :class:`IDAError` if not found."""
    import idc

    offset = idc.get_member_offset(sid, member_name)
    if offset == -1:
        raise IDAError(f"Member not found: {member_name}", error_type="NotFound")
    return offset


def list_structures(args: dict) -> dict:
    import idautils
    import idc

    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))

    def _iter():
        for idx, sid, name in idautils.Structs():
            yield {
                "index": idx,
                "name": name,
                "id": sid,
                "size": idc.get_struc_size(sid),
                "member_count": idc.get_member_qty(sid),
                "is_union": idc.is_union(sid),
            }

    return paginate_iter(_iter(), offset, limit)


def get_structure(args: dict) -> dict:
    import idautils
    import idc

    name = args["name"]
    sid = resolve_struct(name)

    members = []
    for member_offset, member_name, member_size in idautils.StructMembers(sid):
        members.append(
            {
                "offset": member_offset,
                "name": member_name,
                "size": member_size,
            }
        )

    return {
        "name": name,
        "id": sid,
        "size": idc.get_struc_size(sid),
        "member_count": len(members),
        "members": members,
    }


def create_structure(args: dict) -> dict:
    import idc

    name = args["name"]
    is_union = bool(args.get("is_union", False))
    sid = idc.get_struc_id(name)
    if not is_bad_addr(sid):
        raise IDAError(f"Structure already exists: {name}", error_type="AlreadyExists")

    sid = idc.add_struc(idc.BADADDR, name, is_union)
    if is_bad_addr(sid):
        raise IDAError(f"Failed to create structure: {name}", error_type="CreateFailed")

    return {"name": name, "id": sid, "is_union": is_union}


def delete_structure(args: dict) -> dict:
    import idc

    name = args["name"]
    sid = resolve_struct(name)

    old_size = idc.get_struc_size(sid)
    old_member_count = idc.get_member_qty(sid)
    if not idc.del_struc(sid):
        raise IDAError(f"Failed to delete structure: {name}", error_type="DeleteFailed")
    return {"name": name, "old_size": old_size, "old_member_count": old_member_count}


def add_struct_member(args: dict) -> dict:
    import idc

    struct_name = args["struct_name"]
    member_name = args["member_name"]
    offset = int(args.get("offset", -1))
    size = int(args.get("size", 1))
    type_str = args.get("type_str", "") or ""

    sid = resolve_struct(struct_name)

    flag_map = {1: idc.FF_BYTE, 2: idc.FF_WORD, 4: idc.FF_DWORD, 8: idc.FF_QWORD}
    flag = flag_map.get(size)
    if flag is None:
        raise IDAError(
            f"Invalid member size: {size}. Must be 1, 2, 4, or 8.", error_type="InvalidArgument"
        )
    flags = flag | idc.FF_DATA

    if offset == -1:
        offset = idc.get_struc_size(sid) or 0

    err_code = idc.add_struc_member(sid, member_name, offset, flags, -1, size)
    if err_code != 0:
        raise IDAError(f"Failed to add member (error {err_code})", error_type="AddMemberFailed")

    if type_str:
        mid = idc.get_member_id(sid, offset)
        if mid != -1 and not idc.SetType(mid, type_str):
            raise IDAError(
                f"Member added but failed to set type {type_str!r}", error_type="SetTypeFailed"
            )

    return {"struct": struct_name, "member": member_name, "offset": offset, "size": size}


def rename_struct_member(args: dict) -> dict:
    import idc

    struct_name = args["struct_name"]
    old_name = args["old_name"]
    new_name = args["new_name"]

    sid = resolve_struct(struct_name)
    member_offset = _resolve_member_offset(sid, old_name)

    if not idc.set_member_name(sid, member_offset, new_name):
        raise IDAError(
            f"Failed to rename member {old_name!r} to {new_name!r}", error_type="RenameFailed"
        )
    return {"struct": struct_name, "old_name": old_name, "new_name": new_name}


def delete_struct_member(args: dict) -> dict:
    import idc

    struct_name = args["struct_name"]
    member_name = args["member_name"]

    sid = resolve_struct(struct_name)
    member_offset = _resolve_member_offset(sid, member_name)

    old_size = idc.get_member_size(sid, member_offset) or 0
    if not idc.del_struc_member(sid, member_offset):
        raise IDAError(f"Failed to delete member {member_name!r}", error_type="DeleteFailed")
    return {"struct": struct_name, "member": member_name, "old_size": old_size}


def retype_struct_member(args: dict) -> dict:
    import idc

    struct_name = args["struct_name"]
    member_name = args["member_name"]
    type_str = args["type_str"]

    sid = resolve_struct(struct_name)
    member_offset = _resolve_member_offset(sid, member_name)

    mid = idc.get_member_id(sid, member_offset)
    if mid == -1:
        raise IDAError(f"Cannot resolve member ID for {member_name!r}", error_type="NotFound")

    old_type = idc.get_type(mid) or ""

    tinfo = parse_type(type_str)

    if not idc.SetType(mid, type_str):
        raise IDAError(f"Failed to set type on {member_name!r}", error_type="RetypeFailed")

    return {
        "struct": struct_name,
        "member": member_name,
        "old_type": old_type,
        "type": str(tinfo),
    }


def set_struct_member_comment(args: dict) -> dict:
    import idc

    struct_name = args["struct_name"]
    member_name = args["member_name"]
    comment = args["comment"]
    repeatable = bool(args.get("repeatable", False))

    sid = resolve_struct(struct_name)
    member_offset = _resolve_member_offset(sid, member_name)

    old_comment = idc.get_member_cmt(sid, member_offset, repeatable) or ""
    if not idc.set_member_cmt(sid, member_offset, comment, repeatable):
        raise IDAError(
            f"Failed to set comment on member {member_name!r}", error_type="SetCommentFailed"
        )
    return {
        "struct": struct_name,
        "member": member_name,
        "old_comment": old_comment,
        "comment": comment,
        "repeatable": repeatable,
    }


COMMANDS = [
    Command(
        "list-structures", list_structures, "structs",
        "List structs/unions (names, sizes, member counts) with pagination.",
        params=[
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Maximum number of results."),
        ],
    ),
    Command(
        "get-structure", get_structure, "structs",
        "Return ONE struct/union with all members (offsets, sizes).",
        params=[
            Param("name", "str", required=True, positional=True,
                  help="Name of the structure."),
        ],
    ),
    Command(
        "create-structure", create_structure, "structs",
        "Create a new structure or union.", mutates=True,
        params=[
            Param("name", "str", required=True, positional=True,
                  help="Name for the new structure."),
            Param("is_union", "bool", default=False,
                  help="If set, create a union instead of a struct."),
        ],
    ),
    Command(
        "delete-structure", delete_structure, "structs",
        "Delete ONE struct/union by name.", mutates=True,
        params=[
            Param("name", "str", required=True, positional=True,
                  help="Name of the structure to delete."),
        ],
    ),
    Command(
        "add-struct-member", add_struct_member, "structs",
        "Add a member to an existing structure.", mutates=True,
        params=[
            Param("struct_name", "str", required=True, positional=True,
                  help="Name of the structure."),
            Param("member_name", "str", required=True, positional=True,
                  help="Name for the new member."),
            Param("offset", "int", default=-1, help="Byte offset (-1 to append at end)."),
            Param("size", "int", default=1, help="Size in bytes (1, 2, 4, or 8)."),
            Param("type_str", "str", default="", help="Optional C type string for the member."),
        ],
    ),
    Command(
        "rename-struct-member", rename_struct_member, "structs",
        "Rename a member of a structure.", mutates=True,
        params=[
            Param("struct_name", "str", required=True, positional=True,
                  help="Name of the structure."),
            Param("old_name", "str", required=True, positional=True,
                  help="Current name of the member."),
            Param("new_name", "str", required=True, positional=True,
                  help="New name for the member."),
        ],
    ),
    Command(
        "delete-struct-member", delete_struct_member, "structs",
        "Delete a member from a structure.", mutates=True,
        params=[
            Param("struct_name", "str", required=True, positional=True,
                  help="Name of the structure."),
            Param("member_name", "str", required=True, positional=True,
                  help="Name of the member to delete."),
        ],
    ),
    Command(
        "retype-struct-member", retype_struct_member, "structs",
        "Change the type of a structure member.", mutates=True,
        params=[
            Param("struct_name", "str", required=True, positional=True,
                  help="Name of the structure."),
            Param("member_name", "str", required=True, positional=True,
                  help="Name of the member to retype."),
            Param("type_str", "str", required=True, positional=True,
                  help="C type string (e.g. \"int\", \"char *\")."),
        ],
    ),
    Command(
        "set-struct-member-comment", set_struct_member_comment, "structs",
        "Set a comment on a structure member.", mutates=True,
        params=[
            Param("struct_name", "str", required=True, positional=True,
                  help="Name of the structure."),
            Param("member_name", "str", required=True, positional=True,
                  help="Name of the member."),
            Param("comment", "str", required=True, positional=True, help="Comment text."),
            Param("repeatable", "bool", default=False,
                  help="If set, set as repeatable comment."),
        ],
    ),
]
