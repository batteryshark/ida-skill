#!/usr/bin/env python3
"""database — metadata/query/flag tools for the open database.

Ported from re_mcp_ida/tools/database.py. Only the metadata/query/flag tools
are ported here; the worker owns the open/close/save/list/wait lifecycle as
built-ins.

Follows the handler contract (see handlers/functions.py):

  * All ``ida_*`` imports live INSIDE handler functions.
  * Each handler takes ``args: dict`` and returns a JSON-serializable dict.
  * Failures raise ``IDAError(msg, error_type=...)``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    format_address,
    is_bad_addr,
    resolve_address,
    session,
)

_DBFL_NAMES = ("kill", "compress", "backup", "temporary")


def get_database_info(args: dict) -> dict:
    import ida_funcs
    import ida_hexrays
    import ida_ida
    import ida_idp
    import ida_segment

    bitness = 64 if ida_ida.inf_is_64bit() else ida_ida.inf_get_app_bitness()
    return {
        "file_path": session.current_path,
        "processor": ida_idp.get_idp_name(),
        "bitness": bitness,
        "min_address": format_address(ida_ida.inf_get_min_ea()),
        "max_address": format_address(ida_ida.inf_get_max_ea()),
        "entry_point": format_address(ida_ida.inf_get_start_ea()),
        "function_count": ida_funcs.get_func_qty(),
        "segment_count": ida_segment.get_segm_qty(),
        "decompiler_available": bool(ida_hexrays.init_hexrays_plugin()),
    }


def get_database_paths(args: dict) -> dict:
    import ida_loader

    return {
        "input_file": ida_loader.get_path(ida_loader.PATH_TYPE_CMD),
        "idb_path": ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
        "id0_path": ida_loader.get_path(ida_loader.PATH_TYPE_ID0),
    }


def get_database_flags(args: dict) -> dict:
    import ida_loader

    return {
        "kill": bool(ida_loader.is_database_flag(ida_loader.DBFL_KILL)),
        "compress": bool(ida_loader.is_database_flag(ida_loader.DBFL_COMP)),
        "backup": bool(ida_loader.is_database_flag(ida_loader.DBFL_BAK)),
        "temporary": bool(ida_loader.is_database_flag(ida_loader.DBFL_TEMP)),
    }


def set_database_flag(args: dict) -> dict:
    import ida_loader

    dbfl_map = {
        "kill": ida_loader.DBFL_KILL,
        "compress": ida_loader.DBFL_COMP,
        "backup": ida_loader.DBFL_BAK,
        "temporary": ida_loader.DBFL_TEMP,
    }
    flag = args["flag"]
    value = bool(args.get("value", True))
    dbfl = dbfl_map.get(flag.lower())
    if dbfl is None:
        raise IDAError(
            f"Unknown flag: {flag!r}. Valid: {', '.join(dbfl_map)}",
            error_type="InvalidArgument",
        )
    ida_loader.set_database_flag(dbfl, value)
    return {"flag": flag, "value": value}


def flush_buffers(args: dict) -> dict:
    import ida_loader

    ida_loader.flush_buffers()
    return {"status": "flushed"}


def get_fileregion_ea(args: dict) -> dict:
    import ida_loader

    file_offset = int(args["file_offset"])
    ea = ida_loader.get_fileregion_ea(file_offset)
    if is_bad_addr(ea):
        raise IDAError(
            f"No address mapped for file offset {file_offset}", error_type="NotFound"
        )
    return {"file_offset": file_offset, "address": format_address(ea)}


def get_fileregion_offset(args: dict) -> dict:
    import ida_loader

    ea = resolve_address(args["address"])
    offset = ida_loader.get_fileregion_offset(ea)
    if offset == -1:
        raise IDAError(
            f"No file offset for address {format_address(ea)}", error_type="NotFound"
        )
    return {"address": format_address(ea), "file_offset": offset}


def get_elf_debug_file_directory(args: dict) -> dict:
    import ida_loader

    return {"directory": ida_loader.get_elf_debug_file_directory()}


def reload_file(args: dict) -> dict:
    import ida_loader

    path = ida_loader.get_path(ida_loader.PATH_TYPE_CMD)
    result = ida_loader.reload_file(path, bool(args.get("is_remote", False)))
    if not result:
        raise IDAError("Failed to reload file", error_type="ReloadFailed")
    return {"status": "reloaded", "path": path}


COMMANDS = [
    Command(
        "get-database-info", get_database_info, "database",
        "Database metadata: arch, bitness, address range, counts, decompiler.",
        params=[],
        aliases=["info"],
    ),
    Command(
        "get-database-paths", get_database_paths, "database",
        "File paths for the current database (input file, IDB, ID0).",
        params=[],
    ),
    Command(
        "get-database-flags", get_database_flags, "database",
        "Database flags (kill, compress, backup, temporary).",
        params=[],
    ),
    Command(
        "set-database-flag", set_database_flag, "database",
        "Set or clear a database flag (kill/compress/backup/temporary).",
        mutates=True,
        params=[
            Param("flag", "str", required=True, positional=True,
                  help="Flag name: kill|compress|backup|temporary."),
            Param("value", "bool", default=True, help="True to set, False to clear."),
        ],
    ),
    Command(
        "flush-buffers", flush_buffers, "database",
        "Flush IDA's internal byte buffers to disk without a full save.",
        mutates=True,
        params=[],
    ),
    Command(
        "get-fileregion-ea", get_fileregion_ea, "database",
        "Map a byte offset in the input file to its loaded address.",
        params=[Param("file_offset", "int", required=True, positional=True,
                      help="Byte offset in the input file.")],
    ),
    Command(
        "get-fileregion-offset", get_fileregion_offset, "database",
        "Map a database address back to its input file byte offset.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address in the database.")],
    ),
    Command(
        "get-elf-debug-file-directory", get_elf_debug_file_directory, "database",
        "Get the ELF debug file directory configuration path.",
        params=[],
    ),
    Command(
        "reload-file", reload_file, "database",
        "Re-read bytes from the original input file, overwriting patches.",
        mutates=True,
        params=[Param("is_remote", "bool", default=False,
                      help="Whether the file is on a remote debugger server.")],
    ),
]
