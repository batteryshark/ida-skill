#!/usr/bin/env python3
"""signatures — FLIRT signature and type library tools.

Ported from re_mcp_ida/tools/signatures.py. All ``ida_*`` imports live inside
handler bodies; each handler takes ``args: dict`` and returns a plain dict.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import IDAError


def apply_flirt_signature(args: dict) -> dict:
    import idc

    sig_name = args["sig_name"]
    result = idc.plan_to_apply_idasgn(sig_name)
    if result == 0:
        raise IDAError(
            f"Failed to apply signature: {sig_name!r}. File may not exist.",
            error_type="ApplyFailed",
        )
    return {"signature": sig_name, "status": "applied"}


def list_flirt_signatures(args: dict) -> dict:
    import ida_funcs

    sigs = []
    n = ida_funcs.get_idasgn_qty()
    for i in range(n):
        desc = ida_funcs.get_idasgn_desc(i)
        if desc:
            name, optlibs = desc
            sigs.append({"index": i, "name": name, "optional_libs": optlibs})
    return {"count": len(sigs), "signatures": sigs}


def load_type_library(args: dict) -> dict:
    import ida_typeinf

    til_name = args["til_name"]
    result = ida_typeinf.add_til(til_name, ida_typeinf.ADDTIL_DEFAULT)
    if result == 0:
        raise IDAError(f"Failed to load type library: {til_name!r}", error_type="LoadFailed")
    return {"library": til_name, "status": "loaded"}


def list_type_libraries(args: dict) -> dict:
    import ida_typeinf

    til = ida_typeinf.get_idati()
    libs = []
    for i in range(til.nbases):
        base = til.base(i)
        if base:
            libs.append({"index": i, "name": base.name, "description": base.desc or ""})
    return {"count": len(libs), "libraries": libs}


def load_ids_module(args: dict) -> dict:
    import ida_loader

    filename = args["filename"]
    result = ida_loader.load_ids_module(filename)
    if result == 0:
        raise IDAError(f"Failed to load IDS module: {filename!r}", error_type="LoadFailed")
    return {"filename": filename, "status": "applied"}


COMMANDS = [
    Command(
        "apply-flirt-signature", apply_flirt_signature, "signatures",
        "Apply a FLIRT signature library to auto-identify and name library functions.",
        mutates=True,
        params=[Param("sig_name", "str", required=True, positional=True,
                      help="Signature file name (without extension), e.g. 'libc'.")],
    ),
    Command(
        "list-flirt-signatures", list_flirt_signatures, "signatures",
        "List FLIRT signature files currently applied to the database.",
    ),
    Command(
        "load-type-library", load_type_library, "signatures",
        "Load a TIL (type library) for OS/SDK types (e.g. gnulnx_x64, mssdk_win10).",
        mutates=True,
        params=[Param("til_name", "str", required=True, positional=True,
                      help="Type library name (without extension).")],
    ),
    Command(
        "list-type-libraries", list_type_libraries, "signatures",
        "List all loaded type information libraries (TILs).",
    ),
    Command(
        "load-ids-module", load_ids_module, "signatures",
        "Load and apply an IDS (ID Signature) file of library type information.",
        mutates=True,
        params=[Param("filename", "str", required=True, positional=True,
                      help="Name of the IDS file to apply.")],
    ),
]
