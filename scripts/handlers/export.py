#!/usr/bin/env python3
"""export — batch export of disassembly/pseudocode and IDA-native output files.

Ported from re_mcp_ida/tools/export.py. The ``export_all_*`` tools are
legitimate paginated batch-EXPORT tools that iterate functions — ported fully
with :func:`paginate_iter`. All ``ida_*`` imports live inside handler bodies;
each handler takes ``args: dict`` and returns a plain dict.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    clean_disasm_line,
    compile_filter,
    format_address,
    get_func_name,
    paginate_iter,
    resolve_address,
)


def _output_type_map() -> dict:
    import ida_loader

    return {
        "map": ida_loader.OFILE_MAP,
        "idc": ida_loader.OFILE_IDC,
        "lst": ida_loader.OFILE_LST,
        "asm": ida_loader.OFILE_ASM,
        "dif": ida_loader.OFILE_DIF,
    }


def _matching_functions(pattern):
    """Yield (start_ea, name) for functions matching *pattern*."""
    import ida_funcs

    for i in range(ida_funcs.get_func_qty()):
        func = ida_funcs.getn_func(i)
        if func is None:
            continue
        name = get_func_name(func.start_ea)
        if pattern and not pattern.search(name):
            continue
        yield func.start_ea, name


def _decompile_one(func_ea: int, name: str):
    """Decompile a single function.

    Returns ``(exported_dict, None)`` on success or ``(None, error_dict)``.
    """
    import ida_hexrays
    import ida_lines

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception as e:  # noqa: BLE001
        return None, {"name": name, "address": format_address(func_ea), "error": str(e)}

    if cfunc is None:
        return None, {
            "name": name,
            "address": format_address(func_ea),
            "error": "decompilation returned no result",
        }

    sv = cfunc.get_pseudocode()
    lines = [ida_lines.tag_remove(sv[j].line) for j in range(sv.size())]
    return {
        "name": name,
        "address": format_address(func_ea),
        "pseudocode": "\n".join(lines),
    }, None


def _disassemble_one(func_ea: int, name: str) -> dict:
    """Disassemble a single function."""
    import idautils

    lines = [
        f"{format_address(item_ea)}  {clean_disasm_line(item_ea)}"
        for item_ea in idautils.FuncItems(func_ea)
    ]
    return {
        "name": name,
        "address": format_address(func_ea),
        "instruction_count": len(lines),
        "disassembly": "\n".join(lines),
    }


def export_all_pseudocode(args: dict) -> dict:
    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 50))
    pattern = compile_filter(args.get("filter_pattern", "") or "")

    errors: list = []

    def _iter():
        for func_ea, name in _matching_functions(pattern):
            pseudocode, error = _decompile_one(func_ea, name)
            if error is not None:
                errors.append(error)
                continue
            yield pseudocode

    page = paginate_iter(_iter(), offset, limit)
    return {
        "functions": page["items"],
        "errors": errors,
        "total": page["total"],
        "offset": page["offset"],
        "limit": page["limit"],
        "has_more": page["has_more"],
    }


def export_all_disassembly(args: dict) -> dict:
    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 50))
    pattern = compile_filter(args.get("filter_pattern", "") or "")

    def _iter():
        for func_ea, name in _matching_functions(pattern):
            yield _disassemble_one(func_ea, name)

    page = paginate_iter(_iter(), offset, limit)
    return {
        "functions": page["items"],
        "total": page["total"],
        "offset": page["offset"],
        "limit": page["limit"],
        "has_more": page["has_more"],
    }


def generate_output_file(args: dict) -> dict:
    import os

    import ida_fpro
    import ida_ida
    import ida_loader

    output_path = args["output_path"]
    output_type = args["output_type"]
    start_address = args.get("start_address", "") or ""
    end_address = args.get("end_address", "") or ""
    flags = int(args.get("flags", 0))

    otype = _output_type_map().get(output_type.lower())
    if otype is None:
        raise IDAError(
            f"Unknown output type: {output_type!r}. Valid: {', '.join(_output_type_map())}",
            error_type="InvalidArgument",
        )

    ea1 = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
    ea2 = resolve_address(end_address) if end_address else ida_ida.inf_get_max_ea()

    path = os.path.abspath(os.path.expanduser(output_path))
    fp = ida_fpro.qfile_t()
    if not fp.open(path, "w"):
        raise IDAError(f"Failed to open output file: {path}", error_type="OpenFailed")

    try:
        result = ida_loader.gen_file(otype, fp.get_fp(), ea1, ea2, flags)
    finally:
        fp.close()

    if result < 0:
        raise IDAError("Failed to generate output", error_type="GenerateFailed")

    return {
        "output_path": path,
        "output_type": output_type,
        "start_address": format_address(ea1),
        "end_address": format_address(ea2),
        "lines_generated": result,
    }


def generate_exe_file(args: dict) -> dict:
    import contextlib
    import os

    import ida_fpro
    import ida_loader

    output_path = args["output_path"]
    path = os.path.abspath(os.path.expanduser(output_path))
    fp = ida_fpro.qfile_t()
    if not fp.open(path, "wb"):
        raise IDAError(f"Failed to open output file: {path}", error_type="OpenFailed")

    try:
        result = ida_loader.gen_exe_file(fp.get_fp())
    finally:
        fp.close()

    if result == 0:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise IDAError(
            "Cannot generate executable — loader may not support it",
            error_type="NotSupported",
        )

    return {"output_path": path, "status": "generated"}


COMMANDS = [
    Command(
        "export-all-pseudocode", export_all_pseudocode, "export",
        "Decompile MANY functions in one call (paginated, regex-filterable, expensive).",
        params=[
            Param("filter_pattern", "str", default="", positional=True,
                  help="Optional regex to filter function names."),
            Param("offset", "int", default=0, help="Pagination offset (by function index)."),
            Param("limit", "int", default=50, help="Max number of functions to decompile."),
        ],
    ),
    Command(
        "export-all-disassembly", export_all_disassembly, "export",
        "Disassemble MANY functions in one call (paginated, regex-filterable).",
        params=[
            Param("filter_pattern", "str", default="", positional=True,
                  help="Optional regex to filter function names."),
            Param("offset", "int", default=0, help="Pagination offset (by function index)."),
            Param("limit", "int", default=50, help="Max number of functions to export."),
        ],
    ),
    Command(
        "generate-output-file", generate_output_file, "export",
        "Write an IDA-native .asm/.lst/.map/.dif/.idc file to disk.",
        mutates=True,
        params=[
            Param("output_path", "str", required=True, positional=True,
                  help="Path where the output file will be written."),
            Param("output_type", "str", required=True, positional=True,
                  help="Output type: asm|lst|map|dif|idc."),
            Param("start_address", "str", default="",
                  help="Start address of range (empty = entire database)."),
            Param("end_address", "str", default="",
                  help="End address of range (empty = entire database)."),
            Param("flags", "int", default=0, help="Output generation flags (GENFLG_*)."),
        ],
    ),
    Command(
        "generate-exe-file", generate_exe_file, "export",
        "Generate (rebuild) an executable file from the database.",
        mutates=True,
        params=[Param("output_path", "str", required=True, positional=True,
                      help="Path where the executable will be written.")],
    ),
]
