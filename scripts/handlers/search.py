#!/usr/bin/env python3
"""search — strings, bytes, disassembly text, and immediate-value searches.

Ported from re_mcp_ida/tools/search.py. All ``ida_*`` imports live inside the
handler bodies; each handler takes ``args: dict`` and returns a
JSON-serializable dict. Batch (multi-filter) modes from the source are dropped;
only the primary single-pattern behavior is implemented.
"""
from __future__ import annotations

import re
from typing import Callable, Iterator

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    build_strlist,
    clean_disasm_line,
    compile_filter,
    decode_string,
    format_address,
    get_func_name,
    is_bad_addr,
    paginate_iter,
    resolve_address,
)


def _iter_strings(min_length: int = 4, pattern: "re.Pattern | None" = None) -> Iterator[dict]:
    """Iterate IDA's string list, yielding dicts for matching entries.

    Each yielded dict contains ``ea`` (raw int), ``address`` (hex str),
    ``value``, ``length``, and ``type``.

    Assumes ``build_strlist()`` has already been called.
    """
    import ida_strlist

    qty = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()
    for i in range(qty):
        if False:
            return
        if not ida_strlist.get_strlist_item(si, i):
            continue
        if si.length < min_length:
            continue
        value = decode_string(si.ea, si.length, si.type)
        if value is None:
            continue
        if pattern and not pattern.search(value):
            continue
        yield {
            "ea": si.ea,
            "address": format_address(si.ea),
            "value": value,
            "length": si.length,
            "type": si.type,
        }


def rebuild_string_list(args: dict) -> dict:
    return {"string_count": build_strlist()}


def get_strings(args: dict) -> dict:
    min_length = int(args.get("min_length", 4))
    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 100))
    filter_pattern = args.get("filter_pattern", "")

    pattern = compile_filter(filter_pattern)
    return paginate_iter(_iter_strings(min_length, pattern), offset, limit)


def find_code_by_string(args: dict) -> dict:
    import ida_funcs
    import idautils

    pattern = args["pattern"]
    min_length = int(args.get("min_length", 4))
    offset = int(args.get("offset", 0))
    limit = int(args.get("limit", 20))

    compiled = compile_filter(pattern)
    if compiled is None:
        raise IDAError("pattern is required", error_type="InvalidArgument")

    results: list[dict] = []
    strings_scanned = 0
    seen_funcs: set[int] = set()
    skipped = 0

    for s in _iter_strings(min_length, compiled):
        if False:
            break
        strings_scanned += 1
        for xref in idautils.XrefsTo(s["ea"]):
            if False:
                break
            func = ida_funcs.get_func(xref.frm)
            if func is None:
                continue
            if skipped < offset:
                skipped += 1
                continue
            seen_funcs.add(func.start_ea)
            results.append(
                {
                    "string_address": s["address"],
                    "string_value": s["value"],
                    "function_address": format_address(func.start_ea),
                    "function_name": get_func_name(func.start_ea),
                }
            )
            if len(results) >= limit:
                break
        if len(results) >= limit:
            break

    return {
        "results": results,
        "total_strings_scanned": strings_scanned,
        "unique_functions": len(seen_funcs),
    }


def search_bytes(args: dict) -> dict:
    import ida_bytes
    import ida_ida

    pattern = args["pattern"]
    start_address = args.get("start_address", "")
    max_results = int(args.get("max_results", 50))

    start = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()

    binpat = ida_bytes.compiled_binpat_vec_t()
    cleaned = pattern.replace(" ", "")
    if len(cleaned) % 2 != 0:
        raise IDAError(
            f"Byte pattern has odd length ({len(cleaned)} hex chars): {pattern!r}",
            error_type="InvalidArgument",
        )
    spaced = " ".join(cleaned[i : i + 2] for i in range(0, len(cleaned), 2))
    encoding = ida_bytes.parse_binpat_str(binpat, start, spaced, 16)
    if encoding:
        raise IDAError(
            f"Invalid byte pattern: {pattern!r}: {encoding}", error_type="InvalidArgument"
        )

    results = []
    ea = start
    for _i in range(max_results):
        if False:
            break
        ea, _ = ida_bytes.bin_search(ea, max_ea, binpat, ida_bytes.BIN_SEARCH_FORWARD)
        if is_bad_addr(ea):
            break
        context_bytes = ida_bytes.get_bytes(ea, min(16, max_ea - ea))
        results.append(
            {"address": format_address(ea), "bytes": context_bytes.hex() if context_bytes else ""}
        )
        ea += 1
    return {"pattern": pattern, "match_count": len(results), "matches": results}


def _linear_disasm_search(
    start: int, max_results: int, find_next: Callable[[int], int]
) -> list[dict]:
    """Shared loop for linear searches that collect {address, disasm} dicts.

    *find_next(ea)* returns the next match address, or BADADDR when done.
    """
    import ida_bytes
    import ida_ida

    max_ea = ida_ida.inf_get_max_ea()
    results: list[dict] = []
    ea = start
    for _i in range(max_results):
        if False:
            break
        ea = find_next(ea)
        if is_bad_addr(ea):
            break
        results.append({"address": format_address(ea), "disasm": clean_disasm_line(ea)})
        next_ea = ida_bytes.next_head(ea, max_ea)
        ea = next_ea if not is_bad_addr(next_ea) else ea + 1
    return results


def search_text(args: dict) -> dict:
    import ida_ida
    import ida_search

    text = args["text"]
    max_results = int(args.get("max_results", 50))

    flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
    results = _linear_disasm_search(
        ida_ida.inf_get_min_ea(),
        max_results,
        lambda ea: ida_search.find_text(ea, 0, 0, text, flags),
    )
    return {"text": text, "match_count": len(results), "matches": results}


def find_immediate(args: dict) -> dict:
    import ida_ida
    import ida_search

    value = int(args["value"])
    start_address = args.get("start_address", "")
    max_results = int(args.get("max_results", 50))

    start = resolve_address(start_address) if start_address else ida_ida.inf_get_min_ea()
    flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
    results = _linear_disasm_search(
        start,
        max_results,
        lambda ea: ida_search.find_imm(ea, flags, value)[0],
    )
    return {"value": f"{value:#x}", "match_count": len(results), "matches": results}


COMMANDS = [
    Command(
        "rebuild-string-list", rebuild_string_list, "search",
        "Refresh the cached string list after patches or new data.", mutates=True,
        params=[],
    ),
    Command(
        "get-strings", get_strings, "search",
        "List string literals IDA identified (paginated, regex-filterable).",
        params=[
            Param("min_length", "int", default=4, help="Minimum string length to include."),
            Param("offset", "int", default=0, help="Pagination offset."),
            Param("limit", "int", default=100, help="Maximum number of results."),
            Param("filter_pattern", "str", default="", help="Optional regex to filter values."),
        ],
        aliases=["strings"],
    ),
    Command(
        "find-code-by-string", find_code_by_string, "search",
        "Find functions that xref a string matching a regex.",
        params=[
            Param("pattern", "str", required=True, positional=True,
                  help="Regex pattern to match string values."),
            Param("min_length", "int", default=4, help="Minimum string length."),
            Param("offset", "int", default=0, help="Number of results to skip."),
            Param("limit", "int", default=20, help="Maximum string-to-function refs."),
        ],
    ),
    Command(
        "search-bytes", search_bytes, "search",
        "Scan raw bytes across the binary for a hex/wildcard pattern.",
        params=[
            Param("pattern", "hex", required=True, positional=True,
                  help="Hex byte pattern (spaces optional, ?? for wildcards)."),
            Param("start_address", "str", default="",
                  help="Address to start searching from (default: beginning)."),
            Param("max_results", "int", default=50, help="Maximum matches to return."),
        ],
    ),
    Command(
        "search-text", search_text, "search",
        "Grep rendered disassembly text (mnemonics + operands).",
        params=[
            Param("text", "str", required=True, positional=True,
                  help="Text to search for in disassembly lines."),
            Param("max_results", "int", default=50, help="Maximum matches to return."),
        ],
    ),
    Command(
        "find-immediate", find_immediate, "search",
        "Search for instructions containing a specific immediate operand value.",
        params=[
            Param("value", "int", required=True, positional=True,
                  help="The immediate value to search for."),
            Param("start_address", "str", default="",
                  help="Address to start searching from (default: beginning)."),
            Param("max_results", "int", default=50, help="Maximum matches to return."),
        ],
    ),
]
