#!/usr/bin/env python3
"""srclang — source language parsing (import type declarations via compilers).

Ported from re_mcp_ida/tools/srclang.py. All ``ida_*`` imports live inside
handler bodies; each handler takes ``args: dict`` and returns a plain dict.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import IDAError


def _lang_map() -> dict:
    import ida_srclang

    return {
        "c": ida_srclang.SRCLANG_C,
        "cpp": ida_srclang.SRCLANG_CPP,
        "c++": ida_srclang.SRCLANG_CPP,
        "objc": ida_srclang.SRCLANG_OBJC,
        "objective-c": ida_srclang.SRCLANG_OBJC,
        "swift": ida_srclang.SRCLANG_SWIFT,
        "go": ida_srclang.SRCLANG_GO,
    }


def get_source_parser(args: dict) -> dict:
    import ida_srclang

    name = ida_srclang.get_selected_parser_name()
    return {"parser": name or ""}


def parse_source_declarations(args: dict) -> dict:
    import ida_srclang
    import ida_typeinf

    source = args["source"]
    language = args.get("language", "c") or "c"
    is_path = bool(args.get("is_path", False))
    parser_name = args.get("parser_name", "") or ""

    til = ida_typeinf.get_idati()

    if parser_name:
        rc = ida_srclang.parse_decls_with_parser(parser_name, til, source, is_path)
        if rc == -1:
            raise IDAError(f"No parser found with name {parser_name!r}", error_type="NotFound")
    else:
        lang_map = _lang_map()
        lang_key = language.lower()
        if lang_key not in lang_map:
            raise IDAError(
                f"Unknown language {language!r}. Use: {', '.join(sorted(lang_map))}",
                error_type="InvalidArgument",
            )
        lang_id = lang_map[lang_key]
        rc = ida_srclang.parse_decls_for_srclang(lang_id, til, source, is_path)
        if rc == -1:
            raise IDAError(
                f"No parser available for language {language!r}", error_type="NotFound"
            )

    return {
        "error_count": rc,
        "status": "parsed_ok" if rc == 0 else "parsed_with_errors",
    }


COMMANDS = [
    Command(
        "get-source-parser", get_source_parser, "srclang",
        "Get the active source language parser name (e.g. 'clang').",
    ),
    Command(
        "parse-source-declarations", parse_source_declarations, "srclang",
        "Parse C/C++/ObjC/Swift/Go source declarations and import types.",
        mutates=True,
        params=[
            Param("source", "str", required=True, positional=True,
                  help="Source code string, or a file path if is_path is set."),
            Param("language", "str", default="c",
                  help="c|cpp|c++|objc|objective-c|swift|go (ignored if parser_name given)."),
            Param("is_path", "bool", default=False,
                  help="If set, source is interpreted as a file path."),
            Param("parser_name", "str", default="",
                  help="Use a specific parser by name instead of auto-selecting."),
        ],
    ),
]
