#!/usr/bin/env python3
"""gen_reference.py — Generate references/commands.md from the command manifest.

The full command catalog is derived from ``handlers/`` so the reference can
never drift from the code. Run after adding/changing handlers:

    python scripts/gen_reference.py

Writes ../references/commands.md.
"""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ida_cmd import Command, Param  # noqa: E402
import handlers  # noqa: E402

REF = SCRIPT_DIR.parent / "references" / "commands.md"

# Human-friendly section titles + ordering for categories.
CATEGORY_TITLES = {
    "lifecycle": "Lifecycle (worker built-ins)",
    "database": "Database & metadata",
    "functions": "Functions",
    "xrefs": "Cross-references",
    "search": "Search & strings",
    "data": "Data & segments (read)",
    "imports": "Imports / exports / entry points",
    "operands": "Instructions & operands",
    "cfg": "Control flow",
    "frames": "Stack frames",
    "ctree": "Decompiler AST (ctree)",
    "decompiler": "Decompiler variables & comments",
    "comments": "Comments",
    "names": "Names / labels",
    "demangle": "Demangling",
    "types": "Types (apply)",
    "typeinf": "Local types",
    "structs": "Structures",
    "enums": "Enums",
    "function_type": "Function prototypes",
    "func_flags": "Function flags",
    "chunks": "Function chunks",
    "operand_repr": "Operand display",
    "segments": "Segments (modify)",
    "rebase": "Rebase",
    "entry": "Entry points (modify)",
    "patching": "Patching",
    "assemble": "Assembly",
    "makedata": "Data definition",
    "load_data": "Load data",
    "nalt": "Address metadata",
    "analysis": "Analysis control",
    "processor": "Processor info",
    "switches": "Switch tables",
    "regfinder": "Register tracking",
    "regvars": "Register variables",
    "signatures": "Signatures & type libraries",
    "sig_gen": "Signature generation",
    "srclang": "Source language",
    "export": "Batch export",
    "bookmarks": "Bookmarks",
    "colors": "Colors",
    "undo": "Undo / redo",
    "dirtree": "Directory tree",
    "snapshots": "Snapshots",
    "utility": "Utility",
    "debug": "Debugger (dynamic analysis)",
}

CATEGORY_ORDER = list(CATEGORY_TITLES.keys())

# The four lifecycle built-ins are defined in the worker, not in a handler
# module — include them here so the catalog is complete.
LIFECYCLE = [
    Command("open", None, "lifecycle", "Open a binary/database in the worker.",
            params=[Param("file_path", "str", required=True, positional=True,
                          help="Path to binary or .i64/.idb."),
                    Param("run_auto_analysis", "bool", default=True, help="Run auto-analysis.")]),
    Command("close", None, "lifecycle", "Close the current database.",
            params=[Param("save", "bool", default=True, help="Save before closing.")]),
    Command("save", None, "lifecycle", "Flush the database to disk."),
    Command("list-commands", None, "lifecycle", "List all commands (worker-side)."),
]


def main() -> None:
    by_cat: dict[str, list[Command]] = {"lifecycle": list(LIFECYCLE)}
    for c in handlers.COMMANDS:
        by_cat.setdefault(c.category, []).append(c)

    total = sum(len(v) for v in by_cat.values())
    lines: list[str] = []
    lines.append("# IDA Worker — Command Index\n")
    lines.append(
        f"Auto-generated from the command manifest by `scripts/gen_reference.py`. "
        f"**{total} commands** across {len(by_cat)} categories. "
        "Do not edit by hand — regenerate.\n"
    )
    lines.append("This is a compact map (name + one-line summary). For a "
                 "command's exact parameters, ask the CLI directly — it is the "
                 "authoritative, always-current source:\n")
    lines.append("```bash")
    lines.append("python scripts/cli.py <command> --help          # exact params for one command")
    lines.append("python scripts/cli.py commands --category debug  # filtered live listing")
    lines.append("python scripts/cli.py <command> [args] --binary <path>")
    lines.append("python scripts/cli.py call <command> key=value ... --binary <path>  # passthrough")
    lines.append("```")
    lines.append("`*` marks commands that modify the database.\n")

    ordered = [c for c in CATEGORY_ORDER if c in by_cat]
    ordered += [c for c in sorted(by_cat) if c not in CATEGORY_ORDER]

    # Category index.
    lines.append("## Categories\n")
    for cat in ordered:
        title = CATEGORY_TITLES.get(cat, cat)
        anchor = title.lower().replace(" ", "-").replace("(", "").replace(")", "").replace("/", "")
        lines.append(f"- [{title}](#{anchor}) — {len(by_cat[cat])}")
    lines.append("")

    # One compact line per command.
    for cat in ordered:
        title = CATEGORY_TITLES.get(cat, cat)
        lines.append(f"\n## {title}\n")
        width = max(len(c.name) for c in by_cat[cat]) + 1
        for c in sorted(by_cat[cat], key=lambda x: x.name):
            star = "*" if c.mutates else " "
            alias = f" (alias: {', '.join(c.aliases)})" if c.aliases else ""
            lines.append(f"- `{c.name}`{star.rjust(1)} — {c.summary}{alias}".rstrip())
        lines.append("")

    REF.parent.mkdir(parents=True, exist_ok=True)
    REF.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {REF} ({total} commands, {len(by_cat)} categories)")


if __name__ == "__main__":
    main()
