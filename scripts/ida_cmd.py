#!/usr/bin/env python3
"""ida_cmd.py — Pure command manifest primitives (no IDA dependency).

This module defines the metadata types that describe every worker command:
:class:`Param` (one argument) and :class:`Command` (one command = handler +
schema). Handler modules under ``handlers/`` build a module-level
``COMMANDS`` list from these types.

Crucially this module imports **no** ``ida_*`` package, and handler modules
keep their ``ida_*`` imports *inside* functions. That means the full command
manifest can be imported and introspected by ``cli.py`` and ``mcp.py`` on any
Python — no provisioned IDA runtime required. The manifest is the single
source of truth that drives:

  * the worker's command registry / dispatch (worker.py)
  * the CLI's per-command argparse + help (cli.py)
  * the MCP server's generated tools (mcp.py)
  * the generated reference tables (scripts/gen_reference.py)

Handlers receive a single ``args: dict`` and return a JSON-serializable value
(usually a ``dict``). On failure they raise :class:`IDAError`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


class IDAError(Exception):
    """Structured error raised by command handlers.

    ``error_type`` preserves a machine-readable taxonomy (``NotFound``,
    ``InvalidAddress``, ``ParseError``, ...). Extra keyword arguments are
    carried in ``details`` and surfaced to the client alongside the message
    (e.g. ``valid_types=[...]`` or ``available=[...]``).
    """

    def __init__(self, message: str, error_type: str = "Error", **details: Any):
        self.message = message
        self.error_type = error_type
        self.details = details
        super().__init__(message)


# Backwards-compatible alias — the original flat worker used this name.
IDAWorkerError = IDAError


# Valid parameter kinds. The CLI uses these to coerce string input; the MCP
# server uses them to pick Python annotations for the generated tool schema.
#   str   — passed through verbatim
#   int   — parsed with int(value, 0) so "0x10" and "16" both work
#   bool  — a flag (present => True) on the CLI; a bool param over MCP/JSON
#   hex   — a hex byte string like "48 8b c4" (kept as str; worker parses)
#   json  — a JSON literal (list/dict/number); CLI parses with json.loads
KINDS = ("str", "int", "bool", "hex", "json")


@dataclass
class Param:
    """One command argument."""

    name: str
    kind: str = "str"
    required: bool = False
    default: Any = None
    help: str = ""
    positional: bool = False

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"Param {self.name!r}: bad kind {self.kind!r}")


@dataclass
class Command:
    """One worker command: a handler plus its metadata/schema."""

    name: str
    handler: Callable[[dict], Any]
    category: str = ""
    summary: str = ""
    requires_open: bool = True
    mutates: bool = False
    params: list[Param] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)

    def all_names(self) -> list[str]:
        return [self.name, *self.aliases]


def build_registry(modules: list) -> dict[str, Command]:
    """Flatten each module's ``COMMANDS`` list into a name→Command mapping.

    Raises on duplicate command names so collisions surface at import time
    rather than silently shadowing.
    """
    registry: dict[str, Command] = {}
    for mod in modules:
        for cmd in getattr(mod, "COMMANDS", []):
            for name in cmd.all_names():
                if name in registry:
                    raise ValueError(
                        f"Duplicate command name {name!r} "
                        f"(module {getattr(mod, '__name__', mod)!r})"
                    )
                registry[name] = cmd
    return registry
