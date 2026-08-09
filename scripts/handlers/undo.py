#!/usr/bin/env python3
"""undo — undo and redo the last database modification.

Ported from re_mcp_ida/tools/undo.py.

Follows the handler contract (see handlers/functions.py):

  * All ``ida_*`` imports live INSIDE handler functions.
  * Each handler takes ``args: dict`` and returns a JSON-serializable dict.
  * Failures raise ``IDAError(msg, error_type=...)``.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import IDAError


def undo(args: dict) -> dict:
    import ida_undo

    if not ida_undo.perform_undo():
        raise IDAError("Nothing to undo", error_type="UndoFailed")
    return {"action": "undo"}


def redo(args: dict) -> dict:
    import ida_undo

    if not ida_undo.perform_redo():
        raise IDAError("Nothing to redo", error_type="RedoFailed")
    return {"action": "redo"}


COMMANDS = [
    Command(
        "undo", undo, "undo",
        "Undo the last database modification.", mutates=True,
    ),
    Command(
        "redo", redo, "undo",
        "Redo the last undone database modification.", mutates=True,
    ),
]
