#!/usr/bin/env python3
"""utility — number conversion, IDC expression evaluation, script execution.

Ported from re_mcp_ida/tools/utility.py.

Follows the handler contract (see handlers/functions.py):

  * All ``ida_*`` imports live INSIDE handler functions.
  * Each handler takes ``args: dict`` and returns a JSON-serializable dict.
  * Failures raise ``IDAError(msg, error_type=...)``.

Note: ``run-script`` runs arbitrary IDAPython with full FS/network access. This
is a local trusted skill, so it is always enabled (no env gate).
"""
from __future__ import annotations

import contextlib
import io

from ida_cmd import Command, Param
from ida_helpers import IDAError, format_address


def convert_number(args: dict) -> dict:
    value = str(args["value"]).strip()
    try:
        if value.lower().startswith("0x"):
            n = int(value, 16)
        elif value.lower().startswith("0o"):
            n = int(value, 8)
        elif value.lower().startswith("0b"):
            n = int(value, 2)
        else:
            n = int(value, 0)
    except ValueError:
        raise IDAError(
            f"Cannot parse number: {value!r}", error_type="InvalidArgument"
        ) from None

    # Compute signed value for common widths
    signed_32 = n if n < 0x80000000 else n - 0x100000000
    signed_64 = n if n < 0x8000000000000000 else n - 0x10000000000000000

    return {
        "decimal": str(n),
        "hex": hex(n),
        "octal": oct(n),
        "binary": bin(n),
        "signed_32": signed_32 if 0 <= n <= 0xFFFFFFFF else None,
        "signed_64": signed_64 if 0 <= n <= 0xFFFFFFFFFFFFFFFF else None,
    }


def evaluate_expression(args: dict) -> dict:
    import idc

    expression = args["expression"]
    result = idc.eval_idc(expression)
    if isinstance(result, int):
        return {
            "expression": expression,
            "result": result,
            "hex": format_address(result),
        }
    return {"expression": expression, "result": str(result), "hex": None}


def run_script(args: dict) -> dict:
    code = args["code"]
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    exec_globals = {"__builtins__": __builtins__}

    try:
        with (
            contextlib.redirect_stdout(stdout_capture),
            contextlib.redirect_stderr(stderr_capture),
        ):
            exec(code, exec_globals)
    except Exception as e:
        raise IDAError(
            f"{type(e).__name__}: {e}",
            error_type="ScriptError",
            stdout=stdout_capture.getvalue(),
            stderr=stderr_capture.getvalue(),
        ) from e

    return {
        "stdout": stdout_capture.getvalue(),
        "stderr": stderr_capture.getvalue(),
    }


COMMANDS = [
    Command(
        "convert-number", convert_number, "utility",
        "Convert a number between hex, decimal, octal, and binary.",
        requires_open=False,
        params=[
            Param("value", "str", required=True, positional=True,
                  help="Number to convert (0x hex, 0o octal, 0b binary)."),
        ],
    ),
    Command(
        "evaluate-expression", evaluate_expression, "utility",
        "Evaluate an IDC expression and return the result.",
        params=[
            Param("expression", "str", required=True, positional=True,
                  help='IDC expression (e.g. "MinEA()", "0x1000+0x20").'),
        ],
    ),
    Command(
        "run-script", run_script, "utility",
        "DANGEROUS: run arbitrary IDAPython (full FS/network access).",
        mutates=True,
        params=[
            Param("code", "str", required=True, positional=True,
                  help="Python code to execute. Use print() for output."),
        ],
    ),
]
