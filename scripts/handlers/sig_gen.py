#!/usr/bin/env python3
"""sig_gen — FLIRT signature generation from the current database.

Ported from re_mcp_ida/tools/sig_gen.py. All ``ida_*``/``idapro`` imports live
inside handler bodies; each handler takes ``args: dict`` and returns a plain dict.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import IDAError


def generate_signatures(args: dict) -> dict:
    import idapro

    only_pat = bool(args.get("only_pat", False))
    if not hasattr(idapro, "make_signatures"):
        raise IDAError(
            "make_signatures is not available in this idalib version",
            error_type="NotAvailable",
        )
    try:
        success = idapro.make_signatures(only_pat)
    except Exception as e:  # noqa: BLE001
        raise IDAError(str(e), error_type="SignatureGenerationFailed") from e

    if not success:
        raise IDAError("Signature generation failed", error_type="SignatureGenerationFailed")

    return {"status": "ok", "only_pat": only_pat}


COMMANDS = [
    Command(
        "generate-signatures", generate_signatures, "sig_gen",
        "Generate FLIRT .sig and .pat files from the current database.",
        mutates=True,
        params=[Param("only_pat", "bool", default=False,
                      help="If set, only generate the .pat file (no .sig compilation).")],
    ),
]
