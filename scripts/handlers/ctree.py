#!/usr/bin/env python3
"""ctree — Hex-Rays ctree (decompiler AST) exploration.

Ported from re_mcp_ida/tools/ctree.py. All ``ida_*`` imports live inside
handler bodies so the manifest imports cleanly without an IDA runtime.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    IDAError,
    decompile_at,
    format_address,
    get_func_name,
    is_bad_addr,
)

_VALID_PATTERN_TYPES = frozenset(
    {
        "calls",
        "string_refs",
        "comparisons",
        "assignments",
        "casts",
        "pointer_derefs",
        "all",
    }
)


def _comparison_ops() -> frozenset:
    import ida_hexrays

    return frozenset(
        {
            ida_hexrays.cot_eq,
            ida_hexrays.cot_ne,
            ida_hexrays.cot_sge,
            ida_hexrays.cot_sgt,
            ida_hexrays.cot_sle,
            ida_hexrays.cot_slt,
            ida_hexrays.cot_uge,
            ida_hexrays.cot_ugt,
            ida_hexrays.cot_ule,
            ida_hexrays.cot_ult,
        }
    )


def _assignment_ops() -> frozenset:
    import ida_hexrays

    return frozenset(
        {
            ida_hexrays.cot_asg,
            ida_hexrays.cot_asgadd,
            ida_hexrays.cot_asgsub,
            ida_hexrays.cot_asgmul,
            ida_hexrays.cot_asgband,
            ida_hexrays.cot_asgbor,
            ida_hexrays.cot_asgxor,
            ida_hexrays.cot_asgshl,
            ida_hexrays.cot_asgsshr,
            ida_hexrays.cot_asgushr,
        }
    )


def _op_name(op: int) -> str:
    import ida_hexrays

    op_names = {
        getattr(ida_hexrays, attr): attr
        for attr in dir(ida_hexrays)
        if attr.startswith(("cot_", "cit_"))
    }
    return op_names.get(op, f"op_{op}")


def get_ctree(args: dict) -> dict:
    import ida_hexrays

    function_address = args["function_address"]
    depth = int(args.get("depth", 3))

    cfunc, func = decompile_at(function_address)

    depth = max(1, min(depth, 10))

    def _item_to_dict(item, current_depth):
        if item is None or current_depth <= 0:
            return None

        result = {
            "op": _op_name(item.op),
            "op_id": item.op,
        }

        if not is_bad_addr(item.ea):
            result["address"] = format_address(item.ea)

        if item.is_expr():
            expr = item.cexpr
            _type = expr.type
            if _type and not _type.empty():
                result["type"] = str(_type)

            # Number literal
            if item.op == ida_hexrays.cot_num:
                result["value"] = expr.numval()
            # String literal
            elif item.op == ida_hexrays.cot_str:
                result["string"] = expr.string
            # Object (variable/global)
            elif item.op == ida_hexrays.cot_obj:
                result["obj_ea"] = format_address(expr.obj_ea)
            # Variable reference
            elif item.op == ida_hexrays.cot_var:
                v = expr.v
                if v:
                    idx = v.idx
                    if 0 <= idx < len(cfunc.lvars):
                        result["var_name"] = cfunc.lvars[idx].name
            # Function call
            elif item.op == ida_hexrays.cot_call:
                if expr.x:
                    call_target = _item_to_dict(expr.x, current_depth - 1)
                    if call_target:
                        result["call_target"] = call_target
                if expr.a and current_depth > 1:
                    call_args = []
                    for i in range(len(expr.a)):
                        arg = _item_to_dict(expr.a[i], current_depth - 1)
                        if arg:
                            call_args.append(arg)
                    result["arguments"] = call_args

            # Binary/unary operands (skip for calls — already captured above)
            if current_depth > 1 and item.op != ida_hexrays.cot_call:
                if expr.x:
                    x = _item_to_dict(expr.x, current_depth - 1)
                    if x:
                        result["x"] = x
                if expr.y:
                    y = _item_to_dict(expr.y, current_depth - 1)
                    if y:
                        result["y"] = y

        else:
            insn = item.cinsn
            if current_depth > 1 and insn:
                # if statement
                if item.op == ida_hexrays.cit_if and insn.cif:
                    cif = insn.cif
                    if cif.expr:
                        result["condition"] = _item_to_dict(cif.expr, current_depth - 1)
                    if cif.ithen:
                        result["then"] = _item_to_dict(cif.ithen, current_depth - 1)
                    if cif.ielse:
                        result["else"] = _item_to_dict(cif.ielse, current_depth - 1)
                # while/do/for
                elif item.op == ida_hexrays.cit_while and insn.cwhile:
                    result["condition"] = _item_to_dict(insn.cwhile.expr, current_depth - 1)
                    result["body"] = _item_to_dict(insn.cwhile.body, current_depth - 1)
                elif item.op == ida_hexrays.cit_do and insn.cdo:
                    result["condition"] = _item_to_dict(insn.cdo.expr, current_depth - 1)
                    result["body"] = _item_to_dict(insn.cdo.body, current_depth - 1)
                elif item.op == ida_hexrays.cit_for and insn.cfor:
                    result["init"] = _item_to_dict(insn.cfor.init, current_depth - 1)
                    result["condition"] = _item_to_dict(insn.cfor.expr, current_depth - 1)
                    result["step"] = _item_to_dict(insn.cfor.step, current_depth - 1)
                    result["body"] = _item_to_dict(insn.cfor.body, current_depth - 1)
                # return
                elif item.op == ida_hexrays.cit_return and insn.creturn:
                    result["return_expr"] = _item_to_dict(insn.creturn.expr, current_depth - 1)
                # block
                elif item.op == ida_hexrays.cit_block and insn.cblock:
                    stmts = []
                    for stmt in insn.cblock:
                        s = _item_to_dict(stmt, current_depth - 1)
                        if s:
                            stmts.append(s)
                    result["statements"] = stmts
                # expression statement
                elif item.op == ida_hexrays.cit_expr and insn.cexpr:
                    result["expr"] = _item_to_dict(insn.cexpr, current_depth - 1)
                # switch
                elif item.op == ida_hexrays.cit_switch and insn.cswitch:
                    result["switch_expr"] = _item_to_dict(insn.cswitch.expr, current_depth - 1)

        return result

    body = _item_to_dict(cfunc.body, depth)

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "ctree": body,
    }


def find_ctree_calls(args: dict) -> dict:
    import ida_hexrays
    import ida_name

    function_address = args["function_address"]
    callee_name = args.get("callee_name", "") or ""

    cfunc, func = decompile_at(function_address)

    calls = []

    class CallFinder(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, expr):
            if expr.op == ida_hexrays.cot_call:
                target = expr.x
                target_name = ""
                target_addr = None

                if target and target.op == ida_hexrays.cot_obj:
                    target_addr = target.obj_ea
                    target_name = ida_name.get_name(target_addr) or ""

                if callee_name and callee_name not in target_name:
                    return 0

                call_info = {
                    "callee": target_name,
                    "arg_count": len(expr.a) if expr.a else 0,
                    "callee_address": format_address(target_addr)
                    if target_addr is not None
                    else None,
                    "call_address": format_address(expr.ea) if not is_bad_addr(expr.ea) else None,
                }

                calls.append(call_info)
            return 0

    visitor = CallFinder()
    visitor.apply_to(cfunc.body, None)

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "call_count": len(calls),
        "calls": calls,
    }


def find_ctree_patterns(args: dict) -> dict:
    import ida_hexrays
    import ida_name

    function_address = args["function_address"]
    pattern_type = args.get("pattern_type", "all") or "all"

    cfunc, func = decompile_at(function_address)

    if pattern_type not in _VALID_PATTERN_TYPES:
        raise IDAError(
            f"Invalid pattern_type: {pattern_type!r}",
            error_type="InvalidArgument",
            valid_types=sorted(_VALID_PATTERN_TYPES),
        )

    comparison_ops = _comparison_ops()
    assignment_ops = _assignment_ops()

    results = {
        "calls": [],
        "string_refs": [],
        "comparisons": [],
        "assignments": [],
        "casts": [],
        "pointer_derefs": [],
    }

    class PatternFinder(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, expr):
            addr = format_address(expr.ea) if not is_bad_addr(expr.ea) else None

            if (pattern_type in ("all", "calls")) and expr.op == ida_hexrays.cot_call:
                target = expr.x
                name = ""
                if target and target.op == ida_hexrays.cot_obj:
                    name = ida_name.get_name(target.obj_ea) or ""
                results["calls"].append({"callee": name, "address": addr})

            if (pattern_type in ("all", "string_refs")) and expr.op == ida_hexrays.cot_str:
                results["string_refs"].append({"string": expr.string, "address": addr})

            if (pattern_type in ("all", "comparisons")) and expr.op in comparison_ops:
                results["comparisons"].append({"op": _op_name(expr.op), "address": addr})

            if (pattern_type in ("all", "assignments")) and expr.op in assignment_ops:
                results["assignments"].append({"op": _op_name(expr.op), "address": addr})

            if (pattern_type in ("all", "casts")) and expr.op == ida_hexrays.cot_cast:
                target_type = (
                    str(expr.type) if expr.type and not expr.type.empty() else "unknown"
                )
                results["casts"].append({"target_type": target_type, "address": addr})

            if (pattern_type in ("all", "pointer_derefs")) and expr.op == ida_hexrays.cot_ptr:
                results["pointer_derefs"].append({"address": addr})

            return 0

    visitor = PatternFinder()
    visitor.apply_to(cfunc.body, None)

    if pattern_type != "all":
        return {
            "function": format_address(func.start_ea),
            "name": get_func_name(func.start_ea),
            "pattern_type": pattern_type,
            "count": len(results[pattern_type]),
            "matches": results[pattern_type],
        }

    summary = {k: len(v) for k, v in results.items()}
    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "summary": summary,
        "results": results,
    }


COMMANDS = [
    Command(
        "get-ctree", get_ctree, "ctree",
        "Return the Hex-Rays AST (ctree) for ONE function as a structured tree.",
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("depth", "int", default=3,
                  help="Maximum tree depth to return (1-10)."),
        ],
    ),
    Command(
        "find-ctree-calls", find_ctree_calls, "ctree",
        "Enumerate call sites inside ONE function's Hex-Rays AST.",
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the function to analyze."),
            Param("callee_name", "str", default="",
                  help="Optional name to filter calls (empty = all calls)."),
        ],
    ),
    Command(
        "find-ctree-patterns", find_ctree_patterns, "ctree",
        "Scan ONE function's Hex-Rays AST for common pattern classes.",
        params=[
            Param("function_address", "str", required=True, positional=True,
                  help="Address or name of the function."),
            Param("pattern_type", "str", default="all",
                  help="calls|string_refs|comparisons|assignments|casts|pointer_derefs|all."),
        ],
    ),
]
