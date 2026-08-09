#!/usr/bin/env python3
"""cfg — control flow graph tools: basic blocks and CFG edges.

Ported from re_mcp_ida/tools/cfg.py.
"""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import (
    format_address,
    get_func_name,
    resolve_function,
)


def get_basic_blocks(args: dict) -> dict:
    import ida_gdl

    func = resolve_function(args["address"])

    flowchart = ida_gdl.FlowChart(func)
    blocks = []
    for block in flowchart:
        succs = [format_address(s.start_ea) for s in block.succs()]
        preds = [format_address(p.start_ea) for p in block.preds()]
        blocks.append(
            {
                "start": format_address(block.start_ea),
                "end": format_address(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "successors": succs,
                "predecessors": preds,
            }
        )

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "block_count": len(blocks),
        "blocks": blocks,
    }


def get_cfg_edges(args: dict) -> dict:
    import ida_gdl

    func = resolve_function(args["address"])

    flowchart = ida_gdl.FlowChart(func)
    edges = []
    for block in flowchart:
        src = format_address(block.start_ea)
        edges.extend(
            {"from": src, "to": format_address(succ.start_ea)} for succ in block.succs()
        )

    return {
        "function": format_address(func.start_ea),
        "name": get_func_name(func.start_ea),
        "edge_count": len(edges),
        "edges": edges,
    }


COMMANDS = [
    Command(
        "get-basic-blocks", get_basic_blocks, "cfg",
        "Get basic blocks of a function (CFG nodes with successor/predecessor lists).",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
    Command(
        "get-cfg-edges", get_cfg_edges, "cfg",
        "Get CFG edges as (source, target) pairs (compact, for graph visualization).",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
]
