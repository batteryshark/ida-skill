#!/usr/bin/env python3
"""Atomic, read-only export of IDA's static function-flow observations."""
from __future__ import annotations

from ida_cmd import Command, Param
from ida_helpers import format_address, get_func_name, resolve_function

_OPERAND_NAMES = {
    0: "void", 1: "register", 2: "memory", 3: "phrase",
    4: "displacement", 5: "immediate", 6: "far", 7: "near",
}


def _addresses(values) -> list[str]:
    return [format_address(value) for value in sorted(set(values))]


def _issue(issues: list[dict], kind: str, message: str, **details) -> None:
    issues.append({"type": kind, "message": message, **details})


def _operand(insn, index: int) -> dict:
    import ida_idp
    import ida_ua
    import idc

    op = insn.ops[index]
    kind = int(op.type)
    result = {
        "index": index,
        "type": _OPERAND_NAMES.get(kind, f"processor_specific_{kind}"),
        "type_id": kind,
        "dtype": int(op.dtype),
        "flags": int(op.flags),
        "text": idc.print_operand(insn.ea, index) or "",
        "read": bool(ida_idp.has_cf_use(int(insn.get_canon_feature()), index)),
        "written": bool(ida_idp.has_cf_chg(int(insn.get_canon_feature()), index)),
    }
    if kind == ida_ua.o_reg:
        result["register"] = int(op.reg)
    elif kind in (ida_ua.o_phrase, ida_ua.o_displ):
        result.update(phrase=int(op.phrase), address=format_address(int(op.addr)))
        if kind == ida_ua.o_displ:
            result["value"] = int(op.value)
    elif kind == ida_ua.o_imm:
        result["value"] = int(op.value)
    elif kind in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
        result["address"] = format_address(int(op.addr))
    else:
        result.update(
            value=int(op.value),
            address=format_address(int(op.addr)),
            specval=int(op.specval),
            specflags=[int(getattr(op, f"specflag{number}")) for number in range(1, 5)],
        )
    return result


def _feature_flags(features: int) -> dict:
    import ida_idp

    names = [
        name for name in (
            "CF_STOP", "CF_CALL", "CF_CHG1", "CF_CHG2", "CF_CHG3", "CF_CHG4",
            "CF_CHG5", "CF_CHG6", "CF_USE1", "CF_USE2", "CF_USE3", "CF_USE4",
            "CF_USE5", "CF_USE6", "CF_JUMP", "CF_SHFT", "CF_HLL", "CF_CHG7",
            "CF_CHG8", "CF_USE7", "CF_USE8",
        )
        if features & int(getattr(ida_idp, name, 0))
    ]
    return {"value": features, "names": names}


def _xrefs(ea: int, outgoing: bool) -> list[dict]:
    import ida_xref

    names = {
        int(ida_xref.fl_U): "unknown",
        int(ida_xref.fl_CF): "call_far",
        int(ida_xref.fl_CN): "call_near",
        int(ida_xref.fl_JF): "jump_far",
        int(ida_xref.fl_JN): "jump_near",
        int(ida_xref.fl_F): "flow",
        int(ida_xref.dr_U): "data_unknown",
        int(ida_xref.dr_O): "data_offset",
        int(ida_xref.dr_W): "data_write",
        int(ida_xref.dr_R): "data_read",
        int(ida_xref.dr_T): "data_text",
        int(ida_xref.dr_I): "data_informational",
        int(ida_xref.dr_S): "data_enum",
    }
    block = ida_xref.xrefblk_t()
    refs = block.refs_from(ea, ida_xref.XREF_ALL) if outgoing else block.refs_to(ea, ida_xref.XREF_ALL)
    result = []
    for ref in refs:
        raw_type = int(ref.type)
        base_type = raw_type & int(ida_xref.XREF_MASK)
        result.append({
            "from": format_address(int(ref.frm)),
            "to": format_address(int(ref.to)),
            "kind": "code" if ref.iscode else "data",
            "type": names.get(base_type, f"unknown_{base_type}"),
            "type_id": raw_type,
            "user": bool(ref.user),
        })
    return sorted(result, key=lambda ref: (int(ref["from"], 16), int(ref["to"], 16), ref["type_id"]))


def _transfer(insn, mnemonic: str, features: int, refs: list[dict]) -> dict:
    import ida_idp
    import ida_ua

    code_refs = [ref for ref in refs if ref["kind"] == "code"]
    static_refs = [ref for ref in code_refs if ref["type"] != "flow"]
    call_refs = [ref for ref in static_refs if ref["type"].startswith("call_")]
    jump_refs = [ref for ref in static_refs if ref["type"].startswith("jump_")]
    direct_operand = int(insn.ops[0].type) in (ida_ua.o_near, ida_ua.o_far)
    operand_target = format_address(int(insn.ops[0].addr)) if direct_operand else None
    stop = bool(features & ida_idp.CF_STOP)
    call = bool(features & ida_idp.CF_CALL) or bool(ida_idp.is_call_insn(insn))
    indirect_jump = bool(features & ida_idp.CF_JUMP) or bool(ida_idp.is_indirect_jump_insn(insn))
    lower = mnemonic.lower()
    loop = lower.startswith("loop") or lower in {"jcxz", "jecxz", "jrcxz"}

    if ida_idp.is_ret_insn(insn):
        kind = "return"
        direct = None
    elif loop:
        kind = "loop"
        direct = direct_operand
    elif call:
        direct = direct_operand
        kind = "direct_call" if direct else "indirect_call"
    elif indirect_jump or direct_operand:
        direct = direct_operand and not indirect_jump
        prefix = "unconditional" if stop else "conditional"
        kind = f"{prefix}_{'direct' if direct else 'indirect'}_jump"
    elif stop:
        kind = "stop"
        direct = None
    elif static_refs:
        kind = "unclassified"
        direct = None
    else:
        kind = "none"
        direct = None
    return {
        "kind": kind,
        "direct": direct,
        "operand_target": operand_target,
        "static_targets": sorted({ref["to"] for ref in call_refs if call}
                                 | {ref["to"] for ref in jump_refs if not call}),
        "unexpected_static_refs": sorted(
            (ref for ref in static_refs
             if (call and ref not in call_refs)
             or (not call and (loop or direct_operand or indirect_jump) and ref not in jump_refs)
             or (not call and not loop and not direct_operand and not indirect_jump)),
            key=lambda ref: (int(ref["to"], 16), ref["type_id"]),
        ),
    }


def _inside_chunks(address: int, chunks: list[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in chunks)


def _fixups(chunks: list[tuple[int, int]]) -> list[dict]:
    import ida_fixup

    result = []
    for start, end in chunks:
        for ea in range(start, end):
            data = ida_fixup.fixup_data_t()
            if not ida_fixup.get_fixup(data, ea):
                continue
            result.append({
                "address": format_address(ea),
                "type": int(data.get_type()),
                "flags": int(data.get_flags()),
                "size": int(data.calc_size()),
                "selector": int(data.sel),
                "offset": format_address(int(data.off)),
                "displacement": int(data.displacement),
                "base": format_address(int(data.get_base())) if data.has_base() else None,
                "external": bool(data.is_extdef()),
                "unused": bool(data.is_unused()),
                "created": bool(data.was_created()),
            })
    return sorted(result, key=lambda item: int(item["address"], 16))


def export_function_flow(args: dict) -> dict:
    import ida_bytes
    import ida_idp
    import ida_segment
    import ida_ua
    import idautils

    func = resolve_function(args["address"])
    raw_chunks = sorted((int(start), int(end)) for start, end in idautils.Chunks(func.start_ea))
    issues: list[dict] = []
    chunks = []
    previous_end = None
    previous_chunk = None
    if not raw_chunks:
        _issue(issues, "missing_chunks", "IDA reported no chunks for the function.")
    for start, end in raw_chunks:
        if end <= start:
            _issue(issues, "invalid_chunk", "Function chunk has zero or negative size.",
                   start=format_address(start), end=format_address(end))
        if previous_end is not None and start < previous_end:
            _issue(issues, "overlapping_chunks", "Function chunks overlap.", address=format_address(start))
        if previous_chunk == (start, end):
            _issue(issues, "duplicate_chunk", "Function chunk is duplicated.",
                   start=format_address(start), end=format_address(end))
        segment = ida_segment.getseg(start)
        if segment is None or (end > start and end > int(segment.end_ea)):
            _issue(issues, "missing_segment", "Chunk is not contained in one IDA segment.",
                   start=format_address(start), end=format_address(end))
        chunks.append({
            "start": format_address(start),
            "end": format_address(end),
            "size": end - start,
            "segment": None if segment is None else {
                "name": ida_segment.get_segm_name(segment) or "",
                "class": ida_segment.get_segm_class(segment) or "",
                "start": format_address(segment.start_ea),
                "end": format_address(segment.end_ea),
                "permissions": int(segment.perm),
                "type": int(segment.type),
                "bitness": int(segment.bitness),
            },
        })
        previous_end = max(previous_end or end, end)
        previous_chunk = (start, end)

    instructions = []
    seen: list[tuple[int, int]] = []
    for chunk_index, (chunk_start, chunk_end) in enumerate(raw_chunks):
        ea = chunk_start
        while ea < chunk_end:
            flags = ida_bytes.get_full_flags(ea)
            item_size = int(ida_bytes.get_item_size(ea))
            if item_size <= 0:
                _issue(issues, "zero_size_item", "IDA reported a zero-size item.", address=format_address(ea))
                ea += 1
                continue
            if not ida_bytes.is_code(flags):
                _issue(issues, "uncovered_chunk_range", "Chunk range does not begin with a decoded code item.",
                       start=format_address(ea), end=format_address(min(chunk_end, ea + item_size)))
                ea += item_size
                continue
            insn = ida_ua.insn_t()
            decoded = int(ida_ua.decode_insn(insn, ea))
            size = int(getattr(insn, "size", 0))
            if decoded <= 0 or size <= 0:
                _issue(issues, "decode_failure", "IDA could not decode a positive-size instruction.",
                       address=format_address(ea), transfer="unresolved_or_unsupported_decode")
                ea += item_size
                continue
            end = ea + size
            if size != item_size:
                _issue(issues, "item_size_mismatch", "Decoded size does not match the IDA code item size.",
                       address=format_address(ea), decoded_size=size, item_size=item_size)
            if end > chunk_end:
                _issue(issues, "instruction_outside_chunk", "Decoded instruction extends beyond its chunk.",
                       address=format_address(ea), end=format_address(end))
            for prior_start, prior_end in seen:
                if ea == prior_start:
                    _issue(issues, "duplicate_instruction", "Instruction address is duplicated.", address=format_address(ea))
                if ea < prior_end and end > prior_start:
                    _issue(issues, "overlapping_instruction", "Decoded instructions overlap.", address=format_address(ea))
            seen.append((ea, end))

            features = int(insn.get_canon_feature())
            mnemonic = insn.get_canon_mnem() or ida_ua.print_insn_mnem(ea) or ""
            refs_from = _xrefs(ea, True)
            refs_to = _xrefs(ea, False)
            code_refs = [ref for ref in refs_from if ref["kind"] == "code"]
            transfer = _transfer(insn, mnemonic, features, refs_from)
            expects_fallthrough = not bool(features & ida_idp.CF_STOP)
            flow_targets = sorted({int(ref["to"], 16) for ref in code_refs if ref["type"] == "flow"})
            expected_flow_targets = [end] if expects_fallthrough else []
            fallthrough = flow_targets == [end]
            successors = sorted({ref["to"] for ref in code_refs if not ref["type"].startswith("call_")})
            if transfer["kind"] == "unconditional_direct_jump" and any(
                    not _inside_chunks(int(target, 16), raw_chunks)
                    for target in transfer["static_targets"]):
                transfer["kind"] = "direct_tail_jump"
            if transfer["kind"] == "unclassified" or (
                    transfer["kind"] == "none"
                    and features & (ida_idp.CF_CALL | ida_idp.CF_JUMP | ida_idp.CF_STOP)):
                _issue(issues, "unclassified_transfer", "IDA transfer evidence could not be classified.",
                       address=format_address(ea))
            missing = []
            if expects_fallthrough and not flow_targets:
                missing.append("ordinary_fallthrough")
            elif flow_targets != expected_flow_targets:
                _issue(
                    issues,
                    "unsupported_ordinary_flow",
                    "Processor ordinary-flow xrefs do not match the supported exact-next-instruction model.",
                    address=format_address(ea),
                    expected_targets=_addresses(expected_flow_targets),
                    observed_targets=_addresses(flow_targets),
                )
            if transfer["kind"] in {
                    "conditional_direct_jump", "unconditional_direct_jump",
                    "direct_tail_jump", "direct_call", "loop",
            } and not transfer["static_targets"]:
                missing.append("static_target")
            if transfer["unexpected_static_refs"]:
                _issue(issues, "unexpected_code_ref", "Code xref kind contradicts the decoded transfer.",
                       address=format_address(ea), refs=transfer["unexpected_static_refs"])
            if transfer["direct"]:
                operand_target = transfer["operand_target"]
                if operand_target in {None, "0x0"}:
                    _issue(issues, "invalid_direct_target", "Decoded direct operand has no sensible target.",
                           address=format_address(ea), operand_target=operand_target)
                elif transfer["static_targets"] and any(
                        target != operand_target for target in transfer["static_targets"]):
                    _issue(issues, "target_mismatch", "Decoded direct operand and typed xref targets disagree.",
                           address=format_address(ea), operand_target=operand_target,
                           xref_targets=transfer["static_targets"])
            if missing:
                _issue(issues, "missing_successor", "Instruction lacks required static successor evidence.",
                       address=format_address(ea), missing=missing)
            if transfer["kind"] in {
                "indirect_call", "conditional_indirect_jump", "unconditional_indirect_jump",
            }:
                _issue(issues, "unresolved_indirect_flow",
                       "Runtime target completeness is outside the static IDA observation boundary.",
                       address=format_address(ea))

            operands = []
            for index in range(8):
                if int(insn.ops[index].type) == ida_ua.o_void:
                    break
                operands.append(_operand(insn, index))
            raw_bytes = ida_bytes.get_bytes(ea, size)
            if raw_bytes is None or len(raw_bytes) != size:
                _issue(issues, "missing_instruction_bytes", "IDA did not return every decoded instruction byte.",
                       address=format_address(ea))
            instructions.append({
                "chunk_index": chunk_index,
                "address": format_address(ea),
                "size": size,
                "bytes": (raw_bytes or b"").hex(),
                "mnemonic": mnemonic,
                "operands": operands,
                "canonical_features": _feature_flags(features),
                "fallthrough": fallthrough,
                "expects_fallthrough": expects_fallthrough,
                "flow_successors": successors,
                "refs_from": refs_from,
                "refs_to": refs_to,
                "transfer": transfer,
            })
            ea = end

    covered_bytes = {
        ea for item in instructions
        for ea in range(int(item["address"], 16), int(item["address"], 16) + item["size"])
        if _inside_chunks(ea, raw_chunks)
    }
    declared_addresses = {
        ea for start, end in raw_chunks if end > start for ea in range(start, end)
    }
    decoded_bytes = len(covered_bytes)
    declared_bytes = len(declared_addresses)
    all_declared_bytes_decoded_once = (
        covered_bytes == declared_addresses
        and not any(issue["type"] in {
            "decode_failure", "duplicate_instruction", "instruction_outside_chunk",
            "item_size_mismatch", "missing_instruction_bytes", "overlapping_instruction",
            "uncovered_chunk_range", "zero_size_item",
        } for issue in issues)
    )
    return {
        "schema": "ida-function-flow-v1",
        "observation_boundary": (
            "Static items, references, fixups, and processor classifications present in the open IDA database; "
            "closed never claims runtime target completeness, behavior, or fidelity."
        ),
        "closed": not issues,
        "issues": sorted(
            issues,
            key=lambda item: (item.get("address", item.get("start", "")), item["type"], item["message"]),
        ),
        "function": {
            "name": get_func_name(func.start_ea),
            "start": format_address(func.start_ea),
            "end": format_address(func.end_ea),
            "size": int(func.size()),
            "flags": int(func.flags),
            "chunks": chunks,
        },
        "instructions": sorted(instructions, key=lambda item: (item["chunk_index"], int(item["address"], 16))),
        "fixups": _fixups(raw_chunks),
        "coverage": {
            "chunk_count": len(raw_chunks),
            "instruction_count": len(instructions),
            "decoded_bytes": decoded_bytes,
            "declared_chunk_bytes": declared_bytes,
            "all_declared_bytes_decoded_once": all_declared_bytes_decoded_once,
            "issue_count": len(issues),
            "issue_types": sorted({item["type"] for item in issues}),
        },
    }


COMMANDS = [
    Command(
        "export-function-flow", export_function_flow, "functions",
        "Export one atomic typed static function-flow envelope with a closure receipt.",
        params=[Param("address", "str", required=True, positional=True,
                      help="Address or name of the function.")],
    ),
]
