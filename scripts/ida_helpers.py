#!/usr/bin/env python3
"""ida_helpers.py — Address resolution, formatting, and IDA utility helpers.

A worker-side port of ``re_mcp_ida.helpers`` adapted for the single-threaded
idalib worker: no async, no Pydantic, no FastMCP. Every function that touches
an ``ida_*`` module imports it **inside** the function body so this module (and
therefore the whole command manifest) can be imported without a provisioned
IDA runtime.

Handler modules import from here for:
  * address parsing / resolution — ``resolve_address``, ``resolve_function``,
    ``decompile_at``, ``decode_insn_at``, ``resolve_segment``,
    ``resolve_struct``, ``resolve_enum``
  * formatting — ``format_address``, ``clean_disasm_line``, ``get_func_name``
  * pagination / filtering — ``paginate``, ``paginate_iter``, ``compile_filter``
  * misc — segment/permission/type/string helpers
  * the :data:`session` state object (open path + capabilities)
"""
from __future__ import annotations

import re
from typing import Any, Callable, Iterable, Iterator

from ida_cmd import IDAError

# Re-export so handlers can do `from ida_helpers import IDAError`.
__all__ = ["IDAError"]

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_BADADDR32 = 0xFFFFFFFF
_BADADDR64 = 0xFFFFFFFFFFFFFFFF


def is_bad_addr(val: int) -> bool:
    """Return True if *val* is an IDA BADADDR / invalid-ID sentinel."""
    return val in (_BADADDR32, _BADADDR64)


# ---------------------------------------------------------------------------
# Session state — updated by worker.py on open/close.
# ---------------------------------------------------------------------------
class _Session:
    """Minimal session state shared between worker.py and handlers."""

    def __init__(self) -> None:
        self.current_path: str | None = None
        self.capabilities: dict[str, bool] = {}

    def is_open(self) -> bool:
        return self.current_path is not None

    def require_open(self, fn):
        """Passthrough decorator — the worker enforces open-state at dispatch.

        Present so ported code decorated with ``@session.require_open`` (e.g.
        the debugger module) works verbatim.
        """
        return fn


session = _Session()


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
def format_address(ea: int) -> str:
    """Format an effective address as a lowercase ``0x`` hex string."""
    return f"0x{ea:x}"


# Alias used by the original flat worker.
format_ea = format_address


# ---------------------------------------------------------------------------
# Address parsing / resolution
# ---------------------------------------------------------------------------
def parse_address(addr: str | int) -> int:
    """Parse an address from hex (``0x...``), decimal, symbol name, or bare hex.

    Symbol names are checked before bare hex so that names like ``add``,
    ``dead``, or ``cafe`` resolve to the named symbol rather than a hex value.
    Use the ``0x`` prefix for explicit hex.
    """
    import ida_name
    import idc

    if isinstance(addr, int):
        return addr

    addr = addr.strip()
    if not addr:
        raise ValueError("Empty address")

    if addr.lower().startswith("0x"):
        return int(addr, 16)
    if addr.isdigit():
        return int(addr)

    ea = idc.get_name_ea_simple(addr)
    if not is_bad_addr(ea) and ea != idc.BADADDR:
        return ea
    ea = ida_name.get_name_ea(0, addr)
    if not is_bad_addr(ea):
        return ea

    if HEX_RE.match(addr):
        return int(addr, 16)

    raise ValueError(f"Cannot resolve address: {addr!r}")


def resolve_address(addr: str | int) -> int:
    """Parse and validate an address. Raises ``IDAError('InvalidAddress')``."""
    try:
        return parse_address(addr)
    except ValueError as e:
        raise IDAError(str(e), error_type="InvalidAddress") from e


def resolve_function(addr: str | int):
    """Resolve an address to its containing ``func_t``. Raises on miss."""
    import ida_funcs

    ea = resolve_address(addr)
    func = ida_funcs.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {format_address(ea)}", error_type="NotFound")
    return func


def decompile_at(addr: str | int):
    """Resolve, get the function, and decompile with Hex-Rays.

    Returns ``(cfunc, func_t)``. Raises ``IDAError`` on any failure.
    """
    import ida_funcs
    import ida_hexrays

    if not session.capabilities.get("decompiler"):
        # Attempt a late init in case capabilities were not probed.
        if not ida_hexrays.init_hexrays_plugin():
            raise IDAError(
                "No decompiler available for this architecture/license",
                error_type="NoDecompiler",
            )
        session.capabilities["decompiler"] = True

    ea = resolve_address(addr)
    func = ida_funcs.get_func(ea)
    if func is None:
        raise IDAError(f"No function at {format_address(ea)}", error_type="NotFound")
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
    except ida_hexrays.DecompilationFailure as e:
        raise IDAError(str(e), error_type="DecompilationFailed") from e
    except Exception as e:  # noqa: BLE001
        raise IDAError(f"Decompilation error: {e}", error_type="DecompilationFailed") from e
    if cfunc is None:
        raise IDAError("Decompilation returned no result", error_type="DecompilationFailed")
    return cfunc, func


def decode_insn_at(ea: int):
    """Decode an instruction at *ea*. Raises ``IDAError('DecodeFailed')``."""
    import ida_ua

    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        raise IDAError(
            f"Cannot decode instruction at {format_address(ea)}", error_type="DecodeFailed"
        )
    return insn


def resolve_segment(address: str | int):
    """Resolve an address to its containing segment. Raises on miss."""
    import ida_segment

    ea = resolve_address(address)
    seg = ida_segment.getseg(ea)
    if seg is None:
        raise IDAError(f"No segment at {format_address(ea)}", error_type="NotFound")
    return seg


def resolve_struct(name: str) -> int:
    """Resolve a struct name to its type ID. Raises ``IDAError('NotFound')``."""
    import idc

    sid = idc.get_struc_id(name)
    if is_bad_addr(sid) or sid == idc.BADADDR:
        raise IDAError(f"Structure not found: {name}", error_type="NotFound")
    return sid


def resolve_enum(name: str) -> int:
    """Resolve an enum name to its type ID (tid). Raises on miss / not-enum."""
    import ida_typeinf

    tid = ida_typeinf.get_named_type_tid(name)
    if is_bad_addr(tid):
        raise IDAError(f"Enum not found: {name}", error_type="NotFound")
    tif = ida_typeinf.tinfo_t()
    tif.get_type_by_tid(tid)
    if not tif.is_enum():
        raise IDAError(f"Not an enum: {name}", error_type="NotFound")
    return tid


# ---------------------------------------------------------------------------
# Disassembly / naming
# ---------------------------------------------------------------------------
def clean_disasm_line(ea: int) -> str:
    """Return a color-code-free disassembly line for an address."""
    import ida_lines

    line = ida_lines.generate_disasm_line(ea, 0)
    if line:
        return ida_lines.tag_remove(line)
    return ""


def get_func_name(ea: int) -> str:
    """Function/label name at *ea*, or the formatted address if unnamed."""
    import ida_name

    return ida_name.get_name(ea) or format_address(ea)


def xref_type_name(xref_type: int) -> str:
    """Human-readable name for an xref type."""
    import idautils

    return idautils.XrefTypeName(xref_type)


# ---------------------------------------------------------------------------
# Segment / permission helpers
# ---------------------------------------------------------------------------
_BITNESS_MAP = {0: 16, 1: 32, 2: 64}
_VALID_PERM_CHARS = frozenset("RWX-")


def segment_bitness(raw: int) -> int:
    """Convert IDA's segment bitness encoding (0/1/2) to a bit count."""
    return _BITNESS_MAP.get(raw, raw)


def format_permissions(perm: int) -> str:
    """Format IDA segment permission flags as ``"RWX"`` / ``"R-X"`` etc."""
    import ida_segment

    s = "R" if perm & ida_segment.SEGPERM_READ else "-"
    s += "W" if perm & ida_segment.SEGPERM_WRITE else "-"
    s += "X" if perm & ida_segment.SEGPERM_EXEC else "-"
    return s


def parse_permissions(permissions: str) -> int:
    """Parse ``"RWX"`` / ``"R-X"`` into IDA segment permission flags."""
    import ida_segment

    perms_upper = permissions.upper()
    if not perms_upper or not all(c in _VALID_PERM_CHARS for c in perms_upper):
        raise IDAError(
            f"Invalid permission string: {permissions!r} "
            f"(each character must be one of R, W, X, or -)",
            error_type="InvalidArgument",
        )
    perm = 0
    if "R" in perms_upper:
        perm |= ida_segment.SEGPERM_READ
    if "W" in perms_upper:
        perm |= ida_segment.SEGPERM_WRITE
    if "X" in perms_upper:
        perm |= ida_segment.SEGPERM_EXEC
    return perm


def validate_operand_num(operand_num: int) -> None:
    """Raise ``IDAError`` if *operand_num* is negative."""
    if operand_num < 0:
        raise IDAError(
            f"Operand index must be >= 0, got {operand_num}",
            error_type="InvalidArgument",
        )


# ---------------------------------------------------------------------------
# Type helpers
# ---------------------------------------------------------------------------
def parse_type(type_str: str):
    """Parse a C type declaration string into a ``tinfo_t``."""
    import ida_typeinf

    tinfo = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    parsed = ida_typeinf.parse_decl(tinfo, til, f"{type_str};", ida_typeinf.PT_TYP)
    if parsed is None:
        raise IDAError(f"Failed to parse type: {type_str!r}", error_type="ParseError")
    return tinfo


def safe_type_size(size: int) -> int | None:
    """Return *size* unless it is an IDA sentinel, in which case ``None``."""
    return None if is_bad_addr(size) else size


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------
def _all_str_types() -> tuple:
    import ida_nalt

    return (
        ida_nalt.STRTYPE_C,
        ida_nalt.STRTYPE_C_16,
        ida_nalt.STRTYPE_C_32,
        ida_nalt.STRTYPE_PASCAL,
        ida_nalt.STRTYPE_PASCAL_16,
        ida_nalt.STRTYPE_PASCAL_32,
        ida_nalt.STRTYPE_LEN2,
        ida_nalt.STRTYPE_LEN2_16,
        ida_nalt.STRTYPE_LEN2_32,
        ida_nalt.STRTYPE_LEN4,
        ida_nalt.STRTYPE_LEN4_16,
        ida_nalt.STRTYPE_LEN4_32,
    )


def build_strlist() -> int:
    """Rebuild the string list with all string types enabled; return count."""
    import ida_strlist

    opts = ida_strlist.get_strlist_options()
    existing = set(opts.strtypes)
    existing.update(_all_str_types())
    opts.strtypes = sorted(existing)
    ida_strlist.build_strlist()
    return ida_strlist.get_strlist_qty()


def decode_string(ea: int, length: int, strtype: int) -> str | None:
    """Decode a string from the database, or ``None`` on failure."""
    import ida_bytes

    raw = ida_bytes.get_strlit_contents(ea, length, strtype)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return raw.hex()


def get_old_item_info(ea: int) -> tuple[str, int]:
    """Return ``(item_type, item_size)`` at *ea* for undo tracking."""
    import ida_bytes

    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_code(flags):
        item_type = "code"
    elif ida_bytes.is_data(flags):
        item_type = "data"
    elif ida_bytes.is_tail(flags):
        item_type = "tail"
    else:
        item_type = "unknown"
    return item_type, ida_bytes.get_item_size(ea)


# ---------------------------------------------------------------------------
# Filtering / pagination
# ---------------------------------------------------------------------------
def compile_filter(pattern: str | None):
    """Compile a case-insensitive regex, or ``None`` for an empty pattern."""
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise IDAError(f"Invalid regex {pattern!r}: {e}", error_type="InvalidArgument") from e


def paginate(items: list, offset: int = 0, limit: int = 100) -> dict:
    """Return a page of a materialized list with pagination metadata."""
    total = len(items)
    page = items[offset : offset + limit] if limit else items[offset:]
    return {
        "items": page,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(page) < total,
    }


_COUNT_AHEAD = 200


def paginate_iter(it: Iterable, offset: int = 0, limit: int = 100) -> dict:
    """Paginate a generator without materializing the whole sequence.

    Reads up to ``_COUNT_AHEAD`` items past the page end to compute an
    approximate ``total`` and an exact ``has_more``.
    """
    iterator: Iterator = iter(it)
    # Skip to offset.
    seen = 0
    for _ in range(offset):
        try:
            next(iterator)
            seen += 1
        except StopIteration:
            return {"items": [], "total": seen, "offset": offset, "limit": limit, "has_more": False}

    page: list = []
    for _ in range(limit) if limit else iter(int, 1):
        try:
            page.append(next(iterator))
            seen += 1
        except StopIteration:
            return {
                "items": page,
                "total": seen,
                "offset": offset,
                "limit": limit,
                "has_more": False,
            }

    # The page is full (limit items). Read ahead to refine the approximate
    # total; has_more is True as soon as a single further item exists.
    ahead = 0
    for _ in range(_COUNT_AHEAD):
        try:
            next(iterator)
            seen += 1
            ahead += 1
        except StopIteration:
            break
    return {
        "items": page,
        "total": seen,
        "offset": offset,
        "limit": limit,
        "has_more": ahead > 0,
    }


def require_capability(name: str) -> None:
    """Raise ``IDAError`` if the current database lacks capability *name*."""
    if not session.capabilities.get(name):
        raise IDAError(
            f"Capability {name!r} not available for this database",
            error_type="Unsupported",
        )
