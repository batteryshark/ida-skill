#!/usr/bin/env python3
"""debug — headless IDA debugger command suite (idalib worker port).

A near-verbatim port of the upstream re_mcp_ida_debugger.py. The model classes,
helper functions, and tool bodies are preserved as-is; only the surrounding
wiring is adapted for the worker:

  * Pydantic BaseModel/Field and FastMCP are replaced by the shim in
    ``_debugshim`` (models serialize to plain dicts; ``@mcp.tool`` just records
    each tool for manifest generation).
  * The module-level ``ida_*`` imports are made lazy: they are bound into module
    globals by ``_ensure_ida()``, which every generated handler calls first.
    This keeps the module (and the whole command manifest) importable without a
    provisioned IDA runtime.
  * The footer auto-generates the ``COMMANDS`` manifest from each tool's
    signature, wrapping it to accept an ``args: dict`` and return a dict.

Tools connect to a remote IDA ``dbgsrv`` listener on the target host. See
references/dynamic.md for the deployment + workflow guide.
"""
from __future__ import annotations

import os
import shlex
import time
from typing import Any

from _debugshim import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_MUTATE_NON_IDEMPOTENT,
    ANNO_READ_ONLY,
    BaseModel,
    Field,
    McpShim,
    dump,
)
from ida_cmd import Command as _Command, IDAError, Param as _Param
from ida_helpers import (
    decompile_at,
    format_address,
    is_bad_addr,
    resolve_address,
    session,
)

# Upstream type aliases (only ever used inside string annotations).
Address = str
HexBytes = str

# Lazily-bound IDA modules (populated by _ensure_ida on first handler call).
ida_bytes, ida_dbg, ida_ida, ida_idaapi, ida_idd, ida_name, ida_segment, idaapi, ida_lines, ida_nalt, idc, idautils = (None,) * 12


def _ensure_ida() -> None:
    """Import IDA debugger modules into this module's globals (idempotent)."""
    global ida_bytes, ida_dbg, ida_ida, ida_idaapi, ida_idd, ida_name, ida_segment, idaapi, ida_lines, ida_nalt, idc, idautils
    if ida_dbg is not None:
        return
    import ida_bytes as _ida_bytes
    import ida_dbg as _ida_dbg
    import ida_ida as _ida_ida
    import ida_idaapi as _ida_idaapi
    import ida_idd as _ida_idd
    import ida_name as _ida_name
    import ida_segment as _ida_segment
    import idaapi as _idaapi
    import ida_lines as _ida_lines
    import ida_nalt as _ida_nalt
    import idc as _idc
    import idautils as _idautils
    ida_bytes = _ida_bytes
    ida_dbg = _ida_dbg
    ida_ida = _ida_ida
    ida_idaapi = _ida_idaapi
    ida_idd = _ida_idd
    ida_name = _ida_name
    ida_segment = _ida_segment
    idaapi = _idaapi
    ida_lines = _ida_lines
    ida_nalt = _ida_nalt
    idc = _idc
    idautils = _idautils
    _init_lazy_constants()


def _init_lazy_constants() -> None:
    """Populate the module-level maps whose values reference IDA constants.

    Kept out of module scope so the manifest imports without an IDA runtime.
    """
    if _STATE_NAMES:
        return
    _STATE_NAMES.update({
        ida_dbg.DSTATE_NOTASK: "notask",
        ida_dbg.DSTATE_RUN: "running",
        ida_dbg.DSTATE_SUSP: "suspended",
    })
    _BPT_TYPES.update({
        "default": ida_idd.BPT_DEFAULT,
        "software": ida_idd.BPT_SOFT,
        "soft": ida_idd.BPT_SOFT,
        "execute": ida_idd.BPT_EXEC,
        "exec": ida_idd.BPT_EXEC,
        "write": ida_idd.BPT_WRITE,
        "read": ida_idd.BPT_READ,
        "readwrite": ida_idd.BPT_RDWR,
        "rw": ida_idd.BPT_RDWR,
    })
    _TRACE_TYPES.update({
        "step": {
            "enabled": ida_dbg.is_step_trace_enabled,
            "enable": ida_dbg.enable_step_trace,
            "disable": ida_dbg.disable_step_trace,
            "get_options": ida_dbg.get_step_trace_options,
            "set_options": ida_dbg.set_step_trace_options,
        },
        "instruction": {
            "enabled": ida_dbg.is_insn_trace_enabled,
            "enable": ida_dbg.enable_insn_trace,
            "disable": ida_dbg.disable_insn_trace,
            "get_options": ida_dbg.get_insn_trace_options,
            "set_options": ida_dbg.set_insn_trace_options,
        },
        "insn": {"alias": "instruction"},
        "function": {
            "enabled": ida_dbg.is_func_trace_enabled,
            "enable": ida_dbg.enable_func_trace,
            "disable": ida_dbg.disable_func_trace,
            "get_options": ida_dbg.get_func_trace_options,
            "set_options": ida_dbg.set_func_trace_options,
        },
        "func": {"alias": "function"},
        "basic_block": {
            "enabled": ida_dbg.is_bblk_trace_enabled,
            "enable": ida_dbg.enable_bblk_trace,
            "disable": ida_dbg.disable_bblk_trace,
            "get_options": ida_dbg.get_bblk_trace_options,
            "set_options": ida_dbg.set_bblk_trace_options,
        },
        "bblk": {"alias": "basic_block"},
    })


# ===========================================================================
# Verbatim body (models + helpers + register) from re_mcp_ida_debugger.py
# ===========================================================================
class DebugEvent(BaseModel):
    """IDA debugger event summary."""

    code: int = Field(description="Debugger event code.")
    name: str = Field(description="Debugger event name.")
    pid: int | None = Field(default=None, description="Process ID.")
    tid: int | None = Field(default=None, description="Thread ID.")
    address: str | None = Field(default=None, description="Event address.")
    handled: bool | None = Field(default=None, description="Whether the event was handled.")
    info: str | None = Field(default=None, description="Event information, when available.")
    exit_code: int | None = Field(default=None, description="Exit code for exit events.")


class DebugStatusResult(BaseModel):
    """Live debugger state."""

    debugger_loaded: bool = Field(description="Whether an IDA debugger module is loaded.")
    debugger_name: str | None = Field(default=None, description="Loaded debugger name.")
    process_state: str = Field(description="Human-readable process state.")
    process_state_id: int = Field(description="IDA process state constant.")
    current_thread: int | None = Field(default=None, description="Current thread ID.")
    current_ip: str | None = Field(default=None, description="Current instruction pointer.")
    current_sp: str | None = Field(default=None, description="Current stack pointer.")
    thread_count: int = Field(description="Known thread count.")
    threads: list[int] = Field(description="Known thread IDs.")
    last_event: DebugEvent | None = Field(default=None, description="Current debugger event.")


class DebugStartResult(BaseModel):
    """Result of launching a target under the debugger."""

    status: str = Field(description="Start status.")
    debugger: str = Field(description="Debugger module name.")
    remote: bool = Field(description="Whether remote debugger mode was requested.")
    target_host: str | None = Field(default=None, description="Remote debug server host.")
    target_port: int | None = Field(default=None, description="Remote debug server port.")
    target_path: str = Field(description="Target executable path passed to IDA.")
    working_directory: str = Field(default="", description="Starting directory passed to IDA.")
    environment_count: int = Field(default=0, description="Number of explicit environment variables passed.")
    environment_merge: bool = Field(default=True, description="Whether explicit environment variables merge with target defaults.")
    result_code: int = Field(description="IDA start_process return code.")
    event: DebugEvent | None = Field(default=None, description="First debugger event, if waited.")


class DebugAttachResult(BaseModel):
    """Result of attaching the debugger."""

    status: str = Field(description="Attach status.")
    debugger: str = Field(description="Debugger module name.")
    remote: bool = Field(description="Whether remote debugger mode was requested.")
    target_host: str | None = Field(default=None, description="Remote debug server host.")
    target_port: int | None = Field(default=None, description="Remote debug server port.")
    pid: int = Field(description="Attached process ID.")
    result_code: int = Field(description="IDA attach_process return code.")
    event: DebugEvent | None = Field(default=None, description="First debugger event, if waited.")


class DebugSimpleResult(BaseModel):
    """Generic debugger command result."""

    status: str = Field(description="Command status.")
    ok: bool = Field(description="Whether IDA accepted the command.")
    event: DebugEvent | None = Field(default=None, description="Debugger event, if waited.")


class DebugProcess(BaseModel):
    """Attachable process."""

    pid: int = Field(description="Process ID.")
    name: str = Field(description="Process name.")


class DebugProcessListResult(BaseModel):
    """Attachable process list."""

    count: int = Field(description="Number of processes returned.")
    processes: list[DebugProcess] = Field(description="Processes.")


class DebugThreadListResult(BaseModel):
    """Debuggee thread list."""

    current_thread: int | None = Field(default=None, description="Current thread ID.")
    threads: list[int] = Field(description="Known thread IDs.")
    count: int = Field(description="Thread count.")


class DebugFlagsResult(BaseModel):
    """CPU flags."""

    register_name: str = Field(description="Flags register used.")
    value: str = Field(description="Full flags register value.")
    flags: dict[str, bool] = Field(description="Decoded common CPU flags.")


class DebugFlagWriteResult(BaseModel):
    """CPU flag write result."""

    flag: str = Field(description="Flag name.")
    value: bool = Field(description="Requested flag value.")
    register_name: str = Field(description="Flags register used.")
    register_value: str = Field(description="Updated flags register value.")
    ok: bool = Field(description="Whether IDA accepted the write.")


class DebugBreakpoint(BaseModel):
    """Breakpoint summary."""

    address: str = Field(description="Breakpoint address.")
    size: int = Field(description="Breakpoint size.")
    type: int = Field(description="IDA breakpoint type.")
    enabled: bool = Field(description="Whether the breakpoint is enabled.")
    active: bool = Field(description="Whether the breakpoint is active in the debuggee.")
    hardware: bool = Field(description="Whether the breakpoint is hardware-backed.")
    condition: str = Field(description="Breakpoint condition.")
    pass_count: int = Field(description="Pass count before stopping.")
    pid: int | None = Field(default=None, description="Breakpoint process ID.")
    tid: int | None = Field(default=None, description="Breakpoint thread ID.")


class DebugBreakpointListResult(BaseModel):
    """Breakpoint list."""

    count: int = Field(description="Number of breakpoints.")
    breakpoints: list[DebugBreakpoint] = Field(description="Breakpoints.")


class DebugBreakpointResult(BaseModel):
    """Breakpoint mutation result."""

    address: str = Field(description="Breakpoint address.")
    ok: bool = Field(description="Whether IDA accepted the mutation.")
    breakpoint: DebugBreakpoint | None = Field(default=None, description="Updated breakpoint.")


class DebugRegistersResult(BaseModel):
    """Register values."""

    tid: int | None = Field(default=None, description="Thread ID used for register read.")
    registers: dict[str, str | int | float] = Field(description="Register values.")


class DebugRegisterWriteResult(BaseModel):
    """Register write result."""

    register_name: str = Field(description="Register name.")
    value: str | int | float = Field(description="Value written.")
    ok: bool = Field(description="Whether IDA accepted the write.")


class DebugStackFrame(BaseModel):
    """Call stack frame."""

    index: int = Field(description="Frame index.")
    call_address: str = Field(description="Call instruction/current PC address.")
    function_address: str = Field(description="Function address.")
    frame_pointer: str = Field(description="Frame pointer.")
    function_known: bool = Field(description="Whether IDA knows the function.")
    disasm: str = Field(default="", description="Disassembly at call address.")


class DebugStacktraceResult(BaseModel):
    """Call stack trace."""

    tid: int = Field(description="Thread ID.")
    frames: list[DebugStackFrame] = Field(description="Stack frames.")
    count: int = Field(description="Frame count.")


class DebugMemoryReadResult(BaseModel):
    """Debuggee memory read."""

    address: str = Field(description="Runtime address.")
    size: int = Field(description="Requested byte count.")
    bytes: str = Field(description="Read bytes as hex.")


class DebugMemoryWriteResult(BaseModel):
    """Debuggee memory write."""

    address: str = Field(description="Runtime address.")
    size: int = Field(description="Number of bytes requested.")
    written: int = Field(description="Number of bytes written, or -1 if unknown.")
    ok: bool = Field(description="Whether IDA reported success.")


class DebugMemoryRegion(BaseModel):
    """Debuggee memory region."""

    start: str = Field(description="Region start address.")
    end: str = Field(description="Region end address.")
    size: int = Field(description="Region size.")
    name: str = Field(description="Region name.")
    sclass: str = Field(description="Region class.")
    bitness: int | None = Field(default=None, description="Region bitness.")
    permissions: int | None = Field(default=None, description="IDA permission bitmask.")


class DebugMemoryMapResult(BaseModel):
    """Debuggee memory map."""

    count: int = Field(description="Number of regions.")
    regions: list[DebugMemoryRegion] = Field(description="Memory regions.")


class DebugMemoryValidityResult(BaseModel):
    """Debuggee memory validity check."""

    address: str = Field(description="Runtime address.")
    size: int = Field(description="Checked byte count.")
    valid: bool = Field(description="Whether the region was readable.")


class DebugMemoryProtectionResult(BaseModel):
    """Debuggee memory protection lookup."""

    address: str = Field(description="Runtime address.")
    region: DebugMemoryRegion | None = Field(default=None, description="Containing memory region, if found.")
    found: bool = Field(description="Whether a containing region was found.")


class DebugMemorySearchMatch(BaseModel):
    """Debuggee memory search match."""

    address: str = Field(description="Runtime match address.")


class DebugMemorySearchResult(BaseModel):
    """Debuggee memory search result."""

    pattern: str = Field(description="Searched byte pattern as hex.")
    count: int = Field(description="Number of returned matches.")
    matches: list[DebugMemorySearchMatch] = Field(description="Match addresses.")
    scanned_bytes: int = Field(description="Number of bytes scanned.")
    truncated: bool = Field(description="Whether scanning stopped because of limits.")


class DebugModule(BaseModel):
    """Runtime module summary."""

    name: str = Field(description="Module name or path.")
    base: str = Field(description="Module base address.")
    size: int = Field(description="Module image size.")
    rebase_to: str = Field(description="IDA rebase target for the module.")


class DebugModuleListResult(BaseModel):
    """Runtime module list."""

    count: int = Field(description="Number of modules.")
    modules: list[DebugModule] = Field(description="Runtime modules.")


class DebugSymbol(BaseModel):
    """Runtime/debug symbol."""

    address: str = Field(description="Symbol address.")
    name: str = Field(description="Symbol name.")
    source: str = Field(description="Symbol source.")


class DebugSymbolListResult(BaseModel):
    """Runtime/debug symbol list."""

    count: int = Field(description="Number of symbols.")
    symbols: list[DebugSymbol] = Field(description="Symbols.")


class DebugAnnotationResult(BaseModel):
    """Runtime/debug annotation result."""

    address: str = Field(description="Runtime/static address.")
    value: str = Field(description="Annotation value.")
    ok: bool = Field(description="Whether IDA accepted the mutation or lookup found a value.")


class DebugDisassemblyLine(BaseModel):
    """Runtime/static disassembly line."""

    address: str = Field(description="Instruction address.")
    text: str = Field(description="Disassembly text.")


class DebugDisassemblyResult(BaseModel):
    """Runtime/static disassembly result."""

    address: str = Field(description="Start address.")
    lines: list[DebugDisassemblyLine] = Field(description="Disassembly lines.")
    count: int = Field(description="Line count.")


class DebugPatchResult(BaseModel):
    """Runtime patch result."""

    address: str = Field(description="Patch address.")
    instruction: str = Field(description="Assembly instruction.")
    old_bytes: str = Field(description="Previous runtime bytes.")
    new_bytes: str = Field(description="New runtime bytes.")
    patched: bool = Field(description="Whether the runtime write succeeded.")


class DebugPatchListResult(BaseModel):
    """Runtime patch list."""

    count: int = Field(description="Patch count.")
    patches: list[DebugPatchResult] = Field(description="Recorded runtime patches.")


class DebugBranchDestinationResult(BaseModel):
    """Branch destination result."""

    address: str = Field(description="Instruction address.")
    destination: str = Field(description="Resolved branch/call destination.")
    ok: bool = Field(description="Whether a destination was resolved.")


class DebugLastExceptionResult(BaseModel):
    """Last debugger exception/event result."""

    event: DebugEvent | None = Field(default=None, description="Current debugger event.")
    is_exception: bool = Field(description="Whether the event appears to be an exception event.")


class DebugCurrentLocationResult(BaseModel):
    """Current debugger location."""

    process_state: str = Field(description="Human-readable process state.")
    current_thread: int | None = Field(default=None, description="Current thread ID.")
    current_ip: str | None = Field(default=None, description="Current instruction pointer.")
    current_sp: str | None = Field(default=None, description="Current stack pointer.")
    disasm: str = Field(default="", description="Disassembly at the current instruction pointer.")


class DebugDecompileCurrentResult(BaseModel):
    """Current-location decompilation result."""

    address: str = Field(description="Current instruction pointer.")
    function: str = Field(description="Containing function entry.")
    pseudocode: str = Field(description="Hex-Rays pseudocode.")


class DebugEventWaitResult(BaseModel):
    """Wait-for-event result."""

    code: int = Field(description="wait_for_next_event return code.")
    timed_out: bool = Field(description="Whether the wait timed out.")
    event: DebugEvent | None = Field(default=None, description="Debugger event.")


class DebugWaitUntilResult(BaseModel):
    """Conditional debugger event wait result."""

    matched: bool = Field(description="Whether the requested condition matched.")
    reason: str = Field(description="Match or timeout reason.")
    iterations: int = Field(description="Number of debugger events consumed.")
    event: DebugEvent | None = Field(default=None, description="Last debugger event observed.")
    process_state: str = Field(description="Final process state.")
    current_ip: str | None = Field(default=None, description="Final instruction pointer, if available.")


class DebugGenericResult(BaseModel):
    """Generic structured debugger result."""

    status: str = Field(description="Command status.")
    ok: bool = Field(description="Whether the command succeeded or is supported.")
    details: dict[str, Any] = Field(default_factory=dict, description="Command-specific details.")
    error: str | None = Field(default=None, description="Error or unsupported reason.")


class DebugCommandResult(BaseModel):
    """Debugger backend command result."""

    command: str = Field(description="Debugger command text.")
    ok: bool = Field(description="Whether the backend accepted the command.")
    output: str = Field(default="", description="Backend command output.")


class DebugProcessOptionsResult(BaseModel):
    """IDA debugger process options."""

    path: str = Field(default="", description="Configured executable path.")
    args: str = Field(default="", description="Configured command-line arguments.")
    working_directory: str = Field(default="", description="Configured starting directory.")
    host: str = Field(default="", description="Configured remote host.")
    password: str = Field(default="", description="Configured remote password or token.")
    port: int = Field(default=-1, description="Configured remote port.")
    environment: dict[str, str] = Field(default_factory=dict, description="Configured launch environment variables.")
    environment_merge: bool = Field(default=True, description="Whether configured env vars merge with target defaults.")


class DebugExceptionInfo(BaseModel):
    """Debugger exception policy entry."""

    code: int = Field(description="Exception code.")
    name: str = Field(description="Exception name.")
    description: str = Field(default="", description="Exception description.")
    flags: int = Field(description="IDA exception flags.")
    break_on: bool = Field(description="Whether IDA breaks on this exception.")
    handle: bool = Field(description="Whether IDA handles this exception.")


class DebugExceptionListResult(BaseModel):
    """Debugger exception policy list."""

    count: int = Field(description="Number of exception entries.")
    exceptions: list[DebugExceptionInfo] = Field(description="Exception policy entries.")


class DebugTraceConfigResult(BaseModel):
    """Debugger trace configuration."""

    enabled: dict[str, bool] = Field(description="Enabled state by trace type.")
    options: dict[str, int] = Field(description="Trace options by trace type.")
    event_count: int = Field(description="Number of recorded trace events.")
    base_address: str | None = Field(default=None, description="Trace base address.")
    platform: str = Field(default="", description="Trace platform, when available.")


class DebugTraceEvent(BaseModel):
    """Trace event summary."""

    index: int = Field(description="Trace event index.")
    type: int = Field(description="IDA trace event type.")
    type_name: str = Field(description="Trace event type name.")
    tid: int | None = Field(default=None, description="Thread ID.")
    address: str | None = Field(default=None, description="Trace event address.")
    debug_event: DebugEvent | None = Field(default=None, description="Associated debugger event, if any.")


class DebugTraceEventListResult(BaseModel):
    """Trace event list."""

    count: int = Field(description="Number of returned trace events.")
    total: int = Field(description="Total number of trace events in IDA.")
    events: list[DebugTraceEvent] = Field(description="Trace events.")


class DebugTraceRegistersResult(BaseModel):
    """Trace event register values."""

    index: int = Field(description="Trace event index.")
    registers: dict[str, str | int | float | None] = Field(description="Register values captured in the trace event.")


class DebugTraceMemoryItem(BaseModel):
    """Trace memory item."""

    address: str = Field(description="Memory address.")
    bytes: str = Field(description="Bytes as hex.")


class DebugTraceMemoryResult(BaseModel):
    """Trace event memory details."""

    index: int = Field(description="Trace event index.")
    memory: list[DebugTraceMemoryItem] = Field(description="Register-referenced memory snapshots.")
    regions: list[DebugMemoryRegion] = Field(default_factory=list, description="Memory map snapshot regions.")


class DebugThreadNameResult(BaseModel):
    """Thread name result."""

    tid: int = Field(description="Thread ID.")
    name: str = Field(description="Debugger thread name.")


class DebugThreadSregBaseResult(BaseModel):
    """Thread segment-register base result."""

    tid: int = Field(description="Thread ID.")
    register: str = Field(description="Segment register name used, if any.")
    sreg_value: str = Field(description="Segment register selector/value.")
    base: str | None = Field(default=None, description="Resolved segment base, or null on failure.")
    ok: bool = Field(description="Whether IDA resolved a base.")


# Populated lazily by _ensure_ida() (values reference ida_dbg/ida_idd constants).
_STATE_NAMES: dict = {}

_BPT_TYPES: dict = {}

_IP_NAMES = ("RIP", "EIP", "PC", "IP", "rip", "eip", "pc", "ip")
_SP_NAMES = ("RSP", "ESP", "SP", "rsp", "esp", "sp")

_FLAGS_NAMES = ("RFLAGS", "EFLAGS", "FLAGS", "rflags", "eflags", "flags")
_FLAG_BITS = {
    "CF": 0,
    "PF": 2,
    "AF": 4,
    "ZF": 6,
    "SF": 7,
    "TF": 8,
    "IF": 9,
    "DF": 10,
    "OF": 11,
}

# Populated lazily by _ensure_ida() (values reference ida_dbg trace functions).
_TRACE_TYPES: dict = {}

_EVENT_ALIASES = {
    "start": {"PROCESS_STARTED", "PROCESS_ATTACHED"},
    "process_start": {"PROCESS_STARTED"},
    "process_started": {"PROCESS_STARTED"},
    "attach": {"PROCESS_ATTACHED"},
    "process_attached": {"PROCESS_ATTACHED"},
    "exit": {"PROCESS_EXITED"},
    "process_exit": {"PROCESS_EXITED"},
    "process_exited": {"PROCESS_EXITED"},
    "detach": {"PROCESS_DETACHED"},
    "process_detached": {"PROCESS_DETACHED"},
    "thread_start": {"THREAD_STARTED"},
    "thread_started": {"THREAD_STARTED"},
    "thread_exit": {"THREAD_EXITED"},
    "thread_exited": {"THREAD_EXITED"},
    "module_load": {"LIB_LOADED"},
    "library_load": {"LIB_LOADED"},
    "lib_loaded": {"LIB_LOADED"},
    "module_unload": {"LIB_UNLOADED"},
    "library_unload": {"LIB_UNLOADED"},
    "lib_unloaded": {"LIB_UNLOADED"},
    "breakpoint": {"BREAKPOINT"},
    "bpt": {"BREAKPOINT"},
    "exception": {"EXCEPTION"},
    "suspend": {"PROCESS_SUSPENDED"},
    "process_suspended": {"PROCESS_SUSPENDED"},
}

_RUNTIME_PATCHES: dict[int, DebugPatchResult] = {}


def _set_batch_mode() -> None:
    if hasattr(idaapi, "cvar") and hasattr(idaapi.cvar, "batch_mode"):
        idaapi.cvar.batch_mode = True


def _parse_runtime_address(value: Address) -> int:
    if isinstance(value, int):
        return value
    try:
        return resolve_address(value)
    except Exception:
        text = str(value).strip()
        try:
            return int(text, 0)
        except ValueError:
            if text.lower().startswith("0x"):
                raise
            return int(text, 16)


def _parse_hex_bytes(value: HexBytes) -> bytes:
    cleaned = value.replace(" ", "").replace("_", "")
    if not cleaned:
        raise IDAError("Empty hex string", error_type="InvalidArgument")
    if len(cleaned) % 2:
        raise IDAError("Hex string must have an even number of digits", error_type="InvalidArgument")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise IDAError(f"Invalid hex string: {value!r}", error_type="InvalidArgument") from None


def _default_debugger_name() -> str:
    filetype = ida_ida.inf_get_filetype()
    if filetype == ida_ida.f_PE:
        return "win32"
    if filetype == ida_ida.f_ELF:
        return "linux"
    if filetype == ida_ida.f_MACHO:
        return "mac"
    return "gdb"


def _load_debugger(
    debugger: str = "",
    *,
    remote: bool = False,
    target_host: str = "",
    target_port: int | None = None,
    password: str = "",
) -> str:
    _set_batch_mode()
    dbg_name = debugger or _default_debugger_name()
    if not ida_dbg.load_debugger(dbg_name, bool(remote)):
        raise IDAError(
            f"Failed to load IDA debugger module {dbg_name!r} (remote={remote})",
            error_type="DebuggerLoadFailed",
        )
    if remote:
        if not target_host:
            raise IDAError("target_host is required for remote debugging", error_type="InvalidArgument")
        ida_dbg.set_remote_debugger(target_host, password, target_port if target_port else -1)
    return dbg_name


def _looks_like_windows_path(path: str) -> bool:
    return path.startswith("\\\\") or (len(path) >= 3 and path[1] == ":" and path[2] in {"\\", "/"})


def _target_path(path: str = "", *, remote: bool = False) -> str:
    if path:
        expanded = os.path.expanduser(path)
        if remote or _looks_like_windows_path(expanded):
            return expanded
        return os.path.realpath(expanded)
    input_path = ida_nalt.get_input_file_path()
    return os.path.realpath(input_path) if input_path else ""


def _args_to_string(args: list[str] | str | None) -> str:
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    return " ".join(shlex.quote(arg) for arg in args)


def _make_launch_env(
    environment: dict[str, Any] | None = None,
    *,
    merge: bool = True,
) -> ida_idd.launch_env_t | None:
    if not environment:
        return None
    envs = ida_idd.launch_env_t()
    envs.merge = bool(merge)
    for key, value in environment.items():
        name = str(key)
        if not name:
            raise IDAError("Environment variable names must be non-empty", error_type="InvalidArgument")
        envs.set(name, "" if value is None else str(value))
    return envs


def _set_launch_environment(
    *,
    path: str,
    args: str,
    working_directory: str,
    remote: bool,
    target_host: str,
    target_port: int | None,
    password: str,
    environment: dict[str, Any] | None,
    environment_merge: bool,
) -> None:
    envs = _make_launch_env(environment, merge=environment_merge)
    if envs is None:
        return
    try:
        ida_dbg.set_process_options(
            path or None,
            args or None,
            envs,
            working_directory or None,
            target_host or None if remote else None,
            password or None if remote else None,
            target_port if remote and target_port else -1,
        )
    except Exception as exc:
        raise IDAError(
            f"Failed to configure launch environment: {exc}",
            error_type="DebuggerLaunchEnvironmentFailed",
        ) from exc


def _event_summary() -> DebugEvent | None:
    try:
        ev = ida_dbg.get_debug_event()
    except Exception:
        return None
    if ev is None:
        return None
    return _debug_event_to_summary(ev)


class suppress_ida_errors:
    """Tiny context manager to ignore optional SWIG accessor failures."""

    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc, tb):
        return True


def _wait_for_event(timeout_seconds: int, *, continue_process: bool = False) -> DebugEventWaitResult:
    flags = ida_dbg.WFNE_ANY
    if continue_process:
        flags |= ida_dbg.WFNE_CONT
    code = int(ida_dbg.wait_for_next_event(flags, timeout_seconds))
    return DebugEventWaitResult(
        code=code,
        timed_out=code == ida_dbg.DEC_TIMEOUT,
        event=_event_summary(),
    )


def _unsupported(operation: str, reason: str, **details: Any) -> DebugGenericResult:
    return DebugGenericResult(
        status="unsupported",
        ok=False,
        error=reason,
        details={"operation": operation, **details},
    )


def _qstring_to_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _env_to_dict(envs: Any) -> dict[str, str]:
    if envs is None:
        return {}
    with suppress_ida_errors():
        raw = envs.envs()
        if isinstance(raw, dict):
            return {str(k): str(v) for k, v in raw.items()}
        if isinstance(raw, (list, tuple)):
            result: dict[str, str] = {}
            for item in raw:
                text = str(item)
                if "=" in text:
                    key, value = text.split("=", 1)
                    result[key] = value
            return result
    return {}


def _get_process_options_result() -> DebugProcessOptionsResult:
    with suppress_ida_errors():
        path, args, envs, sdir, host, password, port = ida_dbg.get_process_options2()
        return DebugProcessOptionsResult(
            path=_qstring_to_str(path),
            args=_qstring_to_str(args),
            working_directory=_qstring_to_str(sdir),
            host=_qstring_to_str(host),
            password=_qstring_to_str(password),
            port=int(port),
            environment=_env_to_dict(envs),
            environment_merge=bool(getattr(envs, "merge", True)) if envs is not None else True,
        )
    path, args, sdir, host, password, port = ida_dbg.get_process_options()
    return DebugProcessOptionsResult(
        path=_qstring_to_str(path),
        args=_qstring_to_str(args),
        working_directory=_qstring_to_str(sdir),
        host=_qstring_to_str(host),
        password=_qstring_to_str(password),
        port=int(port),
    )


def _normalize_trace_type(trace_type: str) -> str:
    key = trace_type.strip().lower().replace("-", "_") or "instruction"
    info = _TRACE_TYPES.get(key)
    if info and "alias" in info:
        key = str(info["alias"])
    if key not in _TRACE_TYPES or "alias" in _TRACE_TYPES[key]:
        raise IDAError(f"Unsupported trace type: {trace_type!r}", error_type="InvalidArgument")
    return key


def _trace_type_names(trace_types: list[str] | str | None = None) -> list[str]:
    if trace_types is None:
        return ["instruction"]
    if isinstance(trace_types, str):
        if trace_types.strip().lower() in {"all", "*"}:
            return ["step", "instruction", "function", "basic_block"]
        items = [item.strip() for item in trace_types.split(",") if item.strip()]
    else:
        items = trace_types
    return [_normalize_trace_type(item) for item in items]


def _trace_config() -> DebugTraceConfigResult:
    enabled = {}
    options = {}
    for trace_type in ["step", "instruction", "function", "basic_block"]:
        info = _TRACE_TYPES[trace_type]
        enabled[trace_type] = bool(info["enabled"]())
        options[trace_type] = int(info["get_options"]())
    base = None
    with suppress_ida_errors():
        value = ida_dbg.get_trace_base_address()
        base = None if is_bad_addr(value) else format_address(value)
    platform = ""
    with suppress_ida_errors():
        platform = str(ida_dbg.get_trace_platform() or "")
    return DebugTraceConfigResult(
        enabled=enabled,
        options=options,
        event_count=int(ida_dbg.get_tev_qty()),
        base_address=base,
        platform=platform,
    )


def _trace_event_type_name(value: int) -> str:
    for name in ("tev_none", "tev_insn", "tev_call", "tev_ret", "tev_bpt", "tev_mem", "tev_event"):
        if hasattr(ida_dbg, name) and int(getattr(ida_dbg, name)) == value:
            return name.removeprefix("tev_")
    return str(value)


def _trace_event(index: int) -> DebugTraceEvent:
    if index < 0 or index >= ida_dbg.get_tev_qty():
        raise IDAError(f"Trace event index out of range: {index}", error_type="InvalidArgument")
    info = ida_dbg.tev_info_t()
    if not ida_dbg.get_tev_info(index, info):
        raise IDAError(f"Failed to get trace event {index}", error_type="TraceEventFailed")
    ev = ida_idd.debug_event_t()
    debug_event = None
    if ida_dbg.get_tev_event(index, ev):
        debug_event = _debug_event_to_summary(ev)
    return DebugTraceEvent(
        index=index,
        type=int(info.type),
        type_name=_trace_event_type_name(int(info.type)),
        tid=None if info.tid == ida_idd.NO_THREAD else int(info.tid),
        address=None if is_bad_addr(info.ea) else format_address(info.ea),
        debug_event=debug_event,
    )


def _debug_event_to_summary(ev: ida_idd.debug_event_t) -> DebugEvent | None:
    try:
        code = int(ev.eid())
    except Exception:
        return None
    if code <= 0:
        return None
    with suppress_ida_errors():
        name = ida_idd.get_debug_event_name(ev)
    if not name:
        name = str(code)
    info = None
    exit_code = None
    with suppress_ida_errors():
        info = ev.info()
    if not info:
        with suppress_ida_errors():
            modinfo = ev.modinfo()
            info = str(modinfo.name or "")
    if not info:
        with suppress_ida_errors():
            exc = ev.exc()
            info = str(exc.info or "")
    with suppress_ida_errors():
        exit_code = int(ev.exit_code())
    return DebugEvent(
        code=code,
        name=str(name),
        pid=None if ev.pid in (-1, ida_idd.NO_PROCESS) else int(ev.pid),
        tid=None if ev.tid == ida_idd.NO_THREAD else int(ev.tid),
        address=None if is_bad_addr(ev.ea) else format_address(ev.ea),
        handled=bool(ev.handled),
        info=info or None,
        exit_code=exit_code,
    )


def _exception_to_model(item: ida_idd.exception_info_t) -> DebugExceptionInfo:
    return DebugExceptionInfo(
        code=int(item.code),
        name=str(item.name or ""),
        description=str(item.desc or ""),
        flags=int(item.flags),
        break_on=bool(item.break_on()),
        handle=bool(item.handle()),
    )


def _exception_flags(
    *,
    flags: int | None = None,
    break_on: bool | None = None,
    handle: bool | None = None,
    message: bool | None = None,
    silent: bool | None = None,
    old_flags: int = 0,
) -> int:
    value = int(old_flags if flags is None else flags)
    updates = [
        (break_on, ida_idd.EXC_BREAK),
        (handle, ida_idd.EXC_HANDLE),
        (message, ida_idd.EXC_MSG),
        (silent, ida_idd.EXC_SILENT),
    ]
    for setting, bit in updates:
        if setting is None:
            continue
        if setting:
            value |= bit
        else:
            value &= ~bit
    return value


def _region_from_mapping(item: dict[str, Any]) -> ida_idd.memory_info_t:
    region = ida_idd.memory_info_t()
    region.start_ea = _parse_runtime_address(item["start"])
    region.end_ea = _parse_runtime_address(item["end"])
    region.name = str(item.get("name", ""))
    region.sclass = str(item.get("sclass", ""))
    region.sbase = _parse_runtime_address(item.get("sbase", "0")) if item.get("sbase") is not None else 0
    region.bitness = int(item.get("bitness", 1))
    region.perm = int(item.get("permissions", item.get("perm", 0)))
    return region


def _badaddr_to_none(value: int) -> str | None:
    return None if is_bad_addr(value) else format_address(value)


def _run_requests_and_wait(wait: bool, timeout_seconds: int) -> DebugEvent | None:
    ida_dbg.run_requests()
    if not wait:
        return None
    return _wait_for_event(timeout_seconds).event


def _read_named_register(names: tuple[str, ...]) -> str | None:
    for name in names:
        try:
            value = ida_dbg.get_reg_val(name)
        except Exception:
            continue
        return _format_reg_value(value)
    return None


def _read_register_int(names: tuple[str, ...]) -> tuple[str, int] | None:
    for name in names:
        try:
            value = ida_dbg.get_reg_val(name)
        except Exception:
            continue
        if isinstance(value, int):
            return name, value
        if isinstance(value, bytes):
            return name, int.from_bytes(value, byteorder="little", signed=False)
        if isinstance(value, str):
            try:
                return name, int(value, 0)
            except ValueError:
                continue
        if hasattr(value, "ival"):
            try:
                return name, int(value.ival)
            except Exception:
                continue
    return None


def _format_reg_value(value: Any) -> str | int | float:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, int):
        return format_address(value)
    return value


def _clean_disasm_at(ea: int) -> str:
    with suppress_ida_errors():
        line = idc.generate_disasm_line(ea, 0)
        if line:
            return ida_lines.tag_remove(line)
    with suppress_ida_errors():
        line = idc.GetDisasm(ea)
        if line:
            return ida_lines.tag_remove(line)
    return ""


def _thread_ids() -> list[int]:
    return [int(ida_dbg.getn_thread(i)) for i in range(ida_dbg.get_thread_qty())]


def _current_thread() -> int | None:
    tid = int(ida_dbg.get_current_thread())
    return None if tid == ida_idd.NO_THREAD else tid


def _thread_sreg_base_impl(
    tid: int | None = None,
    sreg_value: int | None = None,
    register: str = "FS",
) -> DebugThreadSregBaseResult:
    _require_debugger_loaded()
    actual_tid = tid if tid is not None else _current_thread()
    if actual_tid is None:
        raise IDAError("No current thread", error_type="DebuggerNoCurrentThread")
    selector = sreg_value
    if selector is None and register:
        value = ida_dbg.get_reg_val(register)
        selector = int(value, 0) if isinstance(value, str) else int(value)
    if selector is None:
        raise IDAError("sreg_value or register is required", error_type="InvalidArgument")
    base = int(ida_dbg.internal_get_sreg_base(int(actual_tid), int(selector)))
    return DebugThreadSregBaseResult(
        tid=int(actual_tid),
        register=register,
        sreg_value=format_address(int(selector)),
        base=_badaddr_to_none(base),
        ok=not is_bad_addr(base),
    )


def _status() -> DebugStatusResult:
    state = int(ida_dbg.get_process_state())
    return DebugStatusResult(
        debugger_loaded=bool(ida_dbg.dbg_is_loaded()),
        debugger_name=ida_idd.dbg_get_name(),
        process_state=_STATE_NAMES.get(state, str(state)),
        process_state_id=state,
        current_thread=_current_thread(),
        current_ip=_read_named_register(_IP_NAMES),
        current_sp=_read_named_register(_SP_NAMES),
        thread_count=ida_dbg.get_thread_qty(),
        threads=_thread_ids(),
        last_event=_event_summary(),
    )


def _breakpoint_to_model(bpt: ida_dbg.bpt_t) -> DebugBreakpoint:
    return DebugBreakpoint(
        address=format_address(bpt.ea),
        size=int(bpt.size),
        type=int(bpt.type),
        enabled=bool(bpt.enabled()),
        active=bool(bpt.is_active()),
        hardware=bool(bpt.is_hwbpt()),
        condition=str(bpt.condition or ""),
        pass_count=int(bpt.pass_count),
        pid=None if bpt.pid in (-1, ida_idd.NO_PROCESS) else int(bpt.pid),
        tid=None if bpt.tid == ida_idd.NO_THREAD else int(bpt.tid),
    )


def _get_breakpoint(ea: int) -> DebugBreakpoint | None:
    bpt = ida_dbg.bpt_t()
    if not ida_dbg.get_bpt(ea, bpt):
        return None
    return _breakpoint_to_model(bpt)


def _require_debugger_loaded() -> None:
    if not ida_dbg.dbg_is_loaded():
        raise IDAError("No IDA debugger module is loaded", error_type="DebuggerNotLoaded")


def _exit_process_impl(wait: bool, timeout_seconds: int) -> DebugSimpleResult:
    _require_debugger_loaded()
    ok = bool(ida_dbg.request_exit_process())
    event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
    return DebugSimpleResult(status="exit_requested", ok=ok, event=event)


def _start_process_impl(
    target_path: str = "",
    args: list[str] | str | None = None,
    working_directory: str = "",
    environment: dict[str, Any] | None = None,
    environment_merge: bool = True,
    debugger: str = "",
    remote: bool = False,
    target_host: str = "",
    target_port: int | None = None,
    password: str = "",
    wait: bool = True,
    timeout_seconds: int = 10,
) -> DebugStartResult:
    dbg_name = _load_debugger(
        debugger,
        remote=remote,
        target_host=target_host,
        target_port=target_port,
        password=password,
    )
    path = _target_path(target_path, remote=remote)
    arg_string = _args_to_string(args)
    _set_launch_environment(
        path=path,
        args=arg_string,
        working_directory=working_directory,
        remote=remote,
        target_host=target_host,
        target_port=target_port,
        password=password,
        environment=environment,
        environment_merge=environment_merge,
    )
    result = int(ida_dbg.start_process(path or None, arg_string or None, working_directory or None))
    event = _wait_for_event(timeout_seconds).event if wait and result == 1 else None
    return DebugStartResult(
        status="started" if result == 1 else "not_started",
        debugger=dbg_name,
        remote=remote,
        target_host=target_host or None,
        target_port=target_port,
        target_path=path,
        working_directory=working_directory,
        environment_count=len(environment or {}),
        environment_merge=environment_merge,
        result_code=result,
        event=event,
    )


def _read_registers_impl(
    tid: int | None = None,
    names: list[str] | None = None,
) -> DebugRegistersResult:
    _require_debugger_loaded()
    if names:
        values = {}
        for name in names:
            values[name] = _format_reg_value(ida_dbg.get_reg_val(name))
        return DebugRegistersResult(tid=tid, registers=values)

    actual_tid = tid if tid is not None else _current_thread()
    if actual_tid is None:
        actual_tid = ida_idd.NO_THREAD
    dbg = ida_idd.get_dbg()
    regvals = ida_dbg.get_reg_vals(actual_tid)
    values = {}
    for idx, rv in enumerate(regvals):
        rinfo = dbg.regs(idx)
        values[rinfo.name] = _format_reg_value(rv.pyval(rinfo.dtype))
    return DebugRegistersResult(tid=None if actual_tid == ida_idd.NO_THREAD else actual_tid, registers=values)


def _read_memory_impl(address: Address, size: int = 256) -> DebugMemoryReadResult:
    _require_debugger_loaded()
    if size <= 0:
        raise IDAError("size must be positive", error_type="InvalidArgument")
    ea = _parse_runtime_address(address)
    data = ida_idd.dbg_read_memory(ea, size)
    if data is None:
        raise IDAError(f"Failed to read debuggee memory at {format_address(ea)}", error_type="DebuggerMemoryReadFailed")
    return DebugMemoryReadResult(address=format_address(ea), size=size, bytes=data.hex())


def _memory_regions() -> list[DebugMemoryRegion]:
    info = ida_idd.dbg_get_memory_info()
    regions = []
    if not info:
        return regions
    for item in info:
        try:
            start = item.start_ea
            end = item.end_ea
            name = item.name
            sclass = item.sclass
            bitness = item.bitness
            perm = item.perm
        except AttributeError:
            start, end, name, sclass, _sbase, bitness, perm = item
        regions.append(
            DebugMemoryRegion(
                start=format_address(start),
                end=format_address(end),
                size=int(end - start),
                name=str(name),
                sclass=str(sclass),
                bitness=int(bitness),
                permissions=int(perm),
            )
        )
    return regions


def _manual_regions_result() -> DebugMemoryMapResult:
    regions = []
    for item in ida_dbg.get_manual_regions() or []:
        start, end, name, sclass, _sbase, bitness, perm = item
        regions.append(
            DebugMemoryRegion(
                start=format_address(start),
                end=format_address(end),
                size=end - start,
                name=str(name or ""),
                sclass=str(sclass or ""),
                bitness=int(bitness),
                permissions=int(perm),
            )
        )
    return DebugMemoryMapResult(count=len(regions), regions=regions)


def _search_memory_range(
    start: int,
    end: int,
    pattern: bytes,
    max_results: int,
) -> tuple[list[int], int]:
    chunk_size = 0x10000
    overlap = max(len(pattern) - 1, 0)
    matches = []
    scanned = 0
    offset = start
    previous = b""
    while offset < end and len(matches) < max_results:
        size = min(chunk_size, end - offset)
        data = ida_idd.dbg_read_memory(offset, size)
        if not data:
            offset += size
            previous = b""
            continue
        haystack = previous + data
        base = offset - len(previous)
        index = haystack.find(pattern)
        while index != -1 and len(matches) < max_results:
            matches.append(base + index)
            index = haystack.find(pattern, index + 1)
        previous = haystack[-overlap:] if overlap else b""
        scanned += len(data)
        offset += size
    return matches, scanned


def _module_to_model(module: ida_idd.modinfo_t) -> DebugModule:
    return DebugModule(
        name=str(module.name),
        base=format_address(module.base),
        size=int(module.size),
        rebase_to=format_address(module.rebase_to),
    )


def _module_list() -> list[DebugModule]:
    module = ida_idd.modinfo_t()
    modules = []
    if not ida_dbg.get_first_module(module):
        return modules
    while True:
        modules.append(_module_to_model(module))
        if not ida_dbg.get_next_module(module):
            break
    return modules


def _module_list_result() -> DebugModuleListResult:
    _require_debugger_loaded()
    modules = _module_list()
    return DebugModuleListResult(count=len(modules), modules=modules)


def _symbol_list_impl(
    address: Address | None = None,
    size: int = 0,
    module: str = "",
    max_results: int = 256,
) -> DebugSymbolListResult:
    _require_debugger_loaded()
    if max_results <= 0:
        raise IDAError("max_results must be positive", error_type="InvalidArgument")
    if address is not None:
        if size <= 0:
            raise IDAError("size must be positive when address is provided", error_type="InvalidArgument")
        start = _parse_runtime_address(address)
        end = start + size
    elif module:
        item = _module_info_impl(module=module)
        if item is None:
            return DebugSymbolListResult(count=0, symbols=[])
        start = int(item.base, 16)
        end = start + item.size
    else:
        raise IDAError("address or module is required", error_type="InvalidArgument")
    names = ida_name.get_debug_names(start, end)
    symbols = [
        DebugSymbol(address=format_address(ea), name=str(name), source="debug_name")
        for ea, name in sorted(names.items())[: min(max_results, 1000)]
    ]
    return DebugSymbolListResult(count=len(symbols), symbols=symbols)


def _module_info_impl(address: Address | None = None, module: str = "") -> DebugModule | None:
    _require_debugger_loaded()
    if address is not None:
        ea = _parse_runtime_address(address)
        info = ida_idd.modinfo_t()
        if ida_dbg.get_module_info(ea, info):
            return _module_to_model(info)
        return None
    if module:
        needle = module.lower()
        for item in _module_list():
            if needle in item.name.lower():
                return item
    raise IDAError("address or module is required", error_type="InvalidArgument")


def _comment_set_impl(address: Address, comment: str) -> DebugAnnotationResult:
    ea = _parse_runtime_address(address)
    ok = bool(idc.set_cmt(ea, comment, 1))
    return DebugAnnotationResult(address=format_address(ea), value=comment, ok=ok)


def _assemble_at(ea: int, instruction: str) -> bytes:
    result = idautils.Assemble(ea, instruction)
    if isinstance(result, str):
        raise IDAError(result, error_type="AssemblyFailed")
    success, assembled_bytes = result
    if not success:
        raise IDAError(f"Failed to assemble: {instruction!r}", error_type="AssemblyFailed")
    return assembled_bytes


def register(mcp: FastMCP):
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_status() -> DebugStatusResult:
        """Return live IDA debugger state for this database."""
        return _status()

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_wait_until(
        event: str = "",
        address: Address | None = None,
        module: str = "",
        timeout_seconds: int = 30,
        continue_process: bool = True,
    ) -> DebugWaitUntilResult:
        """Wait until a debugger event/address/module condition is observed."""
        _require_debugger_loaded()
        wanted_names = set()
        if event:
            wanted_names = _EVENT_ALIASES.get(event.strip().lower(), {event.strip().upper()})
        wanted_address = _parse_runtime_address(address) if address is not None else None
        module_lower = module.lower()
        deadline = time.monotonic() + max(1, timeout_seconds)
        iterations = 0
        last_event = _event_summary()
        reason = "timeout"
        matched = False
        while time.monotonic() < deadline:
            status = _status()
            current_ip = int(status.current_ip, 16) if status.current_ip else None
            ev = last_event
            name = (ev.name if ev else "").upper()
            info = (ev.info if ev else "") or ""
            event_ok = not wanted_names or name in wanted_names or any(wanted in name for wanted in wanted_names)
            address_ok = wanted_address is None or (
                (ev and ev.address and int(ev.address, 16) == wanted_address)
                or current_ip == wanted_address
            )
            module_ok = not module_lower or module_lower in info.lower()
            if event_ok and address_ok and module_ok:
                matched = True
                reason = "matched"
                break
            remaining = max(1, int(deadline - time.monotonic()))
            waited = _wait_for_event(min(5, remaining), continue_process=continue_process)
            iterations += 1
            last_event = waited.event
            if waited.timed_out:
                reason = "timeout"
                break
        status = _status()
        return DebugWaitUntilResult(
            matched=matched,
            reason=reason,
            iterations=iterations,
            event=last_event,
            process_state=status.process_state,
            current_ip=status.current_ip,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_process_options_get() -> DebugProcessOptionsResult:
        """Return IDA debugger launch/process options."""
        return _get_process_options_result()

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_process_options_set(
        target_path: str = "",
        args: list[str] | str | None = None,
        working_directory: str = "",
        environment: dict[str, Any] | None = None,
        environment_merge: bool = True,
        remote: bool = False,
        target_host: str = "",
        target_port: int | None = None,
        password: str = "",
    ) -> DebugProcessOptionsResult:
        """Set IDA debugger launch/process options without starting the process."""
        path = _target_path(target_path, remote=remote) if target_path else None
        arg_string = _args_to_string(args) if args is not None else None
        envs = _make_launch_env(environment, merge=environment_merge) if environment else None
        ida_dbg.set_process_options(
            path,
            arg_string,
            envs,
            working_directory or None,
            target_host or None if remote else None,
            password or None if remote else None,
            target_port if remote and target_port else -1,
        )
        return _get_process_options_result()

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_exception_list() -> DebugExceptionListResult:
        """List debugger exception handling policies."""
        items = [_exception_to_model(item) for item in ida_dbg.retrieve_exceptions()]
        return DebugExceptionListResult(count=len(items), exceptions=items)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_exception_set(
        code: int,
        name: str = "",
        description: str = "",
        flags: int | None = None,
        break_on: bool | None = None,
        handle: bool | None = None,
        message: bool | None = None,
        silent: bool | None = None,
    ) -> DebugExceptionInfo:
        """Add or update one debugger exception policy."""
        exceptions = ida_dbg.retrieve_exceptions()
        for item in exceptions:
            if int(item.code) != int(code):
                continue
            item.name = name or item.name
            item.desc = description or item.desc
            item.flags = _exception_flags(
                flags=flags,
                break_on=break_on,
                handle=handle,
                message=message,
                silent=silent,
                old_flags=int(item.flags),
            )
            if not ida_dbg.store_exceptions():
                raise IDAError("Failed to store exception policies", error_type="ExceptionStoreFailed")
            return _exception_to_model(item)
        new_flags = _exception_flags(
            flags=flags,
            break_on=break_on,
            handle=handle,
            message=message,
            silent=silent,
        )
        error = ida_dbg.define_exception(int(code), name or hex(int(code)), description, new_flags)
        if error:
            raise IDAError(str(error), error_type="ExceptionDefineFailed")
        if not ida_dbg.store_exceptions():
            raise IDAError("Failed to store exception policies", error_type="ExceptionStoreFailed")
        for item in ida_dbg.retrieve_exceptions():
            if int(item.code) == int(code):
                return _exception_to_model(item)
        raise IDAError("Exception was not found after creation", error_type="ExceptionNotFound")

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_exception_continue(
        handled: bool = True,
        wait: bool = False,
        timeout_seconds: int = 10,
    ) -> DebugSimpleResult:
        """Continue after the current exception as handled or unhandled."""
        _require_debugger_loaded()
        ev = ida_dbg.get_debug_event()
        if ev is not None:
            ev.handled = bool(handled)
            with suppress_ida_errors():
                ida_dbg.handle_debug_event(ev, 0)
        ok = bool(ida_dbg.request_continue_process())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="exception_continue_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_send_command(command: str) -> DebugCommandResult:
        """Send a raw command to debugger backends that support command channels."""
        _require_debugger_loaded()
        ok, output = ida_dbg.send_dbg_command(command)
        return DebugCommandResult(command=command, ok=bool(ok), output=str(output or ""))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_appcall(
        function: Address,
        prototype: str = "",
        args: list[Any] | None = None,
        options: int | None = None,
    ) -> DebugGenericResult:
        """Call a debuggee function through IDA Appcall."""
        _require_debugger_loaded()
        call_args = args or []
        target: str | int
        if isinstance(function, str):
            with suppress_ida_errors():
                target = _parse_runtime_address(function)
            if "target" not in locals():
                target = function
        else:
            target = int(function)
        old_options = None
        if options is not None:
            old_options = ida_idd.Appcall.set_appcall_options(int(options))
        try:
            if prototype:
                callable_obj = ida_idd.Appcall.proto(target, prototype)
            else:
                callable_obj = ida_idd.Appcall[target] if isinstance(target, str) else ida_idd.Appcall[target]
            result = callable_obj(*call_args)
        finally:
            if old_options is not None:
                ida_idd.Appcall.set_appcall_options(old_options)
        return DebugGenericResult(
            status="appcall_completed",
            ok=True,
            details={"function": str(function), "result": repr(result), "result_type": type(result).__name__},
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_appcall_cleanup(tid: int | None = None) -> DebugGenericResult:
        """Cleanup IDA Appcall state for a thread."""
        actual_tid = tid if tid is not None else ida_idd.NO_THREAD
        result = int(ida_idd.cleanup_appcall(actual_tid))
        return DebugGenericResult(status="appcall_cleanup", ok=result == 0, details={"tid": actual_tid, "result": result})

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_start(
        target_path: str = "",
        args: list[str] | str | None = None,
        working_directory: str = "",
        environment: dict[str, Any] | None = None,
        environment_merge: bool = True,
        debugger: str = "",
        remote: bool = False,
        target_host: str = "",
        target_port: int | None = None,
        password: str = "",
        wait: bool = True,
        timeout_seconds: int = 10,
    ) -> DebugStartResult:
        """Launch a target under the IDA debugger.

        For remote debugging, launch the matching IDA dbgsrv on the target first,
        then pass remote=True with target_host/target_port.
        """
        return _start_process_impl(
            target_path=target_path,
            args=args,
            working_directory=working_directory,
            environment=environment,
            environment_merge=environment_merge,
            debugger=debugger,
            remote=remote,
            target_host=target_host,
            target_port=target_port,
            password=password,
            wait=wait,
            timeout_seconds=timeout_seconds,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_launch(
        target_path: str = "",
        args: list[str] | str | None = None,
        working_directory: str = "",
        environment: dict[str, Any] | None = None,
        environment_merge: bool = True,
        debugger: str = "",
        remote: bool = False,
        target_host: str = "",
        target_port: int | None = None,
        password: str = "",
        wait: bool = True,
        timeout_seconds: int = 10,
    ) -> DebugStartResult:
        """Alias for debug_start."""
        return _start_process_impl(
            target_path=target_path,
            args=args,
            working_directory=working_directory,
            environment=environment,
            environment_merge=environment_merge,
            debugger=debugger,
            remote=remote,
            target_host=target_host,
            target_port=target_port,
            password=password,
            wait=wait,
            timeout_seconds=timeout_seconds,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_attach(
        pid: int,
        debugger: str = "",
        remote: bool = False,
        target_host: str = "",
        target_port: int | None = None,
        password: str = "",
        wait: bool = True,
        timeout_seconds: int = 10,
    ) -> DebugAttachResult:
        """Attach to a process using the IDA debugger."""
        dbg_name = _load_debugger(
            debugger,
            remote=remote,
            target_host=target_host,
            target_port=target_port,
            password=password,
        )
        result = int(ida_dbg.attach_process(pid, -1))
        event = _wait_for_event(timeout_seconds).event if wait and result == 1 else None
        return DebugAttachResult(
            status="attached" if result == 1 else "not_attached",
            debugger=dbg_name,
            remote=remote,
            target_host=target_host or None,
            target_port=target_port,
            pid=pid,
            result_code=result,
            event=event,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_process_list(
        debugger: str = "",
        remote: bool = False,
        target_host: str = "",
        target_port: int | None = None,
        password: str = "",
    ) -> DebugProcessListResult:
        """List attachable processes known to the loaded debugger."""
        _load_debugger(
            debugger,
            remote=remote,
            target_host=target_host,
            target_port=target_port,
            password=password,
        )
        processes = ida_idd.procinfo_vec_t()
        count = int(ida_dbg.get_processes(processes))
        if count < 0:
            raise IDAError("Debugger failed to enumerate processes", error_type="DebuggerProcessListFailed")
        items = [DebugProcess(pid=int(p.pid), name=str(p.name)) for p in processes]
        return DebugProcessListResult(count=len(items), processes=items)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_exit(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Terminate the active debuggee."""
        return _exit_process_impl(wait=wait, timeout_seconds=timeout_seconds)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_detach(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Detach from the active debuggee."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.request_detach_process())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="detach_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"debugger"})
    @session.require_open
    def debug_kill(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Alias for debug_exit."""
        return _exit_process_impl(wait=wait, timeout_seconds=timeout_seconds)

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"debugger"})
    @session.require_open
    def debug_restart(
        target_path: str = "",
        args: list[str] | str | None = None,
        working_directory: str = "",
        environment: dict[str, Any] | None = None,
        environment_merge: bool = True,
        debugger: str = "",
        remote: bool = False,
        target_host: str = "",
        target_port: int | None = None,
        password: str = "",
        wait: bool = True,
        timeout_seconds: int = 10,
    ) -> DebugStartResult:
        """Terminate the current debuggee if present, then launch again."""
        if ida_dbg.dbg_is_loaded() and ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK:
            if ida_dbg.request_exit_process():
                _run_requests_and_wait(True, timeout_seconds)
        return _start_process_impl(
            target_path=target_path,
            args=args,
            working_directory=working_directory,
            environment=environment,
            environment_merge=environment_merge,
            debugger=debugger,
            remote=remote,
            target_host=target_host,
            target_port=target_port,
            password=password,
            wait=wait,
            timeout_seconds=timeout_seconds,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_continue(wait: bool = False, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Resume execution in the active debugger session."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.request_continue_process())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="continue_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_pause(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Suspend the active debuggee."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.request_suspend_process())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="pause_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_run_to(
        address: Address,
        wait: bool = True,
        timeout_seconds: int = 10,
    ) -> DebugSimpleResult:
        """Run until a runtime/static address is reached."""
        _require_debugger_loaded()
        ea = _parse_runtime_address(address)
        ok = bool(ida_dbg.request_run_to(ea))
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="run_to_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_step_into(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Step one instruction, entering calls."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.request_step_into())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="step_into_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_step_over(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Step one instruction, stepping over calls."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.request_step_over())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="step_over_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_step_out(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Run until the current function returns."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.request_step_until_ret())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="step_out_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_source_location() -> DebugGenericResult:
        """Return current source file/line if source debugging is available."""
        _require_debugger_loaded()
        source_file = ""
        line = -1
        with suppress_ida_errors():
            source_file = str(ida_dbg.get_current_source_file() or "")
        with suppress_ida_errors():
            line = int(ida_dbg.get_current_source_line())
        return DebugGenericResult(
            status="ok" if source_file or line >= 0 else "unavailable",
            ok=bool(source_file or line >= 0),
            details={"file": source_file, "line": line},
            error=None if source_file or line >= 0 else "No source location is available from the active debugger.",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_source_path_map_add(source: str, destination: str) -> DebugGenericResult:
        """Add a source path mapping for source-level debugging."""
        ida_dbg.add_path_mapping(source, destination)
        return DebugGenericResult(status="source_path_mapping_added", ok=True, details={"source": source, "destination": destination})

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_source_step_into(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Source-level step into."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.srcdbg_request_step_into())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="source_step_into_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_source_step_over(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Source-level step over."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.srcdbg_request_step_over())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="source_step_over_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_source_step_out(wait: bool = True, timeout_seconds: int = 10) -> DebugSimpleResult:
        """Source-level step out."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.srcdbg_request_step_until_ret())
        event = _run_requests_and_wait(wait, timeout_seconds) if ok else None
        return DebugSimpleResult(status="source_step_out_requested", ok=ok, event=event)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_event_wait(
        timeout_seconds: int = 10,
        continue_process: bool = False,
    ) -> DebugEventWaitResult:
        """Wait for the next debugger event."""
        _require_debugger_loaded()
        return _wait_for_event(timeout_seconds, continue_process=continue_process)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_last_exception() -> DebugLastExceptionResult:
        """Return the current debugger event, marked if it appears exception-related."""
        _require_debugger_loaded()
        event = _event_summary()
        name = (event.name if event else "").lower()
        return DebugLastExceptionResult(event=event, is_exception="exception" in name or "exc" in name)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_trace_enable(trace_types: list[str] | str | None = None) -> DebugTraceConfigResult:
        """Enable one or more IDA trace types: step, instruction, function, basic_block, or all."""
        for trace_type in _trace_type_names(trace_types):
            _TRACE_TYPES[trace_type]["enable"](True)
        return _trace_config()

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_trace_disable(trace_types: list[str] | str | None = None) -> DebugTraceConfigResult:
        """Disable one or more IDA trace types: step, instruction, function, basic_block, or all."""
        for trace_type in _trace_type_names(trace_types):
            _TRACE_TYPES[trace_type]["disable"]()
        return _trace_config()

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_trace_config_get() -> DebugTraceConfigResult:
        """Return IDA trace configuration and event count."""
        return _trace_config()

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_trace_config_set(
        trace_type: str = "",
        options: int | None = None,
        trace_size: int | None = None,
        base_address: Address | None = None,
        platform: str = "",
    ) -> DebugTraceConfigResult:
        """Update IDA trace options, circular buffer size, base address, or platform."""
        if trace_type and options is not None:
            normalized = _normalize_trace_type(trace_type)
            _TRACE_TYPES[normalized]["set_options"](int(options))
        if trace_size is not None:
            if not ida_dbg.set_trace_size(int(trace_size)):
                raise IDAError("Failed to set trace size", error_type="TraceConfigFailed")
        if base_address is not None:
            ida_dbg.set_trace_base_address(_parse_runtime_address(base_address))
        if platform:
            ida_dbg.set_trace_platform(platform)
        return _trace_config()

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_trace_clear() -> DebugGenericResult:
        """Clear IDA's trace buffer."""
        ida_dbg.clear_trace()
        return DebugGenericResult(status="trace_cleared", ok=True, details={"event_count": int(ida_dbg.get_tev_qty())})

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_trace_events(offset: int = 0, limit: int = 50) -> DebugTraceEventListResult:
        """List trace events from IDA's trace buffer."""
        total = int(ida_dbg.get_tev_qty())
        bounded_offset = max(0, offset)
        bounded_limit = max(1, min(limit, 500))
        events = [_trace_event(index) for index in range(bounded_offset, min(total, bounded_offset + bounded_limit))]
        return DebugTraceEventListResult(count=len(events), total=total, events=events)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_trace_event_get(index: int) -> DebugTraceEvent:
        """Return one trace event."""
        return _trace_event(index)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_trace_registers_get(index: int, names: list[str] | None = None) -> DebugTraceRegistersResult:
        """Return register values recorded for an instruction trace event."""
        wanted = names or ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP"]
        values: dict[str, str | int | float | None] = {}
        for name in wanted:
            with suppress_ida_errors():
                values[name] = _format_reg_value(ida_dbg.get_tev_reg_val(index, name))
        return DebugTraceRegistersResult(index=index, registers=values)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_trace_memory_get(index: int) -> DebugTraceMemoryResult:
        """Return memory snapshots associated with a trace event."""
        items: list[DebugTraceMemoryItem] = []
        qty = ida_dbg.get_tev_reg_mem_qty(index) or 0
        for item_index in range(int(qty)):
            ea = ida_dbg.get_tev_reg_mem_ea(index, item_index)
            raw = ida_dbg.get_tev_reg_mem(index, item_index)
            try:
                data = bytes(raw)
            except Exception:
                data = bytes(raw or b"")
            items.append(DebugTraceMemoryItem(address=format_address(ea), bytes=data.hex()))
        regions = []
        storage = ida_idd.meminfo_vec_t()
        if ida_dbg.get_tev_memory_info(index, storage):
            for region in storage:
                regions.append(
                    DebugMemoryRegion(
                        start=format_address(region.start_ea),
                        end=format_address(region.end_ea),
                        size=region.end_ea - region.start_ea,
                        name=str(region.name or ""),
                        sclass=str(region.sclass or ""),
                        bitness=int(region.bitness),
                        permissions=int(region.perm),
                    )
                )
        return DebugTraceMemoryResult(index=index, memory=items, regions=regions)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_trace_save(file_path: str, description: str = "") -> DebugGenericResult:
        """Save IDA's trace buffer to a trace file."""
        ok = bool(ida_dbg.save_trace_file(file_path, description))
        return DebugGenericResult(status="trace_saved" if ok else "trace_not_saved", ok=ok, details={"file_path": file_path})

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_trace_load(file_path: str) -> DebugGenericResult:
        """Load an IDA trace file."""
        error = ida_dbg.load_trace_file(file_path)
        ok = error is None
        return DebugGenericResult(status="trace_loaded" if ok else "trace_not_loaded", ok=ok, error=None if ok else str(error), details={"file_path": file_path})

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_thread_list() -> DebugThreadListResult:
        """List debuggee threads."""
        _require_debugger_loaded()
        threads = _thread_ids()
        return DebugThreadListResult(current_thread=_current_thread(), threads=threads, count=len(threads))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_thread_select(tid: int) -> DebugSimpleResult:
        """Select the current debugger thread."""
        _require_debugger_loaded()
        ok = bool(ida_dbg.select_thread(tid))
        return DebugSimpleResult(status="thread_selected" if ok else "thread_not_selected", ok=ok)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_thread_suspend(tid: int) -> DebugSimpleResult:
        """Suspend one debuggee thread."""
        _require_debugger_loaded()
        result = int(ida_dbg.request_suspend_thread(tid))
        ida_dbg.run_requests()
        return DebugSimpleResult(status="thread_suspend_requested", ok=result != 0)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_thread_resume(tid: int) -> DebugSimpleResult:
        """Resume one debuggee thread."""
        _require_debugger_loaded()
        result = int(ida_dbg.request_resume_thread(tid))
        ida_dbg.run_requests()
        return DebugSimpleResult(status="thread_resume_requested", ok=result != 0)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_thread_name_get(tid: int | None = None) -> DebugThreadNameResult:
        """Return a thread name by ID or the current thread."""
        _require_debugger_loaded()
        actual_tid = tid if tid is not None else _current_thread()
        if actual_tid is None:
            raise IDAError("No current thread", error_type="DebuggerNoCurrentThread")
        for index in range(ida_dbg.get_thread_qty()):
            if int(ida_dbg.getn_thread(index)) == int(actual_tid):
                return DebugThreadNameResult(tid=int(actual_tid), name=str(ida_dbg.getn_thread_name(index) or ""))
        raise IDAError(f"Unknown thread: {actual_tid}", error_type="DebuggerUnknownThread")

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_thread_sreg_base(
        tid: int | None = None,
        sreg_value: int | None = None,
        register: str = "FS",
    ) -> DebugThreadSregBaseResult:
        """Resolve a segment-register base for a thread."""
        return _thread_sreg_base_impl(tid=tid, sreg_value=sreg_value, register=register)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_thread_teb(tid: int | None = None) -> DebugThreadSregBaseResult:
        """Return the likely Windows TEB base using FS on 32-bit or GS on 64-bit."""
        register = "GS" if ida_ida.inf_get_app_bitness() == 64 else "FS"
        return _thread_sreg_base_impl(tid=tid, register=register)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_list() -> DebugBreakpointListResult:
        """List IDA breakpoints."""
        breakpoints = []
        for idx in range(ida_dbg.get_bpt_qty()):
            bpt = ida_dbg.bpt_t()
            if ida_dbg.getn_bpt(idx, bpt):
                breakpoints.append(_breakpoint_to_model(bpt))
        return DebugBreakpointListResult(count=len(breakpoints), breakpoints=breakpoints)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_add(
        address: Address,
        size: int = 0,
        type: str = "default",
        condition: str = "",
        low_level_condition: bool = False,
    ) -> DebugBreakpointResult:
        """Add a software, hardware, read, write, or execute breakpoint."""
        ea = _parse_runtime_address(address)
        bpt_type = _BPT_TYPES.get(type.lower())
        if bpt_type is None:
            raise IDAError(f"Unsupported breakpoint type: {type!r}", error_type="InvalidArgument")
        ok = bool(ida_dbg.add_bpt(ea, size, bpt_type))
        if not ok and _get_breakpoint(ea) is not None:
            ok = True
        if ok and condition:
            ok = bool(idc.set_bpt_cond(ea, condition, 1 if low_level_condition else 0))
        return DebugBreakpointResult(address=format_address(ea), ok=ok, breakpoint=_get_breakpoint(ea))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_delete(address: Address) -> DebugBreakpointResult:
        """Delete a breakpoint."""
        ea = _parse_runtime_address(address)
        old = _get_breakpoint(ea)
        ok = bool(ida_dbg.del_bpt(ea))
        return DebugBreakpointResult(address=format_address(ea), ok=ok, breakpoint=None if ok else old)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_toggle(address: Address, enabled: bool = True) -> DebugBreakpointResult:
        """Enable or disable an existing breakpoint."""
        ea = _parse_runtime_address(address)
        ok = bool(ida_dbg.enable_bpt(ea, enabled))
        return DebugBreakpointResult(address=format_address(ea), ok=ok, breakpoint=_get_breakpoint(ea))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_condition_set(
        address: Address,
        condition: str = "",
        low_level_condition: bool = False,
    ) -> DebugBreakpointResult:
        """Set or clear a breakpoint condition."""
        ea = _parse_runtime_address(address)
        ok = bool(idc.set_bpt_cond(ea, condition, 1 if low_level_condition else 0))
        return DebugBreakpointResult(address=format_address(ea), ok=ok, breakpoint=_get_breakpoint(ea))

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_get(address: Address) -> DebugBreakpointResult:
        """Return one breakpoint by address."""
        ea = _parse_runtime_address(address)
        bpt = _get_breakpoint(ea)
        return DebugBreakpointResult(address=format_address(ea), ok=bpt is not None, breakpoint=bpt)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_update(
        address: Address,
        size: int | None = None,
        type: str = "",
        pass_count: int | None = None,
        condition: str | None = None,
        low_level_condition: bool | None = None,
        enabled: bool | None = None,
    ) -> DebugBreakpointResult:
        """Update breakpoint size/type/pass count/condition/enabled state."""
        ea = _parse_runtime_address(address)
        bpt = ida_dbg.bpt_t()
        if not ida_dbg.get_bpt(ea, bpt):
            raise IDAError(f"No breakpoint at {format_address(ea)}", error_type="BreakpointNotFound")
        if size is not None:
            bpt.size = int(size)
        if type:
            bpt_type = _BPT_TYPES.get(type.lower())
            if bpt_type is None:
                raise IDAError(f"Unsupported breakpoint type: {type!r}", error_type="InvalidArgument")
            bpt.type = bpt_type
        if pass_count is not None:
            bpt.pass_count = int(pass_count)
        if condition is not None:
            bpt.condition = condition
        if low_level_condition is not None:
            current_condition = condition if condition is not None else str(bpt.condition or "")
            idc.set_bpt_cond(ea, current_condition, 1 if low_level_condition else 0)
            ida_dbg.get_bpt(ea, bpt)
        ok = bool(ida_dbg.update_bpt(bpt))
        if enabled is not None:
            ok = bool(ida_dbg.enable_bpt(ea, enabled)) and ok
        return DebugBreakpointResult(address=format_address(ea), ok=ok, breakpoint=_get_breakpoint(ea))

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_group_set(address: Address, group: str) -> DebugBreakpointResult:
        """Move a breakpoint into a breakpoint group/folder."""
        ea = _parse_runtime_address(address)
        bpt = ida_dbg.bpt_t()
        if not ida_dbg.get_bpt(ea, bpt):
            raise IDAError(f"No breakpoint at {format_address(ea)}", error_type="BreakpointNotFound")
        ok = bool(ida_dbg.set_bpt_group(bpt, group))
        return DebugBreakpointResult(address=format_address(ea), ok=ok, breakpoint=_get_breakpoint(ea))

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_group_list() -> DebugGenericResult:
        """List breakpoint groups/folders."""
        groups = ida_dbg.list_bptgrps() or []
        return DebugGenericResult(status="ok", ok=True, details={"groups": [str(group) for group in groups]})

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_group_enable(group: str, enabled: bool = True) -> DebugGenericResult:
        """Enable or disable all breakpoints in a group."""
        count = int(ida_dbg.enable_bptgrp(group, enabled))
        return DebugGenericResult(status="updated", ok=count >= 0, details={"group": group, "enabled": enabled, "count": count})

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"debugger"})
    @session.require_open
    def debug_breakpoint_group_delete(group: str) -> DebugGenericResult:
        """Delete a breakpoint group/folder."""
        ok = bool(ida_dbg.del_bptgrp(group))
        return DebugGenericResult(status="deleted" if ok else "not_deleted", ok=ok, details={"group": group})

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_registers_read(
        tid: int | None = None,
        names: list[str] | None = None,
    ) -> DebugRegistersResult:
        """Read all registers or a selected list of register names."""
        return _read_registers_impl(tid=tid, names=names)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_gp_registers_read(tid: int | None = None) -> DebugRegistersResult:
        """Read common general-purpose registers."""
        preferred = [
            "RAX",
            "RBX",
            "RCX",
            "RDX",
            "RSI",
            "RDI",
            "RBP",
            "RSP",
            "RIP",
            "EAX",
            "EBX",
            "ECX",
            "EDX",
            "ESI",
            "EDI",
            "EBP",
            "ESP",
            "EIP",
        ]
        all_regs = _read_registers_impl(tid=tid)
        gp = {name: value for name, value in all_regs.registers.items() if name.upper() in preferred}
        return DebugRegistersResult(tid=all_regs.tid, registers=gp)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_register_write(register: str, value: str | int | float) -> DebugRegisterWriteResult:
        """Write one register value by name."""
        _require_debugger_loaded()
        parsed: str | int | float = value
        if isinstance(value, str):
            with suppress_ida_errors():
                parsed = int(value, 0)
        ok = bool(ida_dbg.set_reg_val(register, parsed))
        return DebugRegisterWriteResult(register_name=register, value=value, ok=ok)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_flags_read(flag: str = "") -> DebugFlagsResult:
        """Read common CPU flags from RFLAGS/EFLAGS."""
        _require_debugger_loaded()
        register = _read_register_int(_FLAGS_NAMES)
        if register is None:
            raise IDAError("No FLAGS/EFLAGS/RFLAGS register is available", error_type="DebuggerRegisterUnavailable")
        register_name, value = register
        decoded = {name: bool(value & (1 << bit)) for name, bit in _FLAG_BITS.items()}
        if flag:
            wanted = flag.upper()
            if wanted not in decoded:
                raise IDAError(f"Unsupported flag: {flag!r}", error_type="InvalidArgument")
            decoded = {wanted: decoded[wanted]}
        return DebugFlagsResult(register_name=register_name, value=format_address(value), flags=decoded)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_flags_write(flag: str, value: bool) -> DebugFlagWriteResult:
        """Set or clear one common CPU flag in RFLAGS/EFLAGS."""
        _require_debugger_loaded()
        wanted = flag.upper()
        if wanted not in _FLAG_BITS:
            raise IDAError(f"Unsupported flag: {flag!r}", error_type="InvalidArgument")
        register = _read_register_int(_FLAGS_NAMES)
        if register is None:
            raise IDAError("No FLAGS/EFLAGS/RFLAGS register is available", error_type="DebuggerRegisterUnavailable")
        register_name, current = register
        bit = 1 << _FLAG_BITS[wanted]
        updated = (current | bit) if value else (current & ~bit)
        ok = bool(ida_dbg.set_reg_val(register_name, updated))
        return DebugFlagWriteResult(
            flag=wanted,
            value=value,
            register_name=register_name,
            register_value=format_address(updated),
            ok=ok,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_stacktrace(tid: int | None = None) -> DebugStacktraceResult:
        """Return the current call stack."""
        _require_debugger_loaded()
        actual_tid = tid if tid is not None else _current_thread()
        if actual_tid is None:
            actual_tid = ida_idd.NO_THREAD
        trace = ida_idd.call_stack_t()
        ok = bool(ida_dbg.collect_stack_trace(actual_tid, trace))
        if not ok:
            raise IDAError("Failed to collect stack trace", error_type="DebuggerStackTraceFailed")
        frames = []
        for idx, frame in enumerate(trace):
            disasm = ""
            if not is_bad_addr(frame.callea):
                with suppress_ida_errors():
                    disasm = _clean_disasm_at(frame.callea)
            frames.append(
                DebugStackFrame(
                    index=idx,
                    call_address=format_address(frame.callea),
                    function_address=format_address(frame.funcea),
                    frame_pointer=format_address(frame.fp),
                    function_known=bool(frame.funcok),
                    disasm=disasm,
                )
            )
        return DebugStacktraceResult(tid=actual_tid, frames=frames, count=len(frames))

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_memory_read(address: Address, size: int = 256) -> DebugMemoryReadResult:
        """Read debuggee memory."""
        return _read_memory_impl(address=address, size=size)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_memory_dump(address: Address, size: int) -> DebugMemoryReadResult:
        """Return a debuggee memory dump as hex bytes."""
        return _read_memory_impl(address=address, size=size)

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"debugger"})
    @session.require_open
    def debug_memory_write(address: Address, hex_bytes: HexBytes) -> DebugMemoryWriteResult:
        """Write bytes to debuggee memory."""
        _require_debugger_loaded()
        ea = _parse_runtime_address(address)
        data = _parse_hex_bytes(hex_bytes)
        result = ida_idd.dbg_write_memory(ea, data)
        if isinstance(result, bool):
            ok = result
            written = len(data) if ok else 0
        else:
            written = int(result)
            ok = written == len(data)
        return DebugMemoryWriteResult(address=format_address(ea), size=len(data), written=written, ok=ok)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_memory_is_valid(address: Address, size: int = 1) -> DebugMemoryValidityResult:
        """Check whether a debuggee memory region is readable."""
        _require_debugger_loaded()
        if size <= 0:
            raise IDAError("size must be positive", error_type="InvalidArgument")
        ea = _parse_runtime_address(address)
        data = ida_idd.dbg_read_memory(ea, size)
        return DebugMemoryValidityResult(
            address=format_address(ea),
            size=size,
            valid=data is not None and len(data) == size,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_memory_protection(address: Address) -> DebugMemoryProtectionResult:
        """Return the memory map entry containing a runtime address."""
        _require_debugger_loaded()
        ea = _parse_runtime_address(address)
        for region in _memory_regions():
            start = int(region.start, 16)
            end = int(region.end, 16)
            if start <= ea < end:
                return DebugMemoryProtectionResult(address=format_address(ea), region=region, found=True)
        return DebugMemoryProtectionResult(address=format_address(ea), region=None, found=False)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_memory_search(
        hex_bytes: HexBytes,
        address: Address | None = None,
        size: int = 0,
        max_results: int = 32,
    ) -> DebugMemorySearchResult:
        """Search debuggee memory for a byte pattern."""
        _require_debugger_loaded()
        pattern = _parse_hex_bytes(hex_bytes)
        if max_results <= 0:
            raise IDAError("max_results must be positive", error_type="InvalidArgument")
        bounded_results = min(max_results, 256)
        max_scan_bytes = 64 * 1024 * 1024
        matches: list[int] = []
        scanned = 0
        truncated = False
        if address is not None:
            if size <= 0:
                raise IDAError("size must be positive when address is provided", error_type="InvalidArgument")
            start = _parse_runtime_address(address)
            found, scanned = _search_memory_range(start, start + size, pattern, bounded_results)
            matches.extend(found)
        else:
            for region in _memory_regions():
                if len(matches) >= bounded_results or scanned >= max_scan_bytes:
                    truncated = True
                    break
                start = int(region.start, 16)
                end = int(region.end, 16)
                remaining = max_scan_bytes - scanned
                if end - start > remaining:
                    end = start + remaining
                    truncated = True
                found, region_scanned = _search_memory_range(start, end, pattern, bounded_results - len(matches))
                matches.extend(found)
                scanned += region_scanned
        if len(matches) >= bounded_results:
            truncated = True
        return DebugMemorySearchResult(
            pattern=pattern.hex(),
            count=len(matches),
            matches=[DebugMemorySearchMatch(address=format_address(ea)) for ea in matches],
            scanned_bytes=scanned,
            truncated=truncated,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_memory_map() -> DebugMemoryMapResult:
        """List debuggee memory regions."""
        _require_debugger_loaded()
        regions = _memory_regions()
        return DebugMemoryMapResult(count=len(regions), regions=regions)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_memory_refresh() -> DebugGenericResult:
        """Refresh IDA's cached debugger memory state."""
        _require_debugger_loaded()
        ida_dbg.refresh_debugger_memory()
        return DebugGenericResult(status="refreshed", ok=True)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_memory_invalidate(
        address: Address | None = None,
        size: int = 0,
        contents: bool = True,
        config: bool = False,
    ) -> DebugGenericResult:
        """Invalidate IDA's cached debugger memory contents/configuration."""
        _require_debugger_loaded()
        details: dict[str, Any] = {}
        if config:
            ida_dbg.invalidate_dbgmem_config()
            details["config"] = True
        if contents:
            ea = ida_idaapi.BADADDR if address is None else _parse_runtime_address(address)
            ida_dbg.invalidate_dbgmem_contents(ea, size)
            details["contents"] = {"address": None if is_bad_addr(ea) else format_address(ea), "size": size}
        return DebugGenericResult(status="invalidated", ok=True, details=details)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_manual_regions_get() -> DebugMemoryMapResult:
        """Return manually configured debugger memory regions."""
        return _manual_regions_result()

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_manual_regions_set(regions: list[dict[str, Any]]) -> DebugMemoryMapResult:
        """Replace manually configured debugger memory regions."""
        storage = ida_idd.meminfo_vec_t()
        for item in regions:
            storage.push_back(_region_from_mapping(item))
        ida_dbg.set_manual_regions(storage)
        return _manual_regions_result()

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_manual_regions_enable(enabled: bool = True) -> DebugGenericResult:
        """Enable or disable manual debugger memory regions."""
        ida_dbg.enable_manual_regions(enabled)
        return DebugGenericResult(status="manual_regions_updated", ok=True, details={"enabled": enabled})

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_virtual_module_add(name: str, base: Address, size: int, rebase_to: Address | None = None) -> DebugGenericResult:
        """Add a virtual debugger module."""
        module = ida_idd.modinfo_t()
        module.name = name
        module.base = _parse_runtime_address(base)
        module.size = int(size)
        module.rebase_to = ida_idaapi.BADADDR if rebase_to is None else _parse_runtime_address(rebase_to)
        ok = bool(ida_dbg.add_virt_module(module))
        return DebugGenericResult(
            status="virtual_module_added" if ok else "virtual_module_not_added",
            ok=ok,
            details={"name": name, "base": format_address(module.base), "size": int(size)},
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"debugger"})
    @session.require_open
    def debug_virtual_module_delete(base: Address) -> DebugGenericResult:
        """Delete a virtual debugger module by base address."""
        ea = _parse_runtime_address(base)
        ok = bool(ida_dbg.del_virt_module(ea))
        return DebugGenericResult(status="virtual_module_deleted" if ok else "virtual_module_not_deleted", ok=ok, details={"base": format_address(ea)})

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_memory_protect(address: Address, size: int, permissions: int) -> DebugGenericResult:
        """Report memory-protection support for this debugger backend."""
        return _unsupported(
            "debug_memory_protect",
            "IDA does not expose a generic cross-debugger memory-protect API; use debug_appcall or debug_send_command for backend-specific implementations.",
            address=str(address),
            size=size,
            permissions=permissions,
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_memory_allocate(size: int, permissions: int = 0, address: Address | None = None) -> DebugGenericResult:
        """Report memory-allocation support for this debugger backend."""
        return _unsupported(
            "debug_memory_allocate",
            "IDA does not expose a generic cross-debugger remote allocation API; use debug_appcall or debug_send_command for backend-specific implementations.",
            size=size,
            permissions=permissions,
            address=str(address) if address is not None else None,
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"debugger"})
    @session.require_open
    def debug_memory_free(address: Address, size: int = 0) -> DebugGenericResult:
        """Report memory-free support for this debugger backend."""
        return _unsupported(
            "debug_memory_free",
            "IDA does not expose a generic cross-debugger remote free API; use debug_appcall or debug_send_command for backend-specific implementations.",
            address=str(address),
            size=size,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_module_list() -> DebugModuleListResult:
        """List runtime modules known to the debugger."""
        return _module_list_result()

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_module_info(address: Address | None = None, module: str = "") -> DebugModule | None:
        """Return runtime module information by address or name substring."""
        return _module_info_impl(address=address, module=module)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_symbol_resolve(symbol: str = "", address: Address | None = None) -> DebugSymbol:
        """Resolve a debug/static symbol name or return the name at an address."""
        if address is not None:
            ea = _parse_runtime_address(address)
            name = ida_name.get_debug_names(ea, ea + 1).get(ea) or idc.get_name(ea)
            return DebugSymbol(address=format_address(ea), name=str(name or ""), source="address")
        if not symbol:
            raise IDAError("symbol or address is required", error_type="InvalidArgument")
        ea = ida_name.get_debug_name_ea(symbol)
        source = "debug_name"
        if is_bad_addr(ea):
            ea = _parse_runtime_address(symbol)
            source = "database"
        return DebugSymbol(address=format_address(ea), name=symbol, source=source)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_symbol_list(
        address: Address | None = None,
        size: int = 0,
        module: str = "",
        max_results: int = 256,
    ) -> DebugSymbolListResult:
        """List debug symbols in an address range or module."""
        return _symbol_list_impl(address=address, size=size, module=module, max_results=max_results)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_remote_get_proc_address(module: str, symbol: str) -> DebugSymbol:
        """Resolve a loaded module export/debug symbol when IDA has symbols for it."""
        candidates = [f"{module}!{symbol}", f"{module}_{symbol}", symbol]
        for candidate in candidates:
            with suppress_ida_errors():
                ea = ida_name.get_debug_name_ea(candidate)
                if not is_bad_addr(ea):
                    return DebugSymbol(address=format_address(ea), name=candidate, source="debug_name")
            with suppress_ida_errors():
                ea = idc.get_name_ea_simple(candidate)
                if not is_bad_addr(ea):
                    return DebugSymbol(address=format_address(ea), name=candidate, source="database")
        raise IDAError(
            f"Could not resolve {module}!{symbol}; the active IDA debugger does not expose a generic GetProcAddress API",
            error_type="SymbolNotFound",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_handle_list() -> DebugGenericResult:
        """Report process-handle enumeration support for this debugger backend."""
        return _unsupported(
            "debug_handle_list",
            "IDA does not expose generic process-handle enumeration through ida_dbg/ida_idd.",
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_tcp_connections() -> DebugGenericResult:
        """Report TCP connection enumeration support for this debugger backend."""
        return _unsupported(
            "debug_tcp_connections",
            "IDA does not expose generic process TCP connection enumeration through ida_dbg/ida_idd.",
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_label_set(address: Address, label: str) -> DebugAnnotationResult:
        """Set a debug/runtime label at an address."""
        ea = _parse_runtime_address(address)
        ok = bool(ida_name.set_debug_name(ea, label))
        if not ok:
            ok = bool(idc.set_name(ea, label))
        return DebugAnnotationResult(address=format_address(ea), value=label, ok=ok)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_label_get(address: Address) -> DebugAnnotationResult:
        """Get a debug/runtime label at an address."""
        ea = _parse_runtime_address(address)
        value = ida_name.get_debug_names(ea, ea + 1).get(ea) or idc.get_name(ea) or ""
        return DebugAnnotationResult(address=format_address(ea), value=str(value), ok=bool(value))

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_label_list(
        address: Address | None = None,
        size: int = 0,
        module: str = "",
        max_results: int = 256,
    ) -> DebugSymbolListResult:
        """List debug/runtime labels in an address range or module."""
        return _symbol_list_impl(address=address, size=size, module=module, max_results=max_results)

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_comment_set(address: Address, comment: str) -> DebugAnnotationResult:
        """Set a repeatable IDA comment at a runtime/static address."""
        return _comment_set_impl(address=address, comment=comment)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_comment_get(address: Address) -> DebugAnnotationResult:
        """Get an IDA comment at a runtime/static address."""
        ea = _parse_runtime_address(address)
        value = idc.get_cmt(ea, 1) or idc.get_cmt(ea, 0) or ""
        return DebugAnnotationResult(address=format_address(ea), value=value, ok=bool(value))

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_disassemble(address: Address, count: int = 8) -> DebugDisassemblyResult:
        """Disassemble instructions at a runtime/static address."""
        if count <= 0:
            raise IDAError("count must be positive", error_type="InvalidArgument")
        ea = _parse_runtime_address(address)
        lines = []
        cursor = ea
        for _ in range(min(count, 128)):
            text = _clean_disasm_at(cursor)
            if not text:
                break
            lines.append(DebugDisassemblyLine(address=format_address(cursor), text=text))
            next_ea = idc.next_head(cursor)
            if is_bad_addr(next_ea) or next_ea <= cursor:
                break
            cursor = next_ea
        return DebugDisassemblyResult(address=format_address(ea), lines=lines, count=len(lines))

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_assemble(address: Address, instruction: str) -> DebugPatchResult:
        """Assemble an instruction without writing it to the debuggee."""
        ea = _parse_runtime_address(address)
        assembled = _assemble_at(ea, instruction)
        old = ida_bytes.get_bytes(ea, len(assembled)) or b""
        return DebugPatchResult(
            address=format_address(ea),
            instruction=instruction,
            old_bytes=old.hex(),
            new_bytes=assembled.hex(),
            patched=False,
        )

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"debugger"})
    @session.require_open
    def debug_patch_instruction(address: Address, instruction: str) -> DebugPatchResult:
        """Assemble and patch one instruction in live debuggee memory."""
        _require_debugger_loaded()
        ea = _parse_runtime_address(address)
        assembled = _assemble_at(ea, instruction)
        old = ida_idd.dbg_read_memory(ea, len(assembled)) or b""
        written = ida_idd.dbg_write_memory(ea, assembled)
        if isinstance(written, bool):
            patched = written
        else:
            patched = int(written) == len(assembled)
        result = DebugPatchResult(
            address=format_address(ea),
            instruction=instruction,
            old_bytes=old.hex(),
            new_bytes=assembled.hex(),
            patched=patched,
        )
        if patched:
            _RUNTIME_PATCHES[ea] = result
        return result

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_branch_destination(address: Address) -> DebugBranchDestinationResult:
        """Resolve the first operand destination of a branch/call instruction."""
        ea = _parse_runtime_address(address)
        destination = idc.get_operand_value(ea, 0)
        ok = not is_bad_addr(destination) and destination != 0
        return DebugBranchDestinationResult(
            address=format_address(ea),
            destination=format_address(destination) if ok else "",
            ok=ok,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_patch_list() -> DebugPatchListResult:
        """List runtime patches recorded by this worker."""
        patches = [patch for _ea, patch in sorted(_RUNTIME_PATCHES.items())]
        return DebugPatchListResult(count=len(patches), patches=patches)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_patch_get(address: Address) -> DebugPatchResult | None:
        """Return recorded runtime patch metadata for one address."""
        ea = _parse_runtime_address(address)
        return _RUNTIME_PATCHES.get(ea)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_current_location() -> DebugCurrentLocationResult:
        """Return current runtime location and disassembly."""
        _require_debugger_loaded()
        status = _status()
        disasm = ""
        if status.current_ip:
            with suppress_ida_errors():
                disasm = _clean_disasm_at(int(status.current_ip, 16))
        return DebugCurrentLocationResult(
            process_state=status.process_state,
            current_thread=status.current_thread,
            current_ip=status.current_ip,
            current_sp=status.current_sp,
            disasm=disasm,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger", "decompiler"})
    @session.require_open
    def debug_decompile_current() -> DebugDecompileCurrentResult:
        """Decompile the function containing the current instruction pointer."""
        _require_debugger_loaded()
        status = _status()
        if not status.current_ip:
            raise IDAError("Current instruction pointer is unavailable", error_type="DebuggerRegisterUnavailable")
        ea = int(status.current_ip, 16)
        cfunc, func = decompile_at(ea)
        return DebugDecompileCurrentResult(
            address=format_address(ea),
            function=format_address(func.start_ea),
            pseudocode=str(cfunc),
        )

    @mcp.tool(annotations=ANNO_MUTATE, tags={"debugger"})
    @session.require_open
    def debug_annotate_current(comment: str) -> DebugAnnotationResult:
        """Add a repeatable IDA comment at the current instruction pointer."""
        _require_debugger_loaded()
        status = _status()
        if not status.current_ip:
            raise IDAError("Current instruction pointer is unavailable", error_type="DebuggerRegisterUnavailable")
        return _comment_set_impl(address=status.current_ip, comment=comment)

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"debugger"})
    @session.require_open
    def debug_sync_runtime_modules() -> DebugModuleListResult:
        """Return runtime modules so callers can decide whether to rebase/sync the IDB."""
        return _module_list_result()

    @mcp.tool(annotations=ANNO_DESTRUCTIVE, tags={"debugger"})
    @session.require_open
    def debug_rebase_database(
        new_base: Address | None = None,
        module: str = "",
        current_base: Address | None = None,
        flags: int | None = None,
    ) -> DebugGenericResult:
        """Rebase the IDA database to a runtime module base or explicit base."""
        if new_base is not None:
            target_base = _parse_runtime_address(new_base)
        elif module:
            item = _module_info_impl(module=module)
            if item is None:
                raise IDAError(f"Runtime module not found: {module!r}", error_type="ModuleNotFound")
            target_base = int(item.base, 16)
        else:
            modules = _module_list()
            if not modules:
                raise IDAError("No runtime modules are available", error_type="ModuleNotFound")
            target_base = int(modules[0].base, 16)
        old_base = _parse_runtime_address(current_base) if current_base is not None else int(ida_nalt.get_imagebase())
        delta = target_base - old_base
        move_flags = ida_segment.MSF_FIXONCE | ida_segment.MSF_SILENT if flags is None else int(flags)
        result = int(ida_segment.rebase_program(delta, move_flags))
        ok = result == ida_segment.MOVE_SEGM_OK
        if ok:
            with suppress_ida_errors():
                ida_nalt.set_imagebase(target_base)
        return DebugGenericResult(
            status="rebased" if ok else "rebase_failed",
            ok=ok,
            details={
                "old_base": format_address(old_base),
                "new_base": format_address(target_base),
                "delta": delta,
                "result": result,
            },
            error=None if ok else str(ida_segment.move_segm_strerror(result)),
        )


# ===========================================================================
# Manifest generation — auto-build COMMANDS from the registered tool signatures
# ===========================================================================
import inspect as _inspect  # noqa: E402

_shim = McpShim()
register(_shim)


def _infer_kind(ann: str) -> str:
    a = ann or ""
    if "HexBytes" in a:
        return "hex"
    if "bool" in a:
        return "bool"
    if "int" in a:
        return "int"
    if "list" in a or "dict" in a:
        return "json"
    return "str"


def _make_handler(fn):
    sig = _inspect.signature(fn)

    def handler(args: dict):
        _ensure_ida()
        kwargs = {}
        for pname in sig.parameters:
            if pname in args and args[pname] is not None:
                kwargs[pname] = args[pname]
        return dump(fn(**kwargs))

    return handler


COMMANDS = []
for _name, _fn in _shim.tools.items():
    _sig = _inspect.signature(_fn)
    _params = []
    for _pname, _p in _sig.parameters.items():
        _ann = _p.annotation if isinstance(_p.annotation, str) else ""
        _required = _p.default is _inspect.Parameter.empty
        _default = None if _required else _p.default
        _params.append(_Param(
            _pname, _infer_kind(_ann), required=_required,
            default=_default, positional=_required,
            help=f"({_ann})" if _ann else "",
        ))
    _doc = ((_fn.__doc__ or "").strip().splitlines() or [""])[0]
    _mutates = _shim.annotations.get(_name) != "read_only"
    COMMANDS.append(_Command(
        _name.replace("_", "-"), _make_handler(_fn), "debug", _doc,
        mutates=_mutates, params=_params,
    ))
