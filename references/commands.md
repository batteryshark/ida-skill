# IDA Worker — Command Index

Auto-generated from the command manifest by `scripts/gen_reference.py`. **291 commands** across 47 categories. Do not edit by hand — regenerate.

This is a compact map (name + one-line summary). For a command's exact parameters, ask the CLI directly — it is the authoritative, always-current source:

```bash
python3 scripts/cli.py <command> --help          # exact params for one command
python3 scripts/cli.py commands --category debug  # filtered live listing
python3 scripts/cli.py <command> [args] --binary <path>
python3 scripts/cli.py call <command> key=value ... --binary <path>  # passthrough
```
`*` marks commands that may modify the database or have other side effects.

## Categories

- [Lifecycle (worker built-ins)](#lifecycle-worker-built-ins) — 4
- [Database & metadata](#database--metadata) — 9
- [Functions](#functions) — 7
- [Cross-references](#cross-references) — 3
- [Search & strings](#search--strings) — 6
- [Data & segments (read)](#data--segments-read) — 3
- [Imports / exports / entry points](#imports--exports--entry-points) — 5
- [Instructions & operands](#instructions--operands) — 3
- [Control flow](#control-flow) — 2
- [Stack frames](#stack-frames) — 2
- [Decompiler AST (ctree)](#decompiler-ast-ctree) — 3
- [Decompiler variables & comments](#decompiler-variables--comments) — 6
- [Comments](#comments) — 5
- [Names / labels](#names--labels) — 2
- [Demangling](#demangling) — 3
- [Types (apply)](#types-apply) — 2
- [Local types](#local-types) — 6
- [Structures](#structures) — 9
- [Enums](#enums) — 9
- [Function prototypes](#function-prototypes) — 3
- [Function flags](#function-flags) — 5
- [Function chunks](#function-chunks) — 4
- [Operand display](#operand-display) — 4
- [Segments (modify)](#segments-modify) — 6
- [Rebase](#rebase) — 2
- [Entry points (modify)](#entry-points-modify) — 4
- [Patching](#patching) — 4
- [Assembly](#assembly) — 2
- [Data definition](#data-definition) — 3
- [Load data](#load-data) — 3
- [Address metadata](#address-metadata) — 4
- [Analysis control](#analysis-control) — 7
- [Processor info](#processor-info) — 6
- [Switch tables](#switch-tables) — 2
- [Register tracking](#register-tracking) — 2
- [Register variables](#register-variables) — 6
- [Signatures & type libraries](#signatures--type-libraries) — 5
- [Signature generation](#signature-generation) — 1
- [Source language](#source-language) — 2
- [Batch export](#batch-export) — 4
- [Bookmarks](#bookmarks) — 3
- [Colors](#colors) — 2
- [Undo / redo](#undo--redo) — 2
- [Directory tree](#directory-tree) — 4
- [Snapshots](#snapshots) — 3
- [Utility](#utility) — 3
- [Debugger (dynamic analysis)](#debugger-dynamic-analysis) — 106


## Lifecycle (worker built-ins)

- `close`  — Close the current database.
- `list-commands`  — List all commands (worker-side).
- `open`  — Open a binary/database in the worker.
- `save`  — Flush the database to disk.


## Database & metadata

- `flush-buffers`* — Flush IDA's internal byte buffers to disk without a full save.
- `get-database-flags`  — Database flags (kill, compress, backup, temporary).
- `get-database-info`  — Database metadata: arch, bitness, address range, counts, decompiler. (alias: info)
- `get-database-paths`  — File paths for the current database (input file, IDB, ID0).
- `get-elf-debug-file-directory`  — Get the ELF debug file directory configuration path.
- `get-fileregion-ea`  — Map a byte offset in the input file to its loaded address.
- `get-fileregion-offset`  — Map a database address back to its input file byte offset.
- `reload-file`* — Re-read bytes from the original input file, overwriting patches.
- `set-database-flag`* — Set or clear a database flag (kill/compress/backup/temporary).


## Functions

- `decompile-function`  — Decompile ONE function to Hex-Rays pseudocode. (alias: decompile)
- `delete-function`* — Remove a function definition (code bytes remain).
- `disassemble-function`  — Disassemble the entire function containing an address.
- `get-function`  — Function metadata: bounds, size, flags, comments, chunks.
- `list-functions`  — List functions with regex/flag filtering and pagination. (alias: functions)
- `rename-function`* — Rename ONE function (propagates through xrefs).
- `set-function-bounds`* — Change a function's end address (exclusive).


## Cross-references

- `get-call-graph`  — Get the call graph for a function (callers and callees). (alias: call-graph)
- `get-xrefs-from`  — List all cross-references originating FROM an address. (alias: xrefs-from)
- `get-xrefs-to`  — List all cross-references pointing TO an address. (alias: xrefs-to)


## Search & strings

- `find-code-by-string`  — Find functions that xref a string matching a regex.
- `find-immediate`  — Search for instructions containing a specific immediate operand value.
- `get-strings`  — List string literals IDA identified (paginated, regex-filterable). (alias: strings)
- `rebuild-string-list`* — Refresh the cached string list after patches or new data.
- `search-bytes`  — Scan raw bytes across the binary for a hex/wildcard pattern.
- `search-text`  — Grep rendered disassembly text (mnemonics + operands).


## Data & segments (read)

- `get-segments`  — List all segments (memory layout, permissions, address ranges). (alias: segments)
- `read-bytes`  — Read raw bytes from the database at a given address.
- `read-pointer-table`  — Read an array of pointers (vtable, dispatch table) with optional dereference.


## Imports / exports / entry points

- `get-entry-points`  — List binary entry points (main/DllMain/exports).
- `get-exports`  — List all exported symbols. (alias: exports)
- `get-imports`  — List all imported functions grouped by module. (alias: imports)
- `set-import-name`* — Set the name of an import entry in IDA's import module table.
- `set-import-ordinal`* — Set the ordinal of an import entry in IDA's import module table.


## Instructions & operands

- `decode-instruction`  — Decode ONE instruction at an address (mnemonic, operands, size).
- `decode-instructions`  — Decode N sequential instructions from any address (not bounded by function limits).
- `get-operand-value`  — Get the resolved value of an instruction operand.


## Control flow

- `get-basic-blocks`  — Get basic blocks of a function (CFG nodes with successor/predecessor lists).
- `get-cfg-edges`  — Get CFG edges as (source, target) pairs (compact, for graph visualization).


## Stack frames

- `get-function-vars`  — Get typed locals/params via Hex-Rays decompilation.
- `get-stack-frame`  — Get the stack frame layout of a function (offsets, sizes, no Hex-Rays needed).


## Decompiler AST (ctree)

- `find-ctree-calls`  — Enumerate call sites inside ONE function's Hex-Rays AST.
- `find-ctree-patterns`  — Scan ONE function's Hex-Rays AST for common pattern classes.
- `get-ctree`  — Return the Hex-Rays AST (ctree) for ONE function as a structured tree.


## Decompiler variables & comments

- `get-decompiler-comments`  — List Hex-Rays pseudocode comments for ONE function.
- `get-microcode`  — Get Hex-Rays microcode for a function at a maturity level.
- `list-decompiler-variables`  — List Hex-Rays locals/params for ONE function.
- `rename-decompiler-variable`* — Rename ONE Hex-Rays local or parameter (pseudocode scope).
- `retype-decompiler-variable`* — Retype ONE Hex-Rays local or parameter.
- `set-decompiler-comment`* — Attach a comment to a pseudocode line (Hex-Rays view only).


## Comments

- `append-comment`* — Append to an existing disassembly comment without overwriting.
- `get-comment`  — Read both disassembly comments (regular + repeatable) at ONE address.
- `get-function-comment`  — Read the function-header comment (shown above the prototype).
- `set-comment`* — Set a disassembly-view comment at an instruction or data address. (alias: set_comment)
- `set-function-comment`* — Set the function-header comment (shown above the prototype).


## Names / labels

- `list-names`  — List every named location (functions + globals + data labels), regex-filterable.
- `rename-address`* — Rename ONE label (data, jump target, any non-function address). (alias: rename)


## Demangling

- `demangle-at-address`  — Demangle the symbol name at a given address.
- `demangle-name`  — Demangle a C++ symbol name to readable form.
- `list-demangled-names`  — List named addresses with demangled forms (C++ only), regex-filterable.


## Types (apply)

- `get-type-info`  — Read the name and current IDA type string at an address.
- `set-type`* — Apply an inline C type string at a data address. (alias: set_type)


## Local types

- `apply-type-at-address`* — Apply an already-defined local type at an address.
- `delete-local-type`* — Delete a named local type from the database.
- `delete-local-type-by-ordinal`* — Delete a Local Type by ordinal (for unnamed/anonymous types).
- `get-local-type`  — Get a local type's full declaration (members, sizes, kind) by name.
- `list-local-types`  — List Local Types (typedefs/enums/structs/funcs) with pagination.
- `parse-type-declaration`* — Parse a C declaration and register it as a Local Type.


## Structures

- `add-struct-member`* — Add a member to an existing structure.
- `create-structure`* — Create a new structure or union.
- `delete-struct-member`* — Delete a member from a structure.
- `delete-structure`* — Delete ONE struct/union by name.
- `get-structure`  — Return ONE struct/union with all members (offsets, sizes).
- `list-structures`  — List structs/unions (names, sizes, member counts) with pagination.
- `rename-struct-member`* — Rename a member of a structure.
- `retype-struct-member`* — Change the type of a structure member.
- `set-struct-member-comment`* — Set a comment on a structure member.


## Enums

- `add-enum-member`* — Add a member to an enum.
- `create-enum`* — Create a new enum type (optionally as a bitfield).
- `delete-enum`* — Delete an enum by name.
- `delete-enum-member`* — Delete a member from an enum by its value.
- `get-enum-members`  — List all members of an enum.
- `list-enums`  — List all enums (names, member counts, bitfield status).
- `rename-enum`* — Rename an enum.
- `rename-enum-member`* — Rename an enum member.
- `set-enum-member-comment`* — Set a comment on an enum member.


## Function prototypes

- `get-function-type`  — Get the full type signature (prototype) of a function.
- `set-function-calling-convention`* — Change the calling convention of a function.
- `set-function-type`* — Set a function's full C prototype (return + args + calling convention).


## Function flags

- `add-hidden-range`* — Create a hidden (collapsed) range in the disassembly listing.
- `delete-hidden-range`* — Delete a hidden range that contains the given address.
- `get-byte-flags`  — Get IDA internal flags for a byte (code/data/head/xref status).
- `get-hidden-ranges`  — List all hidden (collapsed) ranges in the database.
- `set-function-flags`* — Set or clear function flags (library, thunk, noreturn, hidden).


## Function chunks

- `append-function-tail`* — Append a tail (non-contiguous chunk) to a function.
- `list-function-chunks`  — List all chunks (contiguous regions) of a function.
- `remove-function-tail`* — Remove a tail (non-contiguous chunk) from a function.
- `set-tail-owner`* — Reassign a function tail chunk to a different owning function.


## Operand display

- `set-operand-enum`* — Display a numeric operand as an enum member name.
- `set-operand-format`* — Change an operand's numeric base (hex/dec/bin/oct/char).
- `set-operand-offset`* — Reinterpret a numeric operand as a flat pointer/offset (creates an xref).
- `set-operand-struct-offset`* — Reinterpret an operand as a struct field offset (creates the struct xref).


## Segments (modify)

- `create-segment`* — Create a new segment in the database.
- `delete-segment`* — Delete the segment containing the given address.
- `set-segment-bitness`* — Change the addressing mode of a segment (16/32/64-bit).
- `set-segment-class`* — Change the class of a segment (CODE/DATA/BSS/STACK/etc.).
- `set-segment-name`* — Rename a segment.
- `set-segment-permissions`* — Change segment permissions (e.g. RWX, R-X, RW-).


## Rebase

- `move-segment`* — Relocate ONE segment to a new start address and fix up references.
- `rebase-program`* — Shift EVERY address by a delta (destructive, global).


## Entry points (modify)

- `add-entry-point`* — Register a new entry point at an address (does not rename existing).
- `get-entry-forwarder`  — Get the forwarder name for an entry point.
- `rename-entry-point`* — Rename an entry point's symbol by ordinal.
- `set-entry-forwarder`* — Set a forwarder name for an entry point.


## Patching

- `create-function`* — Define a new function at an address (IDA auto-detects bounds).
- `make-code`* — Force bytes to be disassembled as code (single instruction, no function).
- `patch-bytes`* — Overwrite raw bytes in the IDB with a hex string (atomic, destructive).
- `undefine`* — Revert code/data definitions back to raw undefined bytes (byte values unchanged).


## Assembly

- `assemble-instruction`  — Assemble an instruction at an address without patching (dry-run).
- `patch-asm`* — Assemble and patch an instruction into the database in one step.


## Data definition

- `make-array`* — Mark a contiguous run of bytes as an array of an already-defined typed element.
- `make-data`* — Mark bytes as a primitive data type (byte/word/dword/qword/float/double).
- `make-string`* — Mark bytes as a C/Pascal/Unicode string (auto-sized if length omitted).


## Load data

- `load-additional-binary`* — Load a binary file into a new auto-created segment (firmware, overlays, etc.).
- `load-bytes-from-file`* — Overwrite bytes in an existing segment from a file (segment must already exist).
- `load-bytes-from-memory`* — Write hex-encoded bytes directly into an existing segment.


## Address metadata

- `get-address-info`  — Get IDA's analysis flags and metadata for an address.
- `get-source-line-number`  — Get the DWARF/debug source line number at an address (null if unmapped).
- `set-library-item`* — Mark or unmark an address as a library item.
- `set-source-line-number`* — Set the source file line number for an address.


## Analysis control

- `get-analysis-problems`  — List analysis problems/conflicts found by IDA.
- `get-exception-handlers`  — Get exception handling (try/catch) blocks for a function.
- `get-fixups`  — List relocation/fixup records in the binary.
- `get-segment-registers`  — Get segment register values at an address.
- `reanalyze-range`* — Reanalyze an address range synchronously (blocks until done).
- `set-segment-register`* — Set a segment register value starting at an address (e.g. fs/gs for TLS).
- `wait-for-analysis`* — Wait for IDA's auto-analysis to complete; returns a DB summary.


## Processor info

- `get-instruction-list`  — Get all instruction mnemonics recognized by the current processor.
- `get-processor-info`  — Get processor/architecture info (name, registers, bitness).
- `get-register-name`  — Get the name of a register by its number and width.
- `is-alignment-instruction`  — Check whether an instruction is alignment padding (NOP sled, etc.).
- `is-call-instruction`  — Check whether the instruction at an address is a call.
- `is-return-instruction`  — Check whether the instruction at an address is a return.


## Switch tables

- `get-switch-info`  — Get switch/jump table structure at an indirect jump (targets, cases, default).
- `list-switches`  — Find all switch/jump tables in the database (may be slow on large binaries).


## Register tracking

- `find-register-value`  — Trace a register value at an address using IDA's backwards register tracker.
- `find-stack-pointer-value`  — Get the stack pointer offset (relative to function entry) at an address.


## Register variables

- `add-regvar`* — Define a register variable (map a register to a name over a range).
- `delete-regvar`* — Delete a register variable definition over a range.
- `get-regvar`  — Get the register variable definition at an address for a register.
- `list-regvars`  — List all register variable definitions in a function.
- `rename-regvar`* — Rename a regvar alias (register-scoped, per-range).
- `set-regvar-comment`* — Set the comment on a register variable definition.


## Signatures & type libraries

- `apply-flirt-signature`* — Apply a FLIRT signature library to auto-identify and name library functions.
- `list-flirt-signatures`  — List FLIRT signature files currently applied to the database.
- `list-type-libraries`  — List all loaded type information libraries (TILs).
- `load-ids-module`* — Load and apply an IDS (ID Signature) file of library type information.
- `load-type-library`* — Load a TIL (type library) for OS/SDK types (e.g. gnulnx_x64, mssdk_win10).


## Signature generation

- `generate-signatures`* — Generate FLIRT .sig and .pat files from the current database.


## Source language

- `get-source-parser`  — Get the active source language parser name (e.g. 'clang').
- `parse-source-declarations`* — Parse C/C++/ObjC/Swift/Go source declarations and import types.


## Batch export

- `export-all-disassembly`  — Disassemble MANY functions in one call (paginated, regex-filterable).
- `export-all-pseudocode`  — Decompile MANY functions in one call (paginated, regex-filterable, expensive).
- `generate-exe-file`* — Generate (rebuild) an executable file from the database.
- `generate-output-file`* — Write an IDA-native .asm/.lst/.map/.dif/.idc file to disk.


## Bookmarks

- `delete-bookmark`* — Delete a bookmark by slot number.
- `get-bookmarks`  — List all bookmarks (marked positions) in the database.
- `set-bookmark`* — Set a bookmark (marked position) at an address.


## Colors

- `get-color`  — Get the background color of an address, function, or segment.
- `set-color`* — Set the background color of an address, function, or segment.


## Undo / redo

- `redo`* — Redo the last undone database modification.
- `undo`* — Undo the last database modification.


## Directory tree

- `create-folder`* — Create a new folder in IDA's directory tree.
- `delete-folder`* — Delete an empty folder from IDA's directory tree.
- `list-folders`  — List folders and items in IDA's directory tree.
- `rename-folder`* — Rename or move a folder in IDA's directory tree.


## Snapshots

- `list-snapshots`  — List all database snapshots (flattened tree with depth).
- `restore-snapshot`* — Revert the database to a prior snapshot (destroys unsaved changes).
- `take-snapshot`* — Create a persistent restore point (survives sessions; stronger than undo).


## Utility

- `convert-number`  — Convert a number between hex, decimal, octal, and binary.
- `evaluate-expression`* — Evaluate an IDC expression and return the result.
- `run-script`* — DANGEROUS: run arbitrary IDAPython (full FS/network access).


## Debugger (dynamic analysis)

- `debug-annotate-current`* — Add a repeatable IDA comment at the current instruction pointer.
- `debug-appcall`* — Call a debuggee function through IDA Appcall.
- `debug-appcall-cleanup`* — Cleanup IDA Appcall state for a thread.
- `debug-assemble`  — Assemble an instruction without writing it to the debuggee.
- `debug-attach`* — Attach to a process using the IDA debugger.
- `debug-branch-destination`  — Resolve the first operand destination of a branch/call instruction.
- `debug-breakpoint-add`* — Add a software, hardware, read, write, or execute breakpoint.
- `debug-breakpoint-condition-set`* — Set or clear a breakpoint condition.
- `debug-breakpoint-delete`* — Delete a breakpoint.
- `debug-breakpoint-get`  — Return one breakpoint by address.
- `debug-breakpoint-group-delete`* — Delete a breakpoint group/folder.
- `debug-breakpoint-group-enable`* — Enable or disable all breakpoints in a group.
- `debug-breakpoint-group-list`  — List breakpoint groups/folders.
- `debug-breakpoint-group-set`* — Move a breakpoint into a breakpoint group/folder.
- `debug-breakpoint-list`  — List IDA breakpoints.
- `debug-breakpoint-toggle`* — Enable or disable an existing breakpoint.
- `debug-breakpoint-update`* — Update breakpoint size/type/pass count/condition/enabled state.
- `debug-comment-get`  — Get an IDA comment at a runtime/static address.
- `debug-comment-set`* — Set a repeatable IDA comment at a runtime/static address.
- `debug-continue`* — Resume execution in the active debugger session.
- `debug-current-location`  — Return current runtime location and disassembly.
- `debug-decompile-current`  — Decompile the function containing the current instruction pointer.
- `debug-detach`* — Detach from the active debuggee.
- `debug-disassemble`  — Disassemble instructions at a runtime/static address.
- `debug-event-wait`* — Wait for the next debugger event.
- `debug-exception-continue`* — Continue after the current exception as handled or unhandled.
- `debug-exception-list`  — List debugger exception handling policies.
- `debug-exception-set`* — Add or update one debugger exception policy.
- `debug-exit`* — Terminate the active debuggee.
- `debug-flags-read`  — Read common CPU flags from RFLAGS/EFLAGS.
- `debug-flags-write`* — Set or clear one common CPU flag in RFLAGS/EFLAGS.
- `debug-gp-registers-read`  — Read common general-purpose registers.
- `debug-handle-list`  — Report process-handle enumeration support for this debugger backend.
- `debug-kill`* — Alias for debug_exit.
- `debug-label-get`  — Get a debug/runtime label at an address.
- `debug-label-list`  — List debug/runtime labels in an address range or module.
- `debug-label-set`* — Set a debug/runtime label at an address.
- `debug-last-exception`  — Return the current debugger event, marked if it appears exception-related.
- `debug-launch`* — Alias for debug_start.
- `debug-manual-regions-enable`* — Enable or disable manual debugger memory regions.
- `debug-manual-regions-get`  — Return manually configured debugger memory regions.
- `debug-manual-regions-set`* — Replace manually configured debugger memory regions.
- `debug-memory-allocate`* — Report memory-allocation support for this debugger backend.
- `debug-memory-dump`  — Return a debuggee memory dump as hex bytes.
- `debug-memory-free`* — Report memory-free support for this debugger backend.
- `debug-memory-invalidate`* — Invalidate IDA's cached debugger memory contents/configuration.
- `debug-memory-is-valid`  — Check whether a debuggee memory region is readable.
- `debug-memory-map`  — List debuggee memory regions.
- `debug-memory-protect`* — Report memory-protection support for this debugger backend.
- `debug-memory-protection`  — Return the memory map entry containing a runtime address.
- `debug-memory-read`  — Read debuggee memory.
- `debug-memory-refresh`* — Refresh IDA's cached debugger memory state.
- `debug-memory-search`  — Search debuggee memory for a byte pattern.
- `debug-memory-write`* — Write bytes to debuggee memory.
- `debug-module-info`  — Return runtime module information by address or name substring.
- `debug-module-list`  — List runtime modules known to the debugger.
- `debug-patch-get`  — Return recorded runtime patch metadata for one address.
- `debug-patch-instruction`* — Assemble and patch one instruction in live debuggee memory.
- `debug-patch-list`  — List runtime patches recorded by this worker.
- `debug-pause`* — Suspend the active debuggee.
- `debug-process-list`* — List attachable processes known to the loaded debugger.
- `debug-process-options-get`  — Return IDA debugger launch/process options.
- `debug-process-options-set`* — Set IDA debugger launch/process options without starting the process.
- `debug-rebase-database`* — Rebase the IDA database to a runtime module base or explicit base.
- `debug-register-write`* — Write one register value by name.
- `debug-registers-read`  — Read all registers or a selected list of register names.
- `debug-remote-get-proc-address`  — Resolve a loaded module export/debug symbol when IDA has symbols for it.
- `debug-restart`* — Terminate the current debuggee if present, then launch again.
- `debug-run-to`* — Run until a runtime/static address is reached.
- `debug-send-command`* — Send a raw command to debugger backends that support command channels.
- `debug-source-location`  — Return current source file/line if source debugging is available.
- `debug-source-path-map-add`* — Add a source path mapping for source-level debugging.
- `debug-source-step-into`* — Source-level step into.
- `debug-source-step-out`* — Source-level step out.
- `debug-source-step-over`* — Source-level step over.
- `debug-stacktrace`  — Return the current call stack.
- `debug-start`* — Launch a target under the IDA debugger.
- `debug-status`  — Return live IDA debugger state for this database.
- `debug-step-into`* — Step one instruction, entering calls.
- `debug-step-out`* — Run until the current function returns.
- `debug-step-over`* — Step one instruction, stepping over calls.
- `debug-symbol-list`  — List debug symbols in an address range or module.
- `debug-symbol-resolve`  — Resolve a debug/static symbol name or return the name at an address.
- `debug-sync-runtime-modules`  — Return runtime modules so callers can decide whether to rebase/sync the IDB.
- `debug-tcp-connections`  — Report TCP connection enumeration support for this debugger backend.
- `debug-thread-list`  — List debuggee threads.
- `debug-thread-name-get`  — Return a thread name by ID or the current thread.
- `debug-thread-resume`* — Resume one debuggee thread.
- `debug-thread-select`* — Select the current debugger thread.
- `debug-thread-sreg-base`  — Resolve a segment-register base for a thread.
- `debug-thread-suspend`* — Suspend one debuggee thread.
- `debug-thread-teb`  — Return the likely Windows TEB base using FS on 32-bit or GS on 64-bit.
- `debug-trace-clear`* — Clear IDA's trace buffer.
- `debug-trace-config-get`  — Return IDA trace configuration and event count.
- `debug-trace-config-set`* — Update IDA trace options, circular buffer size, base address, or platform.
- `debug-trace-disable`* — Disable one or more IDA trace types: step, instruction, function, basic_block, or all.
- `debug-trace-enable`* — Enable one or more IDA trace types: step, instruction, function, basic_block, or all.
- `debug-trace-event-get`  — Return one trace event.
- `debug-trace-events`  — List trace events from IDA's trace buffer.
- `debug-trace-load`* — Load an IDA trace file.
- `debug-trace-memory-get`  — Return memory snapshots associated with a trace event.
- `debug-trace-registers-get`  — Return register values recorded for an instruction trace event.
- `debug-trace-save`* — Save IDA's trace buffer to a trace file.
- `debug-virtual-module-add`* — Add a virtual debugger module.
- `debug-virtual-module-delete`* — Delete a virtual debugger module by base address.
- `debug-wait-until`* — Wait until a debugger event/address/module condition is observed.
