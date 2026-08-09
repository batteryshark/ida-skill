# Navigation — Read-Only Exploration

All commands take `--binary <path>` (resolves the worker port) or `--port <n>`.
Output defaults to compact text; add `--output json` for the structured result
or `--raw` for the full envelope. Addresses accept hex
(`0x401000`), bare hex (`4010a0`), decimal, or symbol names (`main`).

This guide covers the common read-only surface. For the **complete** list with
every parameter, see [commands.md](commands.md) or run
`python3 scripts/cli.py commands`.

## Overview / triage

```bash
python3 scripts/cli.py get-database-info --binary $B    # alias: info
```
Returns arch, bitness, entry point, min/max EA, processor, segment & function
counts, and decompiler availability.

## Functions

```bash
python3 scripts/cli.py list-functions --binary $B                       # alias: functions
python3 scripts/cli.py list-functions --filter_pattern "decrypt|parse" --binary $B
python3 scripts/cli.py list-functions --filter_type user --binary $B    # exclude libs/thunks
python3 scripts/cli.py get-function main --binary $B                     # bounds, flags, chunks
```
`--filter_type` is one of `thunk|library|noreturn|user`. Paginate with
`--offset`/`--limit`.

## Strings & pattern search

```bash
python3 scripts/cli.py get-strings --filter_pattern "http|key|pass" --binary $B  # alias: strings
python3 scripts/cli.py find-code-by-string "license" --binary $B   # strings → xrefs → functions
python3 scripts/cli.py search-bytes "48 8b c4" --binary $B         # byte pattern (?? wildcards)
python3 scripts/cli.py search-text "syscall" --binary $B           # disasm mnemonic/operand text
python3 scripts/cli.py find-immediate 0xdeadbeef --binary $B       # instructions using an immediate
```

## Cross-references & call graph

```bash
python3 scripts/cli.py get-xrefs-to main --binary $B      # who references this  (alias: xrefs-to)
python3 scripts/cli.py get-xrefs-from 0x401200 --binary $B # what this references (alias: xrefs-from)
python3 scripts/cli.py get-call-graph main --depth 2 --binary $B    # alias: call-graph
```

## Names, segments, imports/exports

```bash
python3 scripts/cli.py list-names --filter_pattern "g_" --binary $B
python3 scripts/cli.py get-segments --binary $B           # alias: segments
python3 scripts/cli.py get-imports --binary $B            # alias: imports
python3 scripts/cli.py get-exports --binary $B            # alias: exports
python3 scripts/cli.py get-entry-points --binary $B
```

## Data & structure discovery

```bash
python3 scripts/cli.py read-bytes 0x402000 64 --binary $B          # raw bytes → hex
python3 scripts/cli.py read-pointer-table 0x403000 --count 16 --binary $B  # vtables/dispatch
python3 scripts/cli.py list-switches --binary $B                   # jump tables
python3 scripts/cli.py get-basic-blocks main --binary $B           # CFG blocks
```

## Triage workflow

```bash
B=/path/to/suspicious.bin

python3 scripts/cli.py get-database-info --binary $B
python3 scripts/cli.py get-strings --filter_pattern "http|url|key|pass|encrypt" --binary $B
python3 scripts/cli.py find-code-by-string "encrypt" --binary $B    # jump straight to the functions
python3 scripts/cli.py decompile-function 0x401200 --binary $B      # (see decompilation.md)
python3 scripts/cli.py get-call-graph 0x401200 --depth 2 --binary $B
```

→ Full catalog: [commands.md](commands.md) · `python3 scripts/cli.py commands`
