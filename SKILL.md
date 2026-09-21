---
name: ida-skill
description: >
  Run headless IDA Pro reverse engineering through a persistent, multi-client
  idalib worker. Use for PE, ELF, Mach-O, or raw-binary disassembly,
  decompilation, search, cross-references, type and database editing, patching,
  assembly, and local or remote debugging through IDA dbgsrv. Require the
  operator to provision their own paid IDA Pro 9.x installation and license;
  this skill includes no Hex-Rays binaries, debug servers, or license material.
---

# IDA Pro Reverse Engineering

Run commands from this skill directory. A persistent idalib worker loads each
binary once and serializes concurrent requests on IDA's main thread. Use a
separate worker for each binary and the same `--binary` path throughout its
session; switching between the input and its `.i64`/`.idb` uses a different
worker key.

This repository is source-only. Provision a runtime from your own licensed IDA
installation before first use; keep copied runtimes and license state private.
Read [setup and troubleshooting](references/setup-troubleshooting.md) for host
requirements, provisioning options, external bundles, or worker failures.

## Query and discover

```bash
B=/path/to/binary
python3 scripts/cli.py get-database-info --binary "$B"
python3 scripts/cli.py commands --category functions
python3 scripts/cli.py decompile-function --help
python3 scripts/cli.py decompile-function main --binary "$B"
# Generic passthrough also accepts commands from the manifest:
python3 scripts/cli.py call get-xrefs-to address=main --binary "$B"
```

`cli.py` auto-starts a missing or dead worker unless
`IDA_SKILL_NO_AUTOSTART=1` is set. Commands accept `--binary <path>` or an
explicit `--port <n>`. Auto-start opens a normal writable database and runs
analysis; a query-only task does not imply an enforced read-only session.
Prefer `--binary`: it verifies the recorded worker session on every command.
Explicit `--port` uses the direct protocol without that verification.

Use `commands --category <name>` for targeted discovery and `<command> --help`
for exact parameters. The [generated command index](references/commands.md) is
available when a broader map helps. Read only the workflow guide relevant to
the task:

- [Navigation](references/navigation.md): functions, strings, xrefs, imports,
  search, call graphs, switches, and basic blocks.
- [Decompilation](references/decompilation.md): pseudocode, disassembly, ctree,
  microcode, operands, and stack frames.
- [Labeling](references/labeling.md): names, types, comments, patches, assembly,
  undo, and snapshots.
- [Dynamic analysis](references/dynamic.md): debugger backends, remote servers,
  breakpoints, stepping, registers, memory, and appcall.

Begin with database metadata and a distinctive name, string, or imported API;
follow its xrefs and decompile the relevant functions. Use disassembly when
pseudocode obscures instruction semantics or indirect flow. Base labels and
types on evidence, keep uncertainty in comments, and re-decompile after edits.

Compact text is the normal output: disassembly uses one instruction per line,
record lists use tables, and pseudocode retains real line breaks. For code that
must parse results, set `IDA_SKILL_ALLOW_JSON=1` before `--output json` or
`--raw`; otherwise those options downgrade to text with a notice.

## Worker lifecycle and persistence

Use explicit startup for non-default controls:

```bash
node scripts/bridge.mjs start --binary "$B" --multi-agent
node scripts/bridge.mjs status --binary "$B"
python3 scripts/cli.py save --binary "$B"
node scripts/bridge.mjs stop --binary "$B"
```

Wait for "Worker ready"; initial analysis can take minutes. Repeated `start`
attaches to a verified worker session, and a lock serializes starts and stops
for the same path. A live worker that is not yet responsive must be inspected
before another is started. The session is bound to its original requested path;
an explicit `open` can change the database that session currently holds.

Workers periodically save pending edits and exit after ten idle minutes
(`--autosave 300`, `--idle 600`; zero disables either). Autosave measures time
since the last save and may defer during active work up to twice its interval.
Use `save` for meaningful checkpoints. It saves and reopens the actual IDA
database without reanalysis; the worker remains available afterward.

Finish a session you own with `bridge.mjs stop`, which asks the verified worker
to save and exit. After saving succeeds, it rejects further work.
Keep a shared worker running while other clients still need it. `stop-all`
attempts every tracked worker and reports failures, including a worker still
starting without an RPC port. Failed saves or shutdowns return
nonzero and preserve the live worker and state for diagnosis; read
[troubleshooting](references/setup-troubleshooting.md) before retrying. Never
delete databases or sidecars as a generic repair step.

Database patches modify IDA's view, while export/rebuild commands can write
external files. Debugger process control, memory/register writes, and appcall
can affect the live target. Inspect command help to understand those effects;
the manifest's mutation marker is not a read-only enforcement boundary.

## Concurrent clients

Use `--multi-agent` when coordinating several agents on one database. It blocks
`undo`, `redo`, and `restore-snapshot`, because they roll back global state.
Startup flags apply only when creating a worker; attaching with `--multi-agent`
does not change an existing worker's mode. Avoid global rollback whenever clients
share a database. Assign disjoint functions or address ranges and fix mistakes
forward. Ordinary
single-client snapshots and undo remain available. Requests run FIFO with
per-request results; idle shutdown waits while work is in flight or queued.

## Optional MCP and command extensions

After starting a worker, expose the same command manifest over MCP:

```bash
uv run scripts/mcp_server.py --binary "$B"
# Or connect directly: uv run scripts/mcp_server.py --port 62927
```

Handlers in `scripts/handlers/` keep IDA imports inside functions, so CLI/MCP
schemas can load without a licensed runtime. Add a handler and `Command` entry,
then regenerate the index with `python3 scripts/gen_reference.py`. Lifecycle
schemas live in `scripts/ida_cmd.py` and are shared by CLI, MCP, and the index.

The source is MIT licensed; preserve [NOTICE](NOTICE) for the adapted re-mcp
code. IDA and Hex-Rays runtime material remains separate proprietary software.
