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

Use a persistent idalib worker to load each database once and serve commands
over localhost TCP. Share one worker among concurrent clients; use a separate
worker for each binary.

## Provision a private runtime

Keep this repository source-only. Do not commit or redistribute `bin/`, an IDA
installation, a license file, EULA state, or dbgsrv binaries. Confirm that your
Hex-Rays agreement permits every machine and location where you use a copied
runtime.

Install Node.js 22+ (Node 24 LTS recommended) and the CPython major/minor ABI
required by your IDA build (for example, CPython 3.13 for IDA 9.4). Then copy
from your own installation:

```bash
# macOS
node scripts/setup.mjs --ida-dir "/Applications/IDA Professional 9.4.app" --include-license

# Windows
node scripts/setup.mjs --ida-dir "C:\Path\To\IDA Professional 9.4" --include-license

# Linux
node scripts/setup.mjs --ida-dir "/opt/ida" --include-license
```

Use `--include-license` only for a private bundle. It copies `idapro.hexlic`
and existing EULA state from the installation, the normal IDA user directory,
or `--license-dir <path>`. Omit it to use the machine's existing IDA user
configuration instead. On Windows, a worker with a bundled license writes the
required per-user `EULA 90` value under HKCU; it does not require admin rights.

Choose the copy size:

```bash
# Default: trim to idalib, common processors/loaders/decompilers, and dbgsrv
node scripts/setup.mjs --ida-dir "/path/to/IDA" --include-license

# Full: copy the untrimmed installation and the private license state
node scripts/setup.mjs --ida-dir "/path/to/IDA" --include-license --full
```

The generated payload is self-contained for IDA files and license state. Node
and an ABI-compatible Python interpreter remain host prerequisites.

Provision each target from the corresponding IDA installation to assemble a
three-platform private bundle:

```bash
node scripts/setup.mjs --ida-dir "/path/to/mac-IDA" --target-platform mac --include-license
node scripts/setup.mjs --ida-dir "/path/to/linux-IDA" --target-platform linux --include-license
node scripts/setup.mjs --ida-dir "/path/to/windows-IDA" --target-platform windows --include-license
```

Store payloads outside the checkout when desired:

```bash
node scripts/setup.mjs --ida-dir "/path/to/IDA" --bundle-dir "/private/ida-bundle" --include-license
export IDA_SKILL_BIN_DIR="/private/ida-bundle"
```

In PowerShell, set `$env:IDA_SKILL_BIN_DIR = "C:\private\ida-bundle"` before
running the bridge. Keep the same bundle root for setup, bridge, CLI, and MCP.

Setup writes one runtime per target and a shared debug-server directory:

```text
bin/
├── ida-runtime-mac/
├── ida-runtime-windows/
├── ida-runtime-linux/
├── dbgsrv/
└── runtime/                 # ephemeral worker state
```

Re-run setup safely to validate an existing runtime or refresh private license
state. Add `--force` when changing between trimmed/full modes or replacing the
runtime. On macOS, let setup use `ditto` and clear quarantine so copied code
signatures remain usable.

## Start the worker

```bash
# Import + analyze a binary, then start the worker
node scripts/bridge.mjs start --binary /path/to/binary

# The worker runs as a detached background process.
# It auto-shuts down after 10 min idle (configurable: --idle 600, --idle 0 to disable)
# Unsaved changes are flushed to disk 5 min after they accumulate
# (configurable: --autosave 300, --autosave 0 to disable)

# For orchestrated fan-out (several agents on one worker):
node scripts/bridge.mjs start --binary /path/to/binary --multi-agent
```

Wait for the "Worker ready" message. Analysis of large binaries can take
minutes. Changes from labeling commands are persisted by the periodic
autosave and on graceful shutdown.

Starting is idempotent and race-free: if a worker is already running, `start`
attaches to it, and simultaneous `start` invocations are serialized through a
lock file so only one worker ever opens a given database. `cli.py` also
auto-starts a missing/dead worker on first use (opt out with
`IDA_SKILL_NO_AUTOSTART=1`), so explicit `start` is only needed for
non-default flags.

## Query

All commands take `--binary <path>` (resolves the worker port) or `--port <n>`.
Output is compact, agent-readable text — the canonical format. Do not request
JSON: `--output json` and `--raw` are disabled (they downgrade to text with a
notice) because JSON is far more verbose for the same information. The
`IDA_SKILL_ALLOW_JSON=1` escape hatch exists solely for scripts that must
parse the output programmatically.

**~300 commands** are available — full parity with the `re-mcp-ida` MCP server
plus its complete headless debugger. They are auto-discovered from
`scripts/handlers/` and every one is a first-class CLI subcommand with its own
`--help`. Three ways to discover and invoke:

```bash
# 1. Browse the catalog (optionally by category)
python3 scripts/cli.py commands
python3 scripts/cli.py commands --category debug

# 2. Per-command help (positional args + flags, generated from the manifest)
python3 scripts/cli.py list-functions --help

# 3. Generic passthrough for any command (no subcommand needed)
python3 scripts/cli.py call get-xrefs-to address=main --binary $B
```

A compact index of all commands is in
[references/commands.md](references/commands.md) (regenerate with
`python3 scripts/gen_reference.py`); for a command's exact parameters use
`cli.py <command> --help`. Curated workflow guides, organized by task:

- **Navigation** — read-only exploration: functions, strings, xrefs, names,
  segments, imports/exports, search, call graphs, switches, basic blocks.
  [references/navigation.md](references/navigation.md).
- **Decompilation** — understanding code: decompile/disassemble, ctree/AST,
  microcode, operands, stack frames.
  [references/decompilation.md](references/decompilation.md).
- **Labeling** — modifying the database: rename, types, structs/enums,
  prototypes, comments, patching/assembly, undo, snapshots.
  [references/labeling.md](references/labeling.md).
- **Dynamic** — the headless debugger (106 `debug-*` commands): breakpoints,
  stepping, registers, memory, threads, modules, tracing, appcall.
  [references/dynamic.md](references/dynamic.md).

Quick reference for the most common commands (short aliases in parentheses):

```bash
B=/path/to/binary

python3 scripts/cli.py get-database-info --binary $B          # (info)
python3 scripts/cli.py list-functions --filter_pattern decrypt --binary $B  # (functions)
python3 scripts/cli.py decompile-function main --binary $B    # (decompile)
python3 scripts/cli.py disassemble-function main --binary $B
python3 scripts/cli.py get-xrefs-to main --binary $B          # (xrefs-to)
python3 scripts/cli.py get-strings --filter_pattern password --binary $B    # (strings)
python3 scripts/cli.py get-segments --binary $B               # (segments)
python3 scripts/cli.py get-call-graph main --depth 2 --binary $B  # (call-graph)
```

Disassembly prints one instruction per line as `<address>  <instruction>`.
Other record lists use compact tables, and multiline pseudocode is emitted as
real lines rather than JSON-escaped strings.

### Architecture: modular handlers + one manifest

Each command is a plain handler in `scripts/handlers/<domain>.py` that takes an
`args` dict and returns JSON. Handlers keep their `ida_*` imports *inside*
functions, so the command manifest (`ida_cmd.Command`/`Param`) imports without a
running IDA — that single manifest drives the CLI, the MCP server
(`scripts/mcp.py`), and the generated reference. To add a command, add a handler
+ a `Command(...)` entry; it appears everywhere automatically.

## Stop the worker

```bash
node scripts/bridge.mjs stop --binary /path/to/binary
```

Graceful shutdown persists any labeling changes to the `.i64` database. Use
`status` to check liveness. To kill all workers at once: `node scripts/bridge.mjs stop-all`.
Shutdown waits for IDA to acknowledge the database save before terminating the
worker; large databases may take several minutes.

## How it works

```
bridge.mjs start --binary /path/bin
  → spawns: python3 worker.py --binary /path/bin
  → worker: import idapro → open_database(auto_analysis) → serve TCP
  → writes: bin/runtime/worker-<hash>.port

cli.py functions --binary /path/bin
  → resolves worker port from hash
  → TCP: {"cmd": "functions", "args": {}}
  → worker dispatches to main thread (idalib is single-threaded)
  → returns JSON

bridge.mjs stop --binary /path/bin
  → TCP: {"cmd": "close", "args": {"save": true}}
  → SIGTERM → worker saves database, exits
```

**Why this is fast:** idalib loads as native code via ctypes (no JVM). The
worker process keeps the database open in memory. Queries execute in-process
at native speed — sub-millisecond for most operations.

**Single-database constraint:** idalib holds one database per process. Each
binary gets its own worker. Multiple agents can share one worker (commands
serialized, each <1ms).

## Multiple agents, one worker

Concurrent clients on the same worker are fully supported: requests are
queued FIFO onto IDA's main thread, and each request carries its own result
slot, so responses can never be cross-delivered. The idle shutdown never
fires while a request is in flight or queued.

For orchestrated fan-out, start the worker with `--multi-agent`. This blocks
`undo`, `redo`, and `restore-snapshot` (they roll back *global* database
state — one agent's undo would silently destroy another agent's work); agents
should fix mistakes forward by re-applying the correct label/type. Write
conflicts are best avoided at dispatch time by giving agents disjoint address
ranges.

## Multiple binaries

Each binary gets its own worker process (keyed by path hash). Start as many
as needed concurrently; query each independently by passing the right
`--binary`. Orphaned workers auto-shutdown after the idle timeout.

## Troubleshooting

- **"Runtime not provisioned"** — run `node scripts/setup.mjs --ida-dir /path/to/ida`; add `--include-license` only for a private self-contained bundle.
- **"No worker found for..."** — `cli.py` normally auto-starts one (the worker
  may have auto-shutdown after the idle timeout, 10 min default). If auto-start
  is disabled or failed, run `bridge.mjs start --binary <path>` and check the log.
- **"Connection refused"** — the worker died. Check the log at
  `bin/runtime/worker-<hash>.log`. Restart with `bridge.mjs start`.
- **"Out of private address space for netnodes"** — stale database files.
  Delete the `.i64`/`.id0`/`.id1`/`.id2`/`.nam`/`.til` files next to the
  binary and restart.
- **Analysis timeout** — large binaries take time. Increase the startup
  timeout: `bridge.mjs start --binary <path> --timeout 600`.
- **macOS segfaults** — ensure `setup.mjs` used `ditto` (not `cp`). Re-run
  setup with `--force` (and repeat `--include-license` if wanted). Setup recursively clears the
  quarantine attribute from the locally provisioned runtime; for an existing
  archive, rerun setup once or use
  `xattr -dr com.apple.quarantine bin/ida-runtime-mac`.
- **Python exits during `import idapro`** — IDA 9.4 targets CPython 3.13. The
  bridge prefers `python3.13`; set `IDA_PYTHON=/path/to/python` to override it
  for another IDA release.

## Source license and trademarks

Use the skill source under the MIT License. Preserve the upstream notice for
handler/helper code adapted from [re-mcp](https://github.com/jtsylve/re-mcp),
used under its MIT option. Treat IDA Pro, idalib, decompiler modules, licenses,
and debug servers as separate proprietary Hex-Rays material. This project is
independent and is not affiliated with or endorsed by Hex-Rays.
