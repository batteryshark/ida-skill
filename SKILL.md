---
name: ida-skill
description: >
  Use for static or dynamic reverse engineering of PE, ELF, Mach-O, and raw
  binaries with headless IDA Pro: disassembly, decompilation, xrefs, types,
  database labeling, patching, and debugger control.
---

# IDA Pro Reverse Engineering

Run from this skill directory; `scripts/cli.py` is the sole normal-use
interface. Queries auto-start a read-only worker when none exists. Writable work
must begin with explicit `worker start` and end with `save-and-close`.

```bash
python3 scripts/cli.py commands --category functions
python3 scripts/cli.py decompile main --binary /path/to/binary
python3 scripts/cli.py decompile --help
```

Set `IDA_BINARY=/path/to/binary` to omit repeated `--binary` options. Use
`commands` to discover operations and `<command> --help` for exact current
parameters; never load a static command catalog. Compact text is canonical.
JSON or raw transport output requires `IDA_SKILL_ALLOW_JSON=1` and should be
used only by code that must parse it.

## Choose The Workflow

- Use [operations.md](references/operations.md) for navigation, decompilation,
  labels, types, patches, snapshots, and exports.
- Use [dynamic.md](references/dynamic.md) for local or remote debugger setup,
  breakpoints, stepping, memory/register access, and debuggee safety.
- Use [setup-troubleshooting.md](references/setup-troubleshooting.md) only when
  provisioning fails, startup needs non-default controls, or the runtime is
  incomplete.

Begin read-only; narrow the target before broad decompilation. Base names,
types, and comments on multiple observations. Before coordinated database
mutations, snapshot; save meaningful checkpoints.

## Mandatory Database Lifecycle

Command listings mark side effects; inspect command help before use. Effects may
modify the IDA database, a live debuggee, or an external file. Ordinary rename,
type, comment, and patch commands modify the database. They do not rewrite the
original binary unless explicit export or rebuild is used.

Inspect status before analysis or writable startup. It reports PID and command
line, ownership, RPC and target identity, writable mode, packed database hash,
sidecars, and lifecycle lock. Never start another writable worker while a worker
or live sidecars claim the database.

```bash
python3 scripts/cli.py worker status --binary /path/to/binary
python3 scripts/cli.py worker start --binary /path/to/binary
# perform analysis and intentional mutations
python3 scripts/cli.py worker save-and-close --binary /path/to/binary
```

Writable work is complete only when `save-and-close` reports worker stopped,
repacking completed, no live sidecars, and the resulting `.i64`/`.idb` SHA-256.
`save` is only a checkpoint. A live worker remaining is a lifecycle failure;
never rely on idle shutdown for writable work.

Read-only verification also requires explicit closure:

```bash
python3 scripts/cli.py worker start --read-only --no-run-auto-analysis --binary /path/to/file.i64
python3 scripts/cli.py info --binary /path/to/file.i64
python3 scripts/cli.py worker close-no-save --binary /path/to/file.i64
```

Writable workers track the original analyzed input separately from the mutable
packed database. Explicit saves and autosaves share one checkpoint transaction:
verify source and packed hashes, atomically record intent, save and reopen, then
advance a monotonic generation only after successful reopen. An unexplained
packed hash, changed source, decreasing generation, or interrupted checkpoint
blocks lifecycle operations.

Autosave stays enabled because sidecars are not guaranteed dead-worker recovery
media. Use `save` to make a meaningful mutation batch durable immediately.
`close-no-save` discards only mutations after the latest successful checkpoint;
earlier autosaves and checkpoints persist.

## Recover An Unclosed Database

A packed `.i64` may predate its `.id0`, `.id1`, `.nam`, or `.til` while a worker
owns the unpacked database; this alone is neither corruption nor version
incompatibility. Inspect and recover that worker instead of opening the older
packed database:

```bash
python3 scripts/cli.py worker status --binary /path/to/binary
python3 scripts/cli.py worker recover-unclosed-database --binary /path/to/binary
```

Recovery authenticates PID, nonce, owner, RPC endpoint, target, input, database,
and sidecars. It normally saves and closes the worker; waits for repacking and
exit; hashes the packed database; reopens it read-only to inspect processor,
range, entry point, input identity, and representative analysis; closes without
saving; and requires a stable packed hash. Continue from the recovered database
only after success.

Recovery requires the original worker alive and responsive. If a crash leaves a
dead worker and sidecars, preserve the packed database, sidecars, lineage
journal, state, and log. Never infer a committed generation from timestamps or
promote copied sidecars over the canonical database.

Stop and ask the user only for possible concurrent human/agent use, multiple
claimants, identity disagreement, an unresponsive live worker, IDA
database/processor incompatibility, or failed normal `save-and-close`. Explicit
approval is also required to kill a process, delete sidecars, replace files, or
choose between competing analysis states. On failure preserve the packed
database, sidecars, worker, state record, and log. Never automatically delete
sidecars, kill a worker, or prefer an older packed database. Successful
save/reopen and a stable hash prove storage integrity, not annotations' semantic
correctness.
