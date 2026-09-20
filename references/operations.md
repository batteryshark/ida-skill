# IDA Static Operations

Run from the skill directory. Use `python3 scripts/cli.py commands --category
<name>` to discover operations and `<command> --help` for current syntax.

## Triage And Navigation

Begin with database information, segments, imports/exports, entry points,
strings, and function names. Search for a distinctive string or imported API,
follow its xrefs, inspect callers and callees, then decompile the smallest
relevant functions. This produces better evidence with less output than broad
decompilation.

```bash
python3 scripts/cli.py info --binary "$B"
python3 scripts/cli.py strings --filter_pattern password --binary "$B"
python3 scripts/cli.py xrefs-to 0x401000 --binary "$B"
python3 scripts/cli.py decompile main --binary "$B"
```

Use disassembly when pseudocode hides instruction semantics, calling convention,
stack behavior, indirect control flow, or compiler artifacts. Use ctree,
microcode, operands, register tracking, switch, and CFG commands only when the
ordinary function view cannot answer the question.

`export-function-flow <address>` returns one read-only typed envelope containing
chunks, segments, decoded bytes and operands, processor feature flags, static
successors and xrefs, fixups, transfer classes, and a coverage receipt. `closed`
means complete only within the receipt's declared static IDA boundary; unresolved
indirect flow, decode failures, missing bytes, transfer/xref disagreement, and
coverage anomalies are explicit issues and set it false. Direct transfer closure
requires the decoded operand target and correctly typed call/jump xref to agree;
inferred indirect xrefs remain observations. The receipt makes no runtime-behavior
or semantic-fidelity claim and writes no output file or database state.

## Labeling And Types

Apply names, comments, prototypes, structs, enums, stack variables, and register
variables only when evidence supports them. Prefer incremental edits whose
effect can be checked in a fresh decompilation. Record uncertainty in comments
rather than encoding guesses as authoritative names or types.

Before coordinated mutations:

1. save or create a named snapshot;
2. make one coherent group of changes;
3. re-decompile affected functions and inspect xrefs;
4. undo or restore the snapshot if the evidence becomes worse;
5. use `worker save-and-close` after validation and retain its packed hash.

A checkpoint `save` does not end a writable session. It verifies source and
packed identities, saves, reopens, and atomically advances the database
generation. Autosave uses the same transaction. `close-no-save` discards only
mutations after the latest checkpoint and does not undo previous autosaves.
Read-only verification
must use a worker started with `--read-only`, followed by
`worker close-no-save`; compare the packed hash before and after when verifying
recovery integrity.

`worker clear-stale-read-only` removes only an authenticated dead read-only
worker's PID, state, closed lineage, and optional port bookkeeping; it never
changes source or database files. State must remain generation zero/open-clean,
lineage generation zero/closed, identity and packed hashes must match, and PID
and any port artifact must be canonical positive decimal. It refuses ambiguous
ownership or lifecycle state, live PIDs, reachable ports, sidecars, locks, or
changes by lifecycle-lock-cooperating operations during the locked check. An
arbitrary same-UID replacement after the final recheck is outside this guarantee.
The port artifact may be absent only when
its absence stays stable and authenticated state retains a valid unreachable
port, as normal worker close removes that artifact. Bookkeeping deletion keeps
state until last; an interrupted deletion reports removed and remaining paths,
but partial tuples fail closed and require Human disposition rather than inferred
recovery. If a successful response is lost, a retry reports
`already_absent_unverifiable`; this is not an idempotent-success receipt and no
durable cleanup receipt or automatic partial recovery is created.

Snapshot restore is disabled because its independent close/reopen path bypassed
managed database lineage. Create snapshots as restore points, but do not restore
one through the worker until restoration is integrated with checkpointing.

## Patches And Files

Database patch commands alter IDA's view of bytes or instructions. The original
input file remains unchanged until an explicit export/rebuild operation writes a
new file. Never overwrite the source binary by default; choose a distinct output
path, inspect the command's overwrite behavior, and verify the resulting file.

Commands that export maps, listings, patches, databases, or rebuilt binaries
write external files and therefore have side effects even when the IDA database
is unchanged.

## Output

Use compact text for interactive analysis. If a program must consume structured
results, set `IDA_SKILL_ALLOW_JSON=1` and select `--output json`; `--raw` also
includes the worker transport envelope. Do not request JSON merely for visual
inspection.
