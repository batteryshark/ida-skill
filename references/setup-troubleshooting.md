# IDA Setup And Worker Troubleshooting

Normal commands auto-start a worker. If the bundled runtime is absent or
incomplete, the bridge prints the provisioning command and the detected problem.
Provision from a licensed IDA Pro 9.x installation:

```bash
node scripts/setup.mjs
```

Use `IDADIR` to identify a nonstandard installation and `IDA_PYTHON` when the
runtime needs a specific compatible Python. Run `node scripts/setup.mjs --help`
before using repair, force, full-runtime, or target-platform options. The setup
process copies required licensed runtime files; do not redistribute them.

For startup controls that auto-start cannot express, use the CLI wrapper:

```bash
python3 scripts/cli.py worker start --binary "$B" --timeout 900
python3 scripts/cli.py worker start --binary "$B" --idle 0 --autosave 300
python3 scripts/cli.py worker status --binary "$B"
```

Relevant options include startup timeout, idle shutdown, autosave interval,
multi-agent mutation protection, and whether initial auto-analysis runs. Use
`worker start --help` for the current interface.

`worker status` is the first diagnostic before every writable start. A live but
unresponsive PID, identity mismatch, ownership mismatch, lock, or IDA sidecars
blocks automatic startup. Preserve all state and escalate rather than deleting
files or terminating processes.

Status reports source identity and database lineage independently. A recognized
checkpoint may change the packed hash and advance `database.generation`.
Source mismatch, unexplained packed change, decreasing generation, interrupted
checkpoint, or failed reopen remains a hard block. The atomic lineage journal
supports diagnosis but does not authorize dead-worker recovery.

If startup fails:

1. read the bridge error and runtime log path it reports;
2. confirm Node, the licensed runtime, and compatible Python are available;
3. check whether an old worker is still reported by `worker status`;
4. recover a responsive abandoned worker with `worker
   recover-unclosed-database`; otherwise escalate;
5. reprovision only when validation reports missing or incompatible files.

Normal completion uses `worker save-and-close`; `save` alone is not completion.
On a save or shutdown timeout, the bridge leaves the worker, state record,
sidecars, database, and log intact and returns a diagnostic. Do not force-kill
or remove sidecars as a troubleshooting shortcut.

`recover-unclosed-database` requires the recorded worker to be alive,
responsive, and authenticated. If a dead worker leaves unpacked sidecars,
preserve the complete artifact set. The latest confirmed packed generation is
the automatic recovery point; sidecar promotion requires a separate forensic
procedure and explicit approval.

On macOS, copied binaries may require quarantine removal according to local
security policy. Do not bypass platform security controls without authorization.
