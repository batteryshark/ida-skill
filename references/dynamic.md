# IDA Dynamic Analysis

Dynamic commands execute or alter a debuggee. Use them only for an authorized
target in an environment where execution risk is acceptable. Start with status,
module, thread, register, and memory reads; treat continue/step, register writes,
memory writes, appcall, and process control as side effects.

## Debug Server

IDA uses the matching `dbgsrv` for remote or cross-platform targets. Start the
server on the target, restrict it to a trusted interface or firewall boundary,
and do not expose it to untrusted networks. Configure authentication where the
server supports it and pass the corresponding password through `debug-start` or
the relevant debugger command; do not place credentials in committed files or
logs.

Use `debug-start --help` for debugger, host, port, password, process, and launch
options. It combines backend selection, endpoint configuration, and launch, so
no additional wrapper sequence is needed.

```bash
python3 scripts/cli.py debug-start --help
python3 scripts/cli.py debug-breakpoint-add 0x401000 --binary "$B"
python3 scripts/cli.py debug-continue --binary "$B"
python3 scripts/cli.py debug-registers --binary "$B"
```

## Workflow

1. Confirm the selected debugger and target architecture.
2. Start or attach and inspect modules, runtime base, threads, and status.
3. Add a narrowly chosen breakpoint before continuing.
4. At a stop, inspect registers, stack, memory, and nearby instructions.
5. Step or run to a known address; reassess after every event.
6. Synchronize runtime modules or rebase the database only when load addresses
   require it and the consequences are understood.
7. Detach or exit cleanly and save useful database changes.

Do not automate the inspect/step/interpret loop as a fixed wrapper: each next
operation depends on the observed runtime state. Use timeouts for waits and
long-running operations. When interruption or transport failure occurs, check
debugger status before retrying to avoid duplicate execution or writes.

Memory and register writes affect the live debuggee, not merely the IDA
database. Database labels or comments made during debugging persist separately.
State both effects when a workflow uses both classes of command.
