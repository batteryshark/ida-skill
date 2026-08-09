# Dynamic Analysis — The Headless Debugger

The worker exposes IDA's full headless debugger as **106 `debug-*` commands**
(`ida_dbg` / `ida_idd`), driving a local or remote target through an IDA
`dbgsrv` listener. All commands take `--binary <path>` (or `--port <n>`) and the
worker's database must already be open.

This guide is a workflow map. For every command and its parameters, see
[commands.md](commands.md) (Debugger section) or run
`python3 scripts/cli.py commands --category debug`.

> One process per worker at a time. Where IDA has no portable cross-debugger
> API (e.g. some memory alloc/protect ops), the command returns a structured
> `{"status": "unsupported", ...}` result instead of failing hard.

## 1. Deploy a dbgsrv on the target

The remote debug servers live in `bin/dbgsrv/`. Copy the matching one to the
target host and run it (listens on port **23946** by default):

| Target                | Binary |
|-----------------------|--------|
| Linux x64 / x86       | `linux_server` / `linux_server32` |
| macOS x64 / arm64     | `mac_server` / `mac_server_arm` |
| Windows x64 / x86     | `win64_remote.exe` / `win32_remote32.exe` |
| Android / ARM Linux   | `android_server*` / `armlinux_server*` |

```bash
# on the target:
./linux_server            # or: win64_remote.exe
```

For **local** debugging the worker host is the target — run the matching server
on the same machine and point at `127.0.0.1`.

## 2. Launch or attach

`debug-start` loads the debugger module, sets the remote endpoint, and starts
the target in one step:

```bash
python3 scripts/cli.py debug-start \
  --debugger linux --remote --target_host 192.168.1.50 --target_port 23946 \
  --target_path /opt/target/app --args "-v config.bin" --working_directory /opt/target \
  --binary $B
```

Attach to a running process instead:

```bash
python3 scripts/cli.py debug-process-list --remote --target_host 192.168.1.50 --binary $B
python3 scripts/cli.py debug-attach 4242 --remote --target_host 192.168.1.50 --binary $B
```

`--debugger` is the IDA module name (`linux`, `win32` — used for 64-bit Windows
too, `mac`, `gdb`, ...). Omit `--remote` for a local server.

## 3. Breakpoints

```bash
python3 scripts/cli.py debug-breakpoint-add main --binary $B                 # software exec bp
python3 scripts/cli.py debug-breakpoint-add 0x401000 --type write --size 4 --binary $B  # hw memory bp
python3 scripts/cli.py debug-breakpoint-add decrypt --condition "rdi != 0" --binary $B
python3 scripts/cli.py debug-breakpoint-list --binary $B
python3 scripts/cli.py debug-breakpoint-toggle main --no-enabled --binary $B
python3 scripts/cli.py debug-breakpoint-delete main --binary $B
python3 scripts/cli.py debug-breakpoint-condition-set decrypt --condition "rsi == 0x100" --binary $B
```

`--type` is `software`/`soft`, `exec`/`execute`, `read`, `write`, or
`readwrite`/`rw` (the last four are hardware breakpoints). Breakpoint groups:
`debug-breakpoint-group-set/list/enable/delete`.

## 4. Execution control

```bash
python3 scripts/cli.py debug-continue --binary $B
python3 scripts/cli.py debug-step-into --binary $B
python3 scripts/cli.py debug-step-over --binary $B
python3 scripts/cli.py debug-step-out --binary $B
python3 scripts/cli.py debug-run-to 0x401500 --binary $B
python3 scripts/cli.py debug-wait-until --event breakpoint --timeout_seconds 30 --binary $B
python3 scripts/cli.py debug-status --binary $B      # state, current IP/SP, threads
python3 scripts/cli.py debug-pause --binary $B
python3 scripts/cli.py debug-exit --binary $B        # also: debug-detach / debug-kill / debug-restart
```

## 5. Registers & flags

```bash
python3 scripts/cli.py debug-registers-read --binary $B         # all registers
python3 scripts/cli.py debug-gp-registers-read --binary $B      # general-purpose only
python3 scripts/cli.py debug-register-write rax 0x1 --binary $B
python3 scripts/cli.py debug-flags-read --binary $B
python3 scripts/cli.py debug-flags-write ZF 1 --binary $B
```

## 6. Memory

```bash
python3 scripts/cli.py debug-memory-read 0x7fffffffe000 --size 64 --binary $B
python3 scripts/cli.py debug-memory-write 0x7fffffffe000 "9090" --binary $B
python3 scripts/cli.py debug-memory-dump 0x400000 4096 --binary $B
python3 scripts/cli.py debug-memory-map --binary $B
python3 scripts/cli.py debug-memory-search "48 89 e5" --binary $B
python3 scripts/cli.py debug-memory-is-valid 0x401000 --binary $B
python3 scripts/cli.py debug-memory-protection 0x401000 --binary $B
```

`debug-memory-allocate` / `debug-memory-free` / `debug-memory-protect` may
report `unsupported` depending on the debugger backend.

## 7. Threads, modules, symbols

```bash
python3 scripts/cli.py debug-stacktrace --binary $B
python3 scripts/cli.py debug-thread-list --binary $B
python3 scripts/cli.py debug-thread-select 4242 --binary $B
python3 scripts/cli.py debug-thread-teb --binary $B
python3 scripts/cli.py debug-module-list --binary $B
python3 scripts/cli.py debug-symbol-resolve --symbol malloc --binary $B
python3 scripts/cli.py debug-remote-get-proc-address kernel32.dll VirtualAlloc --binary $B
```

## 8. Runtime disassembly, patching, tracing, appcall

```bash
python3 scripts/cli.py debug-disassemble 0x401000 --count 8 --binary $B
python3 scripts/cli.py debug-patch-instruction 0x401000 --instruction "nop" --binary $B
python3 scripts/cli.py debug-branch-destination 0x401010 --binary $B
python3 scripts/cli.py debug-trace-enable --binary $B          # step/insn/func/bblk tracing
python3 scripts/cli.py debug-trace-events --binary $B
python3 scripts/cli.py debug-trace-save trace.bin --binary $B
python3 scripts/cli.py debug-appcall malloc --prototype "void *malloc(size_t)" --args "[256]" --binary $B
python3 scripts/cli.py debug-last-exception --binary $B
python3 scripts/cli.py debug-exception-list --binary $B
```

## 9. Static ↔ dynamic bridge

```bash
python3 scripts/cli.py debug-current-location --binary $B       # IP with the static function context
python3 scripts/cli.py debug-decompile-current --binary $B      # decompile the current function
python3 scripts/cli.py debug-annotate-current "hit here" --binary $B
python3 scripts/cli.py debug-sync-runtime-modules --binary $B
python3 scripts/cli.py debug-rebase-database --binary $B        # rebase IDB to the runtime base
```

## End-to-end workflow

```bash
B=/path/to/bin; PORT_HOST=192.168.1.50

# 1. set breakpoints (worker DB already open)
python3 scripts/cli.py debug-breakpoint-add main --binary $B

# 2. launch the target under the remote server (stops at the breakpoint)
python3 scripts/cli.py debug-start --debugger linux --remote \
  --target_host $PORT_HOST --target_port 23946 --target_path /opt/target/app --binary $B

# 3. inspect
python3 scripts/cli.py debug-status --binary $B
python3 scripts/cli.py debug-registers-read --binary $B
python3 scripts/cli.py debug-memory-read 0x404000 --size 32 --binary $B

# 4. step / continue
python3 scripts/cli.py debug-step-over --binary $B
python3 scripts/cli.py debug-continue --binary $B

# 5. done
python3 scripts/cli.py debug-exit --binary $B
```

→ Full catalog: [commands.md](commands.md) (Debugger) · `python3 scripts/cli.py commands --category debug`
