# Setup and troubleshooting

Read this when provisioning a runtime or diagnosing startup, save, or shutdown
failures. Run commands from the skill directory.

## Provision a private runtime

Keep this repository source-only. Do not commit or redistribute `bin/`, an IDA
installation, a license file, EULA state, or dbgsrv binaries. Confirm that your
Hex-Rays agreement permits every machine and location where you use a copied
runtime.

Install Node.js 22+ (Node 24 LTS recommended) and the CPython major/minor ABI
required by your IDA build (for example, CPython 3.13 for IDA 9.4). Then copy
from your own installation. Install `uv` only if you plan to use the optional
MCP server.

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

## Troubleshooting

- **Upgrading a running worker** — stop workers with the bridge version that
  started them before upgrading. Current workers use an atomic
  `worker-<hash>.json` record containing their PID, port, original requested
  path and fresh session ID. Legacy PID/port files alone cannot verify an
  owner; the current bridge refuses to attach or stop through them. The bridge
  never sends termination signals to a recorded PID. Direct `--port` remains
  available for deliberate compatibility use, without session verification.
- **Identity mismatch or malformed state** — preserve the state and inspect the
  log. A listening port and live PID do not establish that they belong to the
  same worker. Do not rewrite the record to bypass the check. Session IDs prevent
  accidental misrouting; they are not authentication against local programs.
- **Lifecycle lock timeout** — starts and stops for the same requested path
  share a lock. Wait for the owning operation. If it crashed, confirm that the
  recorded lock owner has exited, check for a surviving worker, and ensure no
  lifecycle commands are running before removing only the stale `.lock` file.
  Stale locks are deliberately not reclaimed automatically: competing
  reclaimers could otherwise remove a newly acquired lock. Leave database,
  sidecar and worker state files intact.
- **"Runtime not provisioned"** — run `node scripts/setup.mjs --ida-dir /path/to/ida`; add `--include-license` only for a private self-contained bundle.
- **"No worker found for..."** — `cli.py` normally auto-starts one (the worker
  may have auto-shutdown after the idle timeout, 10 min default). If auto-start
  is disabled or failed, run `bridge.mjs start --binary <path>` and check the log.
- **"Connection refused"** — inspect `bridge.mjs status` and the log at
  `bin/runtime/worker-<hash>.log` (under `IDA_SKILL_BIN_DIR` for an external
  bundle). A live PID may still be starting or unresponsive; do not infer a
  dead worker solely from a failed connection.
- **"Out of private address space for netnodes" or leftover sidecars** — inspect
  worker status and the log before diagnosing corruption. A live worker can own
  unpacked `.id0`/`.id1`/`.id2`/`.nam`/`.til` files while the packed `.i64`/`.idb`
  is older. Preserve the database and sidecars; deleting them can discard analysis.
  Close a responsive worker normally before opening its database elsewhere.
  For a dead or unresponsive worker, preserve the artifacts for recovery; do not
  automatically delete them or replace the packed database.
- **Analysis timeout** — large binaries take time. A live worker and its state
  are preserved after the startup timeout. Check `bridge.mjs status` and the log;
  let that worker finish instead of starting a second one. For a fresh start,
  allow more time with `bridge.mjs start --binary <path> --timeout 600`.
- **Save or shutdown failure** — a failed `bridge.mjs stop` returns nonzero and
  preserves its state. A save failure leaves the worker available for diagnosis;
  if the shutdown acknowledgement was lost, it may already be exiting. Inspect
  status and the log before retrying; do not force-kill a worker that may still
  be saving. An already-exited worker can be cleaned up, but that alone does not
  prove that its last save succeeded.
- **macOS segfaults** — ensure `setup.mjs` used `ditto` (not `cp`). Re-run
  setup with `--force` (and repeat `--include-license` if wanted). Setup recursively clears the
  quarantine attribute from the locally provisioned runtime; for an existing
  archive, rerun setup once or use
  `xattr -dr com.apple.quarantine bin/ida-runtime-mac`.
- **Python exits during `import idapro`** — IDA 9.4 targets CPython 3.13. The
  bridge prefers `python3.13`; set `IDA_PYTHON=/path/to/python` to override it
  for another IDA release.
