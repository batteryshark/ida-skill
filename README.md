# IDA Skill

IDA Skill is a Codex-compatible skill and local bridge that lets coding agents
and reverse engineers drive a licensed IDA Pro 9.x installation through
persistent headless workers.

Each binary gets its own local worker. The worker opens the database once,
accepts concurrent CLI or MCP clients, saves changes periodically, and exits
after an idle timeout. The command surface covers disassembly, decompilation,
cross-references, types, database edits, patching, assembly, and local or remote
debugging through IDA debug servers.

This repository contains source code only. It does **not** contain IDA, Hex-Rays
decompilers, debug servers, license files, or accepted-EULA state. Provision the
runtime from an IDA installation and license you are authorized to use.

## Requirements

- A paid IDA Pro 9.x installation and valid license
- Node.js 22 or newer
- The CPython ABI required by that IDA release; IDA 9.4 uses CPython 3.13
- `uv` only for the optional MCP server

For a portable licensed bundle, start IDA once and accept its EULA. Setup must
be able to find `idapro.hexlic` plus `ida.reg` on macOS/Linux; pass
`--license-dir <path>` when they are outside the normal IDA directories.

The provisioner recognizes macOS x64/arm64, Linux x64/arm64, and Windows x64.
Source and provisioning tests run on all three operating systems. A licensed
end-to-end IDA 9.4 smoke test has been run on macOS.

## Quickstart

Clone the source, then copy a private runtime from your IDA installation:

```bash
git clone https://github.com/batteryshark/ida-skill.git
cd ida-skill

node scripts/setup.mjs --ida-dir "/path/to/your/IDA" --include-license
```

Common installation paths:

```bash
# macOS
node scripts/setup.mjs --ida-dir "/Applications/IDA Professional 9.4.app" --include-license

# Linux
node scripts/setup.mjs --ida-dir "/opt/ida" --include-license

# Windows
node scripts/setup.mjs --ida-dir "C:\Path\To\IDA Professional 9.4" --include-license
```

Analyze a binary, query it, and stop the worker:

```bash
node scripts/bridge.mjs start --binary /path/to/binary
python3 scripts/cli.py get-database-info --binary /path/to/binary
python3 scripts/cli.py list-functions --limit 20 --binary /path/to/binary
node scripts/bridge.mjs stop --binary /path/to/binary
```

Use `python` instead of `python3` on hosts where that is the CPython command.
The CLI can also auto-start a missing worker on first use.

## Agent integration

`SKILL.md` is the canonical agent and operating guide. For Codex, clone the
repository into the skills directory:

```bash
# macOS / Linux
git clone https://github.com/batteryshark/ida-skill.git \
  "${CODEX_HOME:-$HOME/.codex}/skills/ida-skill"
```

```powershell
# Windows PowerShell
git clone https://github.com/batteryshark/ida-skill.git `
  "$env:USERPROFILE\.codex\skills\ida-skill"
```

`agents/openai.yaml` supplies Codex UI metadata. The CLI and MCP entry points
also work directly when an agent does not load skills.

## Repository map

| Path | Purpose |
| --- | --- |
| `SKILL.md` | Canonical agent instructions and operating guide |
| `agents/openai.yaml` | Codex UI metadata |
| `scripts/setup.mjs` | Copy a private runtime from a licensed IDA installation |
| `scripts/bridge.mjs` | Start, stop, and inspect persistent workers |
| `scripts/worker.py` | Headless idalib TCP worker |
| `scripts/cli.py` | Manifest-driven command-line client |
| `scripts/mcp_server.py` | Optional FastMCP server |
| `scripts/handlers/` | Command implementations grouped by IDA domain |
| `references/` | Generated catalog and task-focused workflows |
| `tests/` | Source-only unit and cross-platform provisioning tests |

## Portable runtime options

Setup writes proprietary files to the ignored `bin/` directory by default.
`--include-license` copies your private license and EULA state; omit it to use
the host's existing IDA configuration.

```bash
# Trimmed runtime: idalib, common processors/loaders/decompilers, and dbgsrv
node scripts/setup.mjs --ida-dir "/path/to/IDA" --include-license

# Full runtime: untrimmed installation plus private license state
node scripts/setup.mjs --ida-dir "/path/to/IDA" --include-license --full

# Keep the private payload outside the source checkout
node scripts/setup.mjs --ida-dir "/path/to/IDA" \
  --bundle-dir "/private/ida-bundle" --include-license --full
export IDA_SKILL_BIN_DIR="/private/ida-bundle"
```

The bundle is self-contained for IDA files and license state. Node.js and an
ABI-compatible Python interpreter remain host prerequisites. Confirm that your
Hex-Rays agreement permits every machine and location where you use a copied
runtime.

To assemble one private bundle for all three operating systems, provision each
runtime from the corresponding installation:

```bash
node scripts/setup.mjs --ida-dir "/path/to/mac-IDA" --target-platform mac --include-license
node scripts/setup.mjs --ida-dir "/path/to/linux-IDA" --target-platform linux --include-license
node scripts/setup.mjs --ida-dir "/path/to/windows-IDA" --target-platform windows --include-license
```

## Multiple agents and binaries

Start with `--multi-agent` when several agents will share a database:

```bash
node scripts/bridge.mjs start --binary /path/to/binary --multi-agent
```

Requests are serialized on IDA's main thread and responses stay paired with
their requesting client. Multi-agent mode blocks global rollback operations
such as undo and snapshot restore. Use a separate worker for each binary;
workers shut down after 10 idle minutes by default.

## Commands and MCP

The generated catalog currently contains 291 commands, including 106 debugger
commands:

```bash
python3 scripts/cli.py commands
python3 scripts/cli.py commands --category debug
python3 scripts/cli.py list-functions --help
```

Decompilation requires the licensed Hex-Rays decompiler for the binary's
architecture. Choose a function name or address from `list-functions`, then
run:

```bash
python3 scripts/cli.py decompile-function FUNCTION --binary /path/to/binary
```

After starting a worker, expose the same canonical commands over MCP:

```bash
uv run scripts/mcp_server.py --binary /path/to/binary
```

See [SKILL.md](SKILL.md) for the complete operating guide and
[references/commands.md](references/commands.md) for the generated command
index. Task-focused guides cover [navigation](references/navigation.md),
[decompilation](references/decompilation.md),
[database labeling and edits](references/labeling.md), and
[dynamic debugging](references/dynamic.md).

## Verify the checkout

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
node --test tests/test_setup.mjs
python3 scripts/check_public.py
```

GitHub Actions runs these checks on Ubuntu, macOS, and Windows. Licensed IDA
files stay outside CI and outside this repository.

## License

The skill source is available under the [MIT License](LICENSE). Portions of the
handler and helper layer are adapted from
[re-mcp](https://github.com/jtsylve/re-mcp); see [NOTICE](NOTICE).

IDA Pro, idalib, Hex-Rays decompilers, licenses, and debug servers are separate
proprietary Hex-Rays material. This project is independent and is not affiliated
with or endorsed by Hex-Rays.
