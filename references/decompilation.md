# Decompilation — Understanding Code

All commands take `--binary <path>` (or `--port <n>`). For the full command
index see [commands.md](commands.md); for a command's exact parameters run
`python3 scripts/cli.py <command> --help`.

## Decompile & disassemble

```bash
python3 scripts/cli.py decompile-function main --binary $B     # Hex-Rays pseudocode (alias: decompile)
python3 scripts/cli.py decompile-function 0x401000 --binary $B
python3 scripts/cli.py disassemble-function main --binary $B   # full function listing
python3 scripts/cli.py decode-instruction 0x401000 --binary $B # one instruction, full operand detail
python3 scripts/cli.py decode-instructions 0x401000 --count 16 --binary $B
```

`decompile-function` needs the Hex-Rays plugin (bundled in the runtime).
`disassemble-function` and `decode-*` do not and are faster for quick looks.
Disassembly output is one `<address>  <instruction>` pair per line by default;
use `--output json` when a structured result is required.

## Function structure

```bash
python3 scripts/cli.py get-function main --binary $B          # bounds, size, flags, comments, chunks
python3 scripts/cli.py get-function-vars main --binary $B     # locals via decompilation
python3 scripts/cli.py get-stack-frame main --binary $B       # stack layout: offsets/sizes/names
python3 scripts/cli.py list-decompiler-variables main --binary $B
python3 scripts/cli.py get-processor-info --binary $B         # arch, bitness, register names
```

## Decompiler internals (ctree / microcode / operands)

```bash
python3 scripts/cli.py get-ctree main --depth 3 --binary $B          # decompiler AST
python3 scripts/cli.py find-ctree-calls main --binary $B             # calls in the AST
python3 scripts/cli.py find-ctree-patterns main --pattern_type string_refs --binary $B
python3 scripts/cli.py get-microcode main --binary $B                # microcode at a maturity level
python3 scripts/cli.py get-operand-value 0x401000 --operand_index 1 --binary $B
```

`find-ctree-patterns` supports `calls`, `string_refs`, `comparisons`,
`assignments`, `casts`, `pointer_derefs`, or `all`.

## Decompilation workflow

```bash
B=/path/to/bin

python3 scripts/cli.py get-database-info --binary $B          # → entry_point
python3 scripts/cli.py decompile-function 0x401000 --binary $B
# spot sub_XXXX calls in the output, then dive:
python3 scripts/cli.py decompile-function sub_401200 --binary $B
python3 scripts/cli.py get-xrefs-from sub_401200 --binary $B  # data it touches
python3 scripts/cli.py read-bytes 0x402050 64 --binary $B
```

Fix wrong prototypes / variable types as you go — see
[labeling.md](labeling.md) (`set-type`, `set-function-type`,
`retype-decompiler-variable`).

→ Full catalog: [commands.md](commands.md) · `python3 scripts/cli.py commands`
