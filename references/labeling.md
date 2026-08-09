# Labeling — Modifying the Database

All commands take `--binary <path>` (or `--port <n>`). Changes persist to the
`.i64` database on graceful worker shutdown (`bridge.mjs stop` or idle timeout);
force a checkpoint any time with `python3 scripts/cli.py save --binary $B`.

For the full command index see [commands.md](commands.md); for a command's exact
parameters run `python3 scripts/cli.py <command> --help`. `*` in the index marks
mutating commands. Most mistakes are reversible with `undo` or a `snapshot`.

## Naming & comments

```bash
python3 scripts/cli.py rename-function sub_401000 decrypt_aes --binary $B
python3 scripts/cli.py rename-address 0x403000 g_aes_key --binary $B     # alias: rename
python3 scripts/cli.py set-comment 0x401000 "AES round loop" --binary $B
python3 scripts/cli.py set-comment 0x401000 "DECRYPT" --repeatable --binary $B
python3 scripts/cli.py set-function-comment main "entry" --binary $B
python3 scripts/cli.py set-decompiler-comment main 0x401010 "key schedule" --binary $B
```

## Types & prototypes

```bash
python3 scripts/cli.py set-type 0x403000 "struct config_t *" --binary $B
python3 scripts/cli.py set-function-type 0x401000 "int __fastcall decrypt(void *buf, int len)" --binary $B
python3 scripts/cli.py parse-type-declaration "struct hdr { int magic; int len; };" --binary $B
python3 scripts/cli.py apply-type-at-address 0x403000 hdr --binary $B
```

## Structures & enums

```bash
python3 scripts/cli.py create-structure config_t --binary $B
python3 scripts/cli.py add-struct-member config_t key_ptr --offset 0 --size 8 --type_str "char *" --binary $B
python3 scripts/cli.py retype-struct-member config_t key_ptr "unsigned char *" --binary $B
python3 scripts/cli.py create-enum error_e --binary $B
python3 scripts/cli.py add-enum-member error_e E_OK 0 --binary $B
```

## Decompiler variables

```bash
python3 scripts/cli.py rename-decompiler-variable main v3 key_len --binary $B
python3 scripts/cli.py retype-decompiler-variable main key_len "size_t" --binary $B
```

## Patching & assembly

```bash
python3 scripts/cli.py patch-bytes 0x401400 --hex_bytes "b801000000c3" --binary $B  # mov eax,1; ret
python3 scripts/cli.py patch-asm 0x401400 --instruction "nop" --binary $B
python3 scripts/cli.py make-code 0x401500 --binary $B
python3 scripts/cli.py undefine 0x401500 --binary $B
python3 scripts/cli.py make-string 0x402000 --string_type c --binary $B
python3 scripts/cli.py make-data 0x402100 --data_type dword --count 4 --binary $B
```

Patch commands return `old_bytes`/`new_bytes` for verification and undo.

## Undo & snapshots

```bash
python3 scripts/cli.py undo --binary $B
python3 scripts/cli.py redo --binary $B
python3 scripts/cli.py take-snapshot --description "before patching" --binary $B
python3 scripts/cli.py list-snapshots --binary $B
python3 scripts/cli.py restore-snapshot <id> --binary $B
python3 scripts/cli.py save --binary $B      # force checkpoint to .i64
```

## Labeling workflow

```bash
B=/path/to/bin

python3 scripts/cli.py decompile-function sub_401200 --binary $B   # study it
python3 scripts/cli.py take-snapshot --description "pre-annotate" --binary $B
python3 scripts/cli.py rename-function sub_401200 aes_decrypt --binary $B
python3 scripts/cli.py set-comment 0x401200 "AES-256-CBC. Key from g_key." --binary $B
python3 scripts/cli.py set-function-type 0x401200 "int aes_decrypt(void *ct, int len, void *pt)" --binary $B
python3 scripts/cli.py rename-address 0x403000 g_aes_key --binary $B
# defeat a license check: always return true
python3 scripts/cli.py patch-bytes 0x401400 --hex_bytes "b801000000c3" --binary $B
python3 scripts/cli.py save --binary $B
```

→ Full catalog: [commands.md](commands.md) · `python3 scripts/cli.py commands`
