# Antigravity Cache — Zero-LLM Structural Pointer Protocol

To protect your cloud KV-prefix cache (`~90%` cost reduction on cached context) and avoid flooding the context window with raw source code before targeted edits:

1. **Map Before Reading Large Source Files (`>250` lines):**
   Before reading an entire source file you have not inspected yet, run the structural pointer map (`0` LLM tokens, `<0.3ms` warm SQLite WAL hit):
   ```bash
   python scripts/kv_pointer_cache.py map <file_path>
   ```
   - Files with `<=250` lines automatically inline numbered source so you never pay a second read call.
   - Larger files emit a deterministic `[Lstart-Lend]` symbol outline + intra-file call edges.
2. **Read Only Exact Line Ranges or Symbol Slices:**
   Use `read_file` with explicit `StartLine` and `EndLine`, or extract a single symbol via `slice`:
   ```bash
   python scripts/kv_pointer_cache.py slice <file_path> <ClassName.method>
   ```
3. **Auto-Guard Escape Hatch:**
   If you call `read_file` without `StartLine`/`EndLine` on a `>250`-line source file, the `PreToolUse` Auto-Guard safely caps the first read to `L1-L80` and delivers the full `[Lstart-Lend]` map once via `ephemeralMessage`. Calling `read_file` a second time on the same file passes through unobstructed if you truly need the full file.
