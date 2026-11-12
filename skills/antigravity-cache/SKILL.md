---
name: antigravity-cache
description: Zero-LLM AST/SQLite structural pointer cache and cloud KV-prefix telemetry (`kv_pointer_cache.py`). Use before reading large source files (>250 lines), when locating symbols across a repository, or when benchmarking token savings and Antigravity cloud KV-cache hit rates.
---

# Antigravity Cache (`kv_pointer_cache.py`)

Deterministic local structural pointer cache built for agentic IDEs. Unlike LLM-based rolling summary caches (which rewrite earlier context and destroy cloud KV-prefix caching), **Antigravity Cache**:
- Uses **0 LLM tokens** (Python `ast` + fence-aware Markdown + JS/TS/Rust/Go brace extractors backed by SQLite WAL).
- Never mutates prior conversation turns (`ephemeralMessage` tail injection only).
- Emits exact `[Lstart-Lend]` line pointers + SHA-256 node digests + `StartLine`/`EndLine` slicing.

## Core Commands

```bash
# Structural outline (>250 lines) or direct numbered inline (<=250 lines)
python scripts/kv_pointer_cache.py map path/to/large_file.py

# Search symbols by name, signature, docstring, or callees across a repo
python scripts/kv_pointer_cache.py locate SymbolOrQuery --root path/to/repo

# Extract exact lines for one function, class, method, or Markdown heading
python scripts/kv_pointer_cache.py slice path/to/large_file.py ClassName.method_name

# Cumulative savings, warm latency benchmark (<0.3ms), and cloud KV-cache telemetry
python scripts/kv_pointer_cache.py stats
```

## Notes

- Override DB location with `ANTIGRAVITY_CACHE_DB=/path/to/cache.sqlite` or `--db`.
- Pass `--force-map` on `map` to print an AST structural map even for `<=250`-line files.
- Never triggers on `.md`, `.json`, images, or bounded `read_file(StartLine, EndLine)` calls.
