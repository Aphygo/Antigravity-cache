#!/usr/bin/env python3
"""Standalone cross-platform pytest suite for Aphygo/Antigravity-cache."""

from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import install as installer  # noqa: E402
from kv_pointer_cache import KVPointerCache, decompose_file, main as cli_main  # noqa: E402

REAL_CACHE_FILE = SCRIPTS_DIR / "kv_pointer_cache.py"


def test_sqlite_schema_and_cold_vs_warm_real_file(tmp_path: Path) -> None:
    """1. Cold vs warm (<1ms, target <0.5ms) indexing on real Python code + SQLite schema."""
    db_path = tmp_path / "pointers.sqlite"
    assert REAL_CACHE_FILE.exists()

    with KVPointerCache(db_path=db_path) as cache:
        conn = sqlite3.connect(db_path)
        file_cols = {r[1] for r in conn.execute("PRAGMA table_info(files)").fetchall()}
        sym_cols = {r[1] for r in conn.execute("PRAGMA table_info(symbols)").fetchall()}
        tbls = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()

        assert {"files", "symbols", "telemetry_counters", "pending_auto_maps", "guard_allowlist"} <= tbls
        assert {"path", "mtime_ns", "size_bytes", "file_sha256", "raw_tokens", "indexed_at"} <= file_cols
        assert {
            "path",
            "qualified_name",
            "kind",
            "start_line",
            "end_line",
            "signature",
            "doc_headline",
            "calls_json",
            "content_sha256",
            "estimated_tokens",
        } <= sym_cols

        cold = cache.index_file(REAL_CACHE_FILE)
        assert cold["cache_hit"] is False
        assert cold["symbol_count"] >= 20
        assert cold["raw_tokens"] > 10_000

        warm_timings_ms: list[float] = []
        warm = None
        for _ in range(5):
            t0 = time.perf_counter()
            warm = cache.index_file(REAL_CACHE_FILE)
            warm_timings_ms.append((time.perf_counter() - t0) * 1000.0)

        assert warm is not None
        assert warm["cache_hit"] is True
        assert min(warm_timings_ms) < 0.5


def test_incremental_symbol_diff_on_edit(tmp_path: Path) -> None:
    """2. Incremental symbol diff (unchanged vs modified vs added vs removed)."""
    db_path = tmp_path / "diff_test.sqlite"
    src_file = tmp_path / "engine.py"

    v1_code = textwrap.dedent(
        '''\
        def keep_unchanged(x: int) -> int:
            return x * 2

        def will_modify(items: list[int]) -> int:
            return sum(items)

        def will_remove(flag: bool) -> str:
            return "yes" if flag else "no"
        '''
    )
    src_file.write_text(v1_code, encoding="utf-8")

    with KVPointerCache(db_path=db_path) as cache:
        res1 = cache.index_file(src_file)
        assert set(res1["diff"]["added"]) == {"keep_unchanged", "will_modify", "will_remove"}

        v2_code = textwrap.dedent(
            '''\
            def keep_unchanged(x: int) -> int:
                return x * 2

            def will_modify(items: list[int], offset: int = 10) -> int:
                return sum(items) + offset

            def newly_added(name: str) -> str:
                return f"hi {name}"
            '''
        )
        src_file.write_text(v2_code, encoding="utf-8")
        st = src_file.stat()
        os.utime(src_file, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))

        res2 = cache.index_file(src_file)
        diff = res2["diff"]
        assert diff["added"] == ["newly_added"]
        assert diff["removed"] == ["will_remove"]
        assert "keep_unchanged" in diff["unchanged"]
        assert "will_modify" in diff["modified"]


def test_exact_line_range_accuracy_and_token_savings(tmp_path: Path) -> None:
    """3. Exact line-range slice accuracy (>85% savings, deterministic KV-safe maps, 0 LLM tokens)."""
    db_path = tmp_path / "accuracy.sqlite"
    raw_lines = REAL_CACHE_FILE.read_text(encoding="utf-8").splitlines()

    with KVPointerCache(db_path=db_path) as cache:
        m1 = cache.render_file_map(REAL_CACHE_FILE)
        m2 = cache.render_file_map(REAL_CACHE_FILE)
        assert m1["map_text"] == m2["map_text"]
        assert m1["llm_tokens_used"] == 0
        assert m1["savings_pct"] > 75.0

        sl = cache.read_slice(REAL_CACHE_FILE, "KVPointerCache.render_file_map")
        assert sl["token_savings_pct"] > 85.0
        assert sl["lines"] == raw_lines[sl["start_line"] - 1 : sl["end_line"]]


def test_polyglot_markdown_ts_rust_and_locate_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """4. Polyglot Markdown (fence-safe), TypeScript, and Rust pointer extraction + CLI."""
    db_path = tmp_path / "polyglot.sqlite"
    proj = tmp_path / "poly"
    proj.mkdir()

    md_file = proj / "ARCH.md"
    md_file.write_text(
        "# Title\nIntro\n```python\n# Ignored heading\ndef x(): pass\n```\n## Details\nBody\n",
        encoding="utf-8",
    )
    ts_file = proj / "client.ts"
    ts_file.write_text(
        "export class Client {\n  async ping(): Promise<void> { return helper(); }\n}\nexport const helper = () => {};\n",
        encoding="utf-8",
    )
    rs_file = proj / "kernel.rs"
    rs_file.write_text(
        "#[derive(Debug)]\npub struct State { pub val: i32 }\nimpl State {\n  pub fn step(&self) -> i32 { self.val }\n}\n",
        encoding="utf-8",
    )

    assert [s.qualified_name for s in decompose_file(md_file)] == ["Title", "Details"]
    ts_syms = {s.qualified_name for s in decompose_file(ts_file)}
    assert {"Client", "Client.ping", "helper"} <= ts_syms
    rs_syms = {s.qualified_name: s for s in decompose_file(rs_file)}
    assert rs_syms["State"].start_line == 1
    assert "State.step" in rs_syms

    assert cli_main(["locate", "State.step", "--root", str(proj), "--db", str(db_path), "--json"]) == 0
    hits = json.loads(capsys.readouterr().out)
    assert hits[0]["qualified_name"] == "State.step"


def test_pre_tool_auto_guard_escape_hatch_and_ephemeral_delivery(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """5. Soft PreToolUse Auto-Guard, PreInvocation ephemeralMessage delivery, and escape hatch."""
    db_path = tmp_path / "guard.sqlite"
    small_py = tmp_path / "small.py"
    small_py.write_text("def tiny():\n    return 1\n", encoding="utf-8")

    large_md = tmp_path / "docs.md"
    large_md.write_text("\n".join(f"# Heading {i}\nParagraph {i}" for i in range(200)), encoding="utf-8")

    with KVPointerCache(db_path=db_path) as cache:
        assert cache.handle_pre_tool_read(
            {"conversationId": "c1", "toolCall": {"name": "read_file", "args": {"Path": str(REAL_CACHE_FILE), "StartLine": 1, "EndLine": 40}}}
        ) == {"decision": "allow"}
        assert cache.handle_pre_tool_read(
            {"conversationId": "c1", "toolCall": {"name": "read_file", "args": {"Path": str(large_md)}}}
        ) == {"decision": "allow"}
        assert cache.handle_pre_tool_read(
            {"conversationId": "c1", "toolCall": {"name": "read_file", "args": {"Path": str(small_py)}}}
        ) == {"decision": "allow"}

        first = cache.handle_pre_tool_read(
            {"conversationId": "c1", "toolCall": {"name": "read_file", "args": {"Path": str(REAL_CACHE_FILE)}}}
        )
        assert first == {"decision": "allow", "overwrite": {"StartLine": 1, "EndLine": 80}}

        second = cache.handle_pre_tool_read(
            {"conversationId": "c1", "toolCall": {"name": "read_file", "args": {"Path": str(REAL_CACHE_FILE)}}}
        )
        assert second == {"decision": "allow"}

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"conversationId": "c1"})))
    assert cli_main(["hook", "--event", "pre_invocation", "--db", str(db_path)]) == 0
    hook_out = json.loads(capsys.readouterr().out)
    assert "Auto-Guard" in hook_out["injectSteps"][0]["ephemeralMessage"]

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"conversationId": "c1"})))
    assert cli_main(["hook", "--event", "pre_invocation", "--db", str(db_path)]) == 0
    assert json.loads(capsys.readouterr().out) == {}


def test_map_small_file_inline_stats_and_installer(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """6. Small-file auto-inline, stats CLI, and cross-platform plugin install/uninstall."""
    small_py = tmp_path / "helper.py"
    small_py.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    db_path = tmp_path / "cli.sqlite"

    assert cli_main(["map", str(small_py), "--db", str(db_path)]) == 0
    assert "1: def add(a: int, b: int) -> int:" in capsys.readouterr().out

    assert cli_main(["stats", "--db", str(db_path), "--roots", str(REAL_CACHE_FILE), "--brain-dir", str(tmp_path / "nb"), "--json"]) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["llm_tokens_used"] == 0
    assert stats["structural_benchmark"]["map_vs_full"]["savings_pct"] > 75.0

    plugin_dest = tmp_path / "plugins" / "antigravity-cache"
    res = installer.install_plugin(
        target_dir=plugin_dest,
        python_exe=sys.executable,
        db_path=db_path,
        dry_run=False,
    )
    assert res["status"] == "installed"
    assert (plugin_dest / "plugin.json").exists()
    hooks_cfg = json.loads((plugin_dest / "hooks.json").read_text(encoding="utf-8"))
    cmd_str = hooks_cfg["antigravity-cache"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "hook --event pre_tool" in cmd_str
    assert "--db" in cmd_str and str(db_path) in cmd_str
    skill_md = (plugin_dest / "skills" / "antigravity-cache" / "SKILL.md").read_text(encoding="utf-8")
    assert f"--db {db_path.as_posix()}" in skill_md

    proc = subprocess.run(
        [sys.executable, str(plugin_dest / "scripts" / "kv_pointer_cache.py"), "stats", "--db", str(db_path), "--roots", str(REAL_CACHE_FILE), "--brain-dir", str(tmp_path / "nb")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    assert "KVPointerCache & Cloud KV-Prefix Telemetry" in proc.stdout

    uninst = installer.uninstall_plugin(target_dir=plugin_dest, dry_run=False)
    assert uninst["status"] == "uninstalled"
    assert not plugin_dest.exists()
