#!/usr/bin/env python3
"""Cross-platform Antigravity 2.0 plugin installer for Aphygo/Antigravity-cache.

Zero external dependencies (Python 3.10+ stdlib only). Installs the plugin bundle
into `~/.gemini/config/plugins/antigravity-cache` and binds hook commands to the
exact `sys.executable` running this script so Windows/macOS/Linux PATH issues never occur.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
PLUGIN_NAME = "antigravity-cache"
DEFAULT_TARGET_DIR = Path.home() / ".gemini" / "config" / "plugins" / PLUGIN_NAME

BUNDLE_SUBPATHS: tuple[str, ...] = (
    "plugin.json",
    "assets/logo.svg",
    "scripts/kv_pointer_cache.py",
    "rules/AGENTS.md",
    "skills/antigravity-cache/SKILL.md",
)


def _quote_cmd_path(path: Path) -> str:
    raw = str(path)
    if " " in raw:
        return f'"{raw}"'
    return raw


def build_installed_hooks(
    python_exe: str, script_path: Path, db_path: Path | None = None
) -> dict[str, object]:
    """Generate an Antigravity `hooks.json` bound to an absolute Python executable and script."""
    py_quoted = _quote_cmd_path(Path(python_exe))
    sc_quoted = _quote_cmd_path(script_path)
    db_flag = f" --db {_quote_cmd_path(db_path)}" if db_path is not None else ""
    return {
        "antigravity-cache": {
            "enabled": True,
            "PreToolUse": [
                {
                    "matcher": "read_file|view_file",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"{py_quoted} {sc_quoted}{db_flag} hook --event pre_tool",
                            "timeout": 10,
                        }
                    ],
                }
            ],
            "PreInvocation": [
                {
                    "type": "command",
                    "command": f"{py_quoted} {sc_quoted}{db_flag} hook --event pre_invocation",
                    "timeout": 10,
                }
            ],
        }
    }


def _rewrite_doc_script_paths(
    text: str, python_exe: str, script_path: Path, db_path: Path | None = None
) -> str:
    py_cmd = Path(python_exe).as_posix() if os.name != "nt" else str(python_exe)
    sc_cmd = script_path.as_posix()
    db_flag = f" --db {db_path.as_posix()}" if db_path is not None else ""
    return text.replace(
        "python scripts/kv_pointer_cache.py",
        f"{py_cmd} {sc_cmd}{db_flag}",
    )


def run_preflight_checks(python_exe: str) -> list[str]:
    """Verify Python version, SQLite3 availability, and required repo files."""
    issues: list[str] = []
    if sys.version_info < (3, 10):
        issues.append(f"Python 3.10+ required, found {sys.version.split()[0]}")
    try:
        import sqlite3  # noqa: F401
    except Exception as exc:
        issues.append(f"sqlite3 stdlib module unavailable: {exc}")

    for rel in BUNDLE_SUBPATHS:
        if not (REPO_ROOT / rel).exists():
            issues.append(f"Missing bundle asset: {REPO_ROOT / rel}")

    if not Path(python_exe).exists():
        issues.append(f"Python executable not found: {python_exe}")
    return issues


def detect_existing_pointer_hooks(config_root: Path) -> list[Path]:
    """Detect whether the user already registered `kv_pointer_cache.py` in global hooks.json."""
    matches: list[Path] = []
    global_hooks = config_root / "hooks.json"
    if global_hooks.exists():
        try:
            if "kv_pointer_cache.py" in global_hooks.read_text(encoding="utf-8", errors="ignore"):
                matches.append(global_hooks)
        except OSError:
            pass
    return matches


def install_plugin(
    *,
    target_dir: Path,
    python_exe: str,
    db_path: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Install (or preview installing) the Antigravity Cache plugin bundle."""
    installed_script = target_dir / "scripts" / "kv_pointer_cache.py"
    hooks_payload = build_installed_hooks(python_exe, installed_script, db_path=db_path)
    hooks_text = json.dumps(hooks_payload, ensure_ascii=False, indent=2) + "\n"

    actions: list[str] = []
    for rel in BUNDLE_SUBPATHS:
        actions.append(f"copy {rel} -> {target_dir / rel}")
    actions.append(f"write {target_dir / 'hooks.json'}")

    if not dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)
        for rel in BUNDLE_SUBPATHS:
            src = REPO_ROOT / rel
            dst = target_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if rel in ("rules/AGENTS.md", "skills/antigravity-cache/SKILL.md"):
                raw = src.read_text(encoding="utf-8")
                dst.write_text(
                    _rewrite_doc_script_paths(raw, python_exe, installed_script, db_path=db_path),
                    encoding="utf-8",
                )
            else:
                shutil.copy2(src, dst)
        (target_dir / "hooks.json").write_text(hooks_text, encoding="utf-8")

    return {
        "status": "dry_run" if dry_run else "installed",
        "target_dir": str(target_dir),
        "python_executable": python_exe,
        "installed_script": str(installed_script),
        "db_path": str(db_path) if db_path is not None else None,
        "actions": actions,
    }


def uninstall_plugin(*, target_dir: Path, dry_run: bool = False) -> dict[str, object]:
    """Remove the installed plugin directory without deleting local SQLite stats caches."""
    existed = target_dir.exists()
    if existed and not dry_run:
        shutil.rmtree(target_dir)
    return {
        "status": "dry_run" if dry_run else ("uninstalled" if existed else "not_installed"),
        "target_dir": str(target_dir),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Install Aphygo/Antigravity-cache as a native Antigravity 2.0 plugin.",
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=DEFAULT_TARGET_DIR,
        help=f"Plugin install destination (default: {DEFAULT_TARGET_DIR})",
    )
    parser.add_argument(
        "--python",
        dest="python_exe",
        default=sys.executable,
        help=f"Python executable to bind into hooks.json (default: {sys.executable})",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional explicit SQLite DB path to bind into hooks and docs.",
    )
    parser.add_argument("--check", action="store_true", help="Run environment & conflict checks.")
    parser.add_argument("--dry-run", action="store_true", help="Preview installation without writing files.")
    parser.add_argument("--uninstall", action="store_true", help="Remove the installed plugin directory.")
    args = parser.parse_args(argv)

    issues = run_preflight_checks(args.python_exe)
    if issues and not args.uninstall:
        for item in issues:
            print(f"[ERROR] {item}", file=sys.stderr)
        return 1

    config_root = args.target_dir.parent.parent if args.target_dir.parent.name == "plugins" else Path.home() / ".gemini" / "config"
    existing_hooks = detect_existing_pointer_hooks(config_root)

    if args.uninstall:
        res = uninstall_plugin(target_dir=args.target_dir, dry_run=args.dry_run)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.check and not args.dry_run:
        print(
            json.dumps(
                {
                    "status": "ok",
                    "python": args.python_exe,
                    "repo_root": str(REPO_ROOT),
                    "target_dir": str(args.target_dir),
                    "existing_global_hooks": [str(p) for p in existing_hooks],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if existing_hooks and not args.dry_run:
        print(
            f"[WARNING] Found existing kv_pointer_cache hook in {existing_hooks[0]}; "
            "remove the duplicate entry if you do not want PreToolUse running twice.",
            file=sys.stderr,
        )

    res = install_plugin(
        target_dir=args.target_dir,
        python_exe=args.python_exe,
        db_path=args.db_path,
        dry_run=args.dry_run,
    )
    if existing_hooks:
        res["existing_global_hooks"] = [str(p) for p in existing_hooks]
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
