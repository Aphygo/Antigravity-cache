#!/usr/bin/env python3
"""Zero-LLM Structural Pointer Cache (`kv_pointer_cache.py`).

Gry's next-generation evolution of Lumen's RLM++ (`rlmlib`):
Eliminates the "cache-on-cache" paradox by preserving 100% of cloud KV-prefix-cache
(zero dynamic system-prompt rewrites, zero LLM scanner summary calls, and zero
double-fetch penalty during edits) while cutting raw file-read context growth by
75-95% via deterministic AST/structural line-range pointers (`#Lstart-Lend`),
SHA-256 node hashes, and static call-graph edges stored in SQLite.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

def _resolve_default_db_path() -> Path:
    """Resolve SQLite pointer store location across Windows/macOS/Linux and plugin runs."""
    env_db = os.environ.get("ANTIGRAVITY_CACHE_DB")
    if env_db:
        return Path(env_db)
    plugin_data = os.environ.get("PLUGIN_DATA")
    if plugin_data:
        return Path(plugin_data) / "kv_pointer_cache.sqlite"
    local_dir = Path(__file__).resolve().parent
    if (local_dir / "inre_efterklang_hook.py").exists():
        return local_dir / "cache" / "kv_pointer_cache.sqlite"
    return Path.home() / ".gemini" / "cache" / "kv_pointer_cache.sqlite"


DEFAULT_DB_PATH = _resolve_default_db_path()
DEFAULT_BRAIN_DIR = Path.home() / ".gemini" / "antigravity" / "brain"

_TRANSCRIPT_INPUT_TOK_RE = re.compile(r'"input_tokens"\s*:\s*(\d+)')
_TRANSCRIPT_CACHE_TOK_RE = re.compile(r'"cache_read_tokens"\s*:\s*(\d+)')

SUPPORTED_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".pyi", ".md", ".mdx", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go"}
)

AUTO_GUARD_CODE_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go"}
)
DEFAULT_GUARD_MAX_LINES = 250
DEFAULT_GUARD_CAP_LINES = 80
DEFAULT_GUARD_ALLOWLIST_TTL_SEC = 1800.0
DEFAULT_SMALL_INLINE_LINES = 250

_READ_BOUND_KEYS: tuple[str, ...] = (
    "StartLine",
    "EndLine",
    "ByteOffset",
    "startLine",
    "endLine",
    "byteOffset",
    "StartLineNumber",
    "EndLineNumber",
    "start_line",
    "end_line",
    "offset",
    "limit",
)
_READ_PATH_KEYS: tuple[str, ...] = ("Path", "AbsolutePath", "TargetFile", "path")

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git", "__pycache__", ".venv", ".venv-amd", "venv", "env",
        "node_modules", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        "target", "dist", "build", "cache",
    }
)

# Trivial Python builtins/exceptions excluded from call-graph edges to keep maps high-signal
_PY_TRIVIAL_BUILTINS: frozenset[str] = frozenset(
    {
        "abs", "all", "any", "bin", "bool", "bytearray", "bytes", "callable",
        "chr", "classmethod", "complex", "delattr", "dict", "dir", "divmod",
        "enumerate", "filter", "float", "format", "frozenset", "getattr",
        "globals", "hasattr", "hash", "hex", "id", "int", "isinstance",
        "issubclass", "iter", "len", "list", "locals", "map", "max",
        "memoryview", "min", "next", "object", "oct", "ord", "pow", "print",
        "property", "range", "repr", "reversed", "round", "set", "setattr",
        "slice", "sorted", "staticmethod", "str", "sum", "super", "tuple",
        "type", "vars", "zip", "Exception", "BaseException", "ValueError",
        "TypeError", "KeyError", "IndexError", "AttributeError", "RuntimeError",
        "OSError", "IOError", "FileNotFoundError", "StopIteration",
        "NotImplementedError", "AssertionError",
    }
)

# Common string/list formatting methods on local variables that add noise without a named service receiver
_CHAINED_NOISE_METHODS: frozenset[str] = frozenset(
    {
        "append", "clear", "copy", "count", "decode", "encode", "endswith",
        "extend", "find", "format", "index", "insert", "items", "join",
        "keys", "lower", "lstrip", "replace", "rfind", "rstrip", "setdefault",
        "sort", "split", "splitlines", "startswith", "strip", "title", "upper",
        "values",
    }
)

_NON_PY_KEYWORDS: frozenset[str] = frozenset(
    {
        "if", "else", "for", "while", "loop", "match", "switch", "case",
        "return", "throw", "catch", "try", "typeof", "instanceof", "new",
        "delete", "await", "async", "function", "fn", "pub", "impl", "struct",
        "enum", "trait", "where", "Some", "None", "Ok", "Err", "vec",
        "println", "eprintln", "format",
    }
)


def normalize_path(path: str | Path) -> str:
    """Fast user-space canonical forward-slash path (avoids slow Win32 handle syscalls)."""
    raw = os.path.normpath(os.path.abspath(os.fspath(path))).replace("\\", "/")
    if len(raw) >= 2 and raw[1] == ":":
        return raw[0].upper() + raw[1:]
    return raw


def estimate_tokens(text: str) -> int:
    """Deterministic zero-LLM token estimate (~4 chars/token)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def compute_sha256(text: str, *, hex_chars: int = 16) -> str:
    """Compute SHA-256 hex digest over LF-normalized source text."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return digest[:hex_chars] if hex_chars < 64 else digest


@dataclass(slots=True)
class SymbolPointer:
    """Deterministic structural pointer for a code or document symbol."""

    qualified_name: str
    kind: str  # 'class' | 'function' | 'method' | 'section'
    start_line: int  # 1-based inclusive (including decorators/attributes)
    end_line: int  # 1-based inclusive
    signature: str
    doc_headline: str
    calls: list[str]
    content_sha256: str
    estimated_tokens: int

    @property
    def line_count(self) -> int:
        return max(1, self.end_line - self.start_line + 1)

    def pointer_uri(self, normalized_file_path: str) -> str:
        return f"file:///{normalized_file_path}#L{self.start_line}-L{self.end_line}"

    def to_dict(self, normalized_file_path: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "qualified_name": self.qualified_name,
            "kind": self.kind,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "signature": self.signature,
            "doc_headline": self.doc_headline,
            "calls": list(self.calls),
            "content_sha256": self.content_sha256,
            "estimated_tokens": self.estimated_tokens,
        }
        if normalized_file_path is not None:
            out["path"] = normalized_file_path
            out["pointer"] = self.pointer_uri(normalized_file_path)
        return out


# ---------------------------------------------------------------------------
# 1. Zero-LLM Multi-Language Structural Decomposer
# ---------------------------------------------------------------------------


def pre_tool_fast_bypass(payload: dict[str, Any]) -> tuple[bool, str, str]:
    """Sub-0.1ms pure-Python pre-filter before opening SQLite in PreToolUse hooks."""
    tool_call = payload.get("toolCall")
    if not isinstance(tool_call, dict):
        return True, "", ""
    name = str(tool_call.get("name") or "").strip().lower()
    if name not in ("read_file", "view_file"):
        return True, "", ""

    args = tool_call.get("args")
    if not isinstance(args, dict):
        return True, "", ""

    for key in _READ_BOUND_KEYS:
        if args.get(key) is not None:
            return True, "", ""

    raw_path: str | None = None
    for pkey in _READ_PATH_KEYS:
        cand = args.get(pkey)
        if isinstance(cand, str) and cand.strip():
            raw_path = cand.strip()
            break
    if not raw_path:
        return True, "", ""

    norm_path = normalize_path(raw_path)
    ext = os.path.splitext(norm_path)[1].lower()
    if ext not in AUTO_GUARD_CODE_EXTENSIONS:
        return True, "", ""

    try:
        st = os.stat(norm_path)
    except OSError:
        return True, "", ""
    if st.st_size < 4096:
        return True, "", ""

    conv_id = str(payload.get("conversationId") or "default_session")
    return False, conv_id, norm_path


def _compact_ws(text: str, max_len: int = 140) -> str:
    clean = " ".join(text.split())
    if len(clean) <= max_len:
        return clean
    return clean[: max_len - 3] + "..."


def _first_doc_line(docstring: str | None, max_len: int = 100) -> str:
    if not docstring:
        return ""
    for line in docstring.splitlines():
        stripped = line.strip()
        if stripped:
            return _compact_ws(stripped, max_len=max_len)
    return ""


def _unparse_short(node: ast.AST, max_len: int = 36) -> str:
    try:
        raw = " ".join(ast.unparse(node).split())
    except Exception:
        return "..."
    if len(raw) <= max_len:
        return raw
    return raw[: max_len - 3] + "..."


def _format_py_arg(arg: ast.arg, default: ast.AST | None = None) -> str:
    part = arg.arg
    if arg.annotation is not None:
        part += f": {_unparse_short(arg.annotation, max_len=44)}"
    if default is not None:
        part += f"={_unparse_short(default, max_len=28)}"
    return part


def _format_py_func_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = node.args
    parts: list[str] = []

    pos_args = list(args.posonlyargs) + list(args.args)
    num_posonly = len(args.posonlyargs)
    defaults_offset = len(pos_args) - len(args.defaults)

    for idx, arg in enumerate(pos_args):
        default_idx = idx - defaults_offset
        default_node = args.defaults[default_idx] if 0 <= default_idx < len(args.defaults) else None
        parts.append(_format_py_arg(arg, default_node))
        if num_posonly > 0 and idx == num_posonly - 1:
            parts.append("/")

    if args.vararg is not None:
        var_part = f"*{args.vararg.arg}"
        if args.vararg.annotation is not None:
            var_part += f": {_unparse_short(args.vararg.annotation, max_len=40)}"
        parts.append(var_part)
    elif args.kwonlyargs:
        parts.append("*")

    for kw_arg, kw_default in zip(args.kwonlyargs, args.kw_defaults):
        parts.append(_format_py_arg(kw_arg, kw_default))

    if args.kwarg is not None:
        kw_part = f"**{args.kwarg.arg}"
        if args.kwarg.annotation is not None:
            kw_part += f": {_unparse_short(args.kwarg.annotation, max_len=40)}"
        parts.append(kw_part)

    ret = ""
    if node.returns is not None:
        ret = f" -> {_unparse_short(node.returns, max_len=48)}"

    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return f"{prefix} {node.name}({', '.join(parts)}){ret}"


def _format_py_class_signature(node: ast.ClassDef) -> str:
    bases = [_unparse_short(b, max_len=40) for b in node.bases]
    for kw in node.keywords:
        if kw.arg:
            bases.append(f"{kw.arg}={_unparse_short(kw.value, max_len=28)}")
        else:
            bases.append(f"**{_unparse_short(kw.value, max_len=28)}")
    inherit = f"({', '.join(bases)})" if bases else ""
    return f"class {node.name}{inherit}"


def _node_start_line_with_decorators(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
    lines: list[str],
) -> int:
    start = node.lineno
    for dec in getattr(node, "decorator_list", ()):
        dec_line = getattr(dec, "lineno", None)
        if dec_line is not None and dec_line < start:
            start = dec_line
    # Ensure a standalone '@' line above a multiline decorator expression is included
    while start > 1 and lines[start - 2].strip() == "@":
        start -= 1
    return max(1, start)


def _decorator_kind_hint(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[bool, str | None]:
    """Detect @overload and @prop.setter / @prop.deleter decorators."""
    is_overload = False
    prop_accessor: str | None = None
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name) and dec.id == "overload":
            is_overload = True
        elif isinstance(dec, ast.Attribute):
            if dec.attr == "overload":
                is_overload = True
            elif dec.attr in ("setter", "deleter"):
                prop_accessor = dec.attr
    return is_overload, prop_accessor


def _extract_py_calls(
    target_node: ast.AST,
    intra_file_short_names: set[str],
    *,
    exclude_nested_defs: bool = False,
) -> list[str]:
    """Extract deterministic sorted callee names from ast.Call nodes."""
    callees: set[str] = set()

    def _visit(cur: ast.AST) -> None:
        for child in ast.iter_child_nodes(cur):
            if exclude_nested_defs and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                # Still inspect decorators of child methods at class definition time if needed, or skip
                continue
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Name):
                    name = func.id
                    if name not in _PY_TRIVIAL_BUILTINS:
                        callees.add(name)
                elif isinstance(func, ast.Attribute):
                    attr = func.attr
                    val = func.value
                    if isinstance(val, ast.Name):
                        if (
                            val.id in ("self", "cls")
                            or attr in intra_file_short_names
                            or attr not in _CHAINED_NOISE_METHODS
                        ):
                            callees.add(f"{val.id}.{attr}")
                    elif isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
                        callees.add(f"{val.value.id}.{val.attr}.{attr}")
                    elif attr in intra_file_short_names or attr not in _CHAINED_NOISE_METHODS:
                        if attr not in _PY_TRIVIAL_BUILTINS:
                            callees.add(attr)
            _visit(child)

    _visit(target_node)
    return sorted(callees)


def _decompose_python(source: str, file_path: str) -> list[SymbolPointer]:
    lines = source.splitlines()
    if not lines:
        return []

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return _decompose_regex_code(source, ext=".py")

    # Pass 1: collect all intra-file defined symbol short names
    intra_names: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            intra_names.add(n.name)

    raw_entries: list[tuple[SymbolPointer, bool]] = []  # (symbol, is_overload)

    def _collect_block(stmts: list[ast.stmt], parent_qname: str | None) -> None:
        for stmt in stmts:
            if isinstance(stmt, ast.ClassDef):
                qname = f"{parent_qname}.{stmt.name}" if parent_qname else stmt.name
                start = _node_start_line_with_decorators(stmt, lines)
                end = min(len(lines), getattr(stmt, "end_lineno", None) or stmt.lineno)
                node_text = "\n".join(lines[start - 1 : end])
                sym = SymbolPointer(
                    qualified_name=qname,
                    kind="class",
                    start_line=start,
                    end_line=end,
                    signature=_format_py_class_signature(stmt),
                    doc_headline=_first_doc_line(ast.get_docstring(stmt)),
                    calls=_extract_py_calls(stmt, intra_names, exclude_nested_defs=True),
                    content_sha256=compute_sha256(node_text),
                    estimated_tokens=estimate_tokens(node_text),
                )
                raw_entries.append((sym, False))
                _collect_block(stmt.body, qname)

            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_overload, accessor = _decorator_kind_hint(stmt)
                base_name = f"{stmt.name}.{accessor}" if accessor else stmt.name
                qname = f"{parent_qname}.{base_name}" if parent_qname else base_name
                kind = "method" if parent_qname else "function"
                start = _node_start_line_with_decorators(stmt, lines)
                end = min(len(lines), getattr(stmt, "end_lineno", None) or stmt.lineno)
                node_text = "\n".join(lines[start - 1 : end])
                sym = SymbolPointer(
                    qualified_name=qname,
                    kind=kind,
                    start_line=start,
                    end_line=end,
                    signature=_format_py_func_signature(stmt),
                    doc_headline=_first_doc_line(ast.get_docstring(stmt)),
                    calls=_extract_py_calls(stmt, intra_names, exclude_nested_defs=False),
                    content_sha256=compute_sha256(node_text),
                    estimated_tokens=estimate_tokens(node_text),
                )
                raw_entries.append((sym, is_overload))

            elif parent_qname is None and isinstance(stmt, (ast.If, ast.Try, ast.With, ast.AsyncWith)):
                # Capture conditional top-level definitions (e.g., platform guards)
                for sub_attr in ("body", "orelse", "finalbody"):
                    sub_stmts = getattr(stmt, sub_attr, None)
                    if isinstance(sub_stmts, list):
                        _collect_block(sub_stmts, None)
                if isinstance(stmt, ast.Try):
                    for handler in stmt.handlers:
                        _collect_block(handler.body, None)

    _collect_block(tree.body, None)

    # Disambiguate @overload stubs vs real implementation and any duplicate names
    non_overload_qnames = {
        sym.qualified_name for sym, is_ov in raw_entries if not is_ov
    }
    used_qnames: dict[str, int] = {}
    overload_counts: dict[str, int] = {}
    final_symbols: list[SymbolPointer] = []

    for sym, is_ov in raw_entries:
        qname = sym.qualified_name
        if is_ov and qname in non_overload_qnames:
            idx = overload_counts.get(qname, 0) + 1
            overload_counts[qname] = idx
            qname = f"{qname}@overload{idx}"

        if qname in used_qnames:
            used_qnames[qname] += 1
            qname = f"{qname}#{used_qnames[qname]}"
        else:
            used_qnames[qname] = 1

        sym.qualified_name = qname
        final_symbols.append(sym)

    final_symbols.sort(key=lambda s: (s.start_line, -s.end_line, s.qualified_name))
    return final_symbols


_MD_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_MD_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")


def _decompose_markdown(source: str) -> list[SymbolPointer]:
    """Heading-based section range decomposer for Markdown (fence-aware)."""
    lines = source.splitlines()
    if not lines:
        return []

    headings: list[tuple[int, int, str]] = []  # (0-based line idx, level, title)
    active_fence: str | None = None

    for idx, line in enumerate(lines):
        fence_match = _MD_FENCE_RE.match(line)
        if fence_match:
            marker = fence_match.group(1)
            if active_fence is None:
                active_fence = marker[0] * len(marker)
            elif line.lstrip().startswith(active_fence[0] * len(active_fence)):
                active_fence = None
            continue

        if active_fence is not None:
            continue

        m = _MD_HEADING_RE.match(line)
        if m:
            level = len(m.group(1))
            title = m.group(2).rstrip("#").strip()
            if title:
                headings.append((idx, level, title))

    if not headings:
        node_text = "\n".join(lines)
        first_line = _first_doc_line(node_text, max_len=90) or "Document"
        return [
            SymbolPointer(
                qualified_name="Document",
                kind="section",
                start_line=1,
                end_line=len(lines),
                signature="# Document",
                doc_headline=first_line,
                calls=[],
                content_sha256=compute_sha256(node_text),
                estimated_tokens=estimate_tokens(node_text),
            )
        ]

    symbols: list[SymbolPointer] = []
    used_qnames: dict[str, int] = {}

    for h_idx, (start_0, level, title) in enumerate(headings):
        if h_idx + 1 < len(headings):
            end_0 = headings[h_idx + 1][0] - 1
            while end_0 > start_0 and not lines[end_0].strip():
                end_0 -= 1
        else:
            end_0 = len(lines) - 1
            while end_0 > start_0 and not lines[end_0].strip():
                end_0 -= 1

        qname = title
        if qname in used_qnames:
            used_qnames[qname] += 1
            qname = f"{title}#{used_qnames[title]}"
        else:
            used_qnames[qname] = 1

        body_headline = ""
        for body_line in lines[start_0 + 1 : end_0 + 1]:
            s = body_line.strip()
            if s and not s.startswith(("```", "~~~", "---")):
                body_headline = _compact_ws(s, max_len=95)
                break

        section_text = "\n".join(lines[start_0 : end_0 + 1])
        symbols.append(
            SymbolPointer(
                qualified_name=qname,
                kind="section",
                start_line=start_0 + 1,
                end_line=end_0 + 1,
                signature=f"{'#' * level} {title}",
                doc_headline=body_headline,
                calls=[],
                content_sha256=compute_sha256(section_text),
                estimated_tokens=estimate_tokens(section_text),
            )
        )

    return symbols


_RUST_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)"), "function"),
    (re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_]\w*)"), "class"),
    (re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z_]\w*)"), "class"),
    (re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_]\w*)"), "class"),
    (re.compile(r"^impl(?:<[^>]*>)?\s+(?:[A-Za-z_][\w:<>]*\s+for\s+)?([A-Za-z_]\w*)"), "class"),
]

_JSTS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)"), "class"),
    (re.compile(r"^(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)"), "class"),
    (re.compile(r"^(?:export\s+)?type\s+([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*="), "class"),
    (re.compile(r"^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*[<(]"), "function"),
    (
        re.compile(
            r"^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:<[^>]*>\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?\s*=>"
        ),
        "function",
    ),
    (
        re.compile(
            r"^(?:(?:public|private|protected|static|async|override|abstract)\s+)*(?:(?:get|set)\s+)?([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\([^;]*\)\s*(?::\s*[^{=;]+)?\{"
        ),
        "method",
    ),
]

_PY_FALLBACK_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^class\s+([A-Za-z_]\w*)"), "class"),
    (re.compile(r"^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\("), "function"),
]

_CALL_TOKEN_RE = re.compile(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\(")


def _find_brace_block_end(lines: list[str], start_idx: int, max_idx: int) -> int:
    """Find matching closing brace line index for C/Rust/JS/TS blocks."""
    depth = 0
    saw_open = False
    for idx in range(start_idx, max_idx + 1):
        line = lines[idx]
        # Strip simple line comments before counting braces
        code_part = line.split("//", 1)[0]
        for ch in code_part:
            if ch == "{":
                depth += 1
                saw_open = True
            elif ch == "}":
                depth -= 1
                if saw_open and depth <= 0:
                    return idx
        if not saw_open and code_part.rstrip().endswith(";"):
            return idx
    return max_idx


def _extract_leading_doc_and_attrs(lines: list[str], def_idx: int) -> tuple[int, str]:
    """Include leading Rust/TS attributes/decorators in start_line and extract /// or /** doc headline."""
    start_idx = def_idx
    idx = def_idx - 1
    doc_lines: list[str] = []

    while idx >= 0:
        s = lines[idx].strip()
        if s.startswith(("#[", "@")):
            start_idx = idx
            idx -= 1
        elif s.startswith(("///", "//!")):
            doc_lines.insert(0, s.lstrip("/! ").strip())
            idx -= 1
        elif s.endswith("*/"):
            # Walk backward to /** or /*
            while idx >= 0:
                cs = lines[idx].strip()
                cleaned = cs.lstrip("/* ").rstrip("*/ ").strip()
                if cleaned:
                    doc_lines.insert(0, cleaned)
                if cs.startswith("/*"):
                    idx -= 1
                    break
                idx -= 1
        else:
            break

    headline = _compact_ws(doc_lines[0], max_len=95) if doc_lines else ""
    return start_idx, headline


def _decompose_regex_code(source: str, *, ext: str) -> list[SymbolPointer]:
    """Clean structural + brace-aware symbol extraction for JS/TS/Rust/Go and Python fallback."""
    lines = source.splitlines()
    if not lines:
        return []

    if ext == ".rs":
        patterns = _RUST_PATTERNS
        brace_scoped = True
    elif ext in (".js", ".jsx", ".ts", ".tsx"):
        patterns = _JSTS_PATTERNS
        brace_scoped = True
    elif ext in (".py", ".pyi"):
        patterns = _PY_FALLBACK_PATTERNS
        brace_scoped = False
    else:
        patterns = _JSTS_PATTERNS + _RUST_PATTERNS + _PY_FALLBACK_PATTERNS
        brace_scoped = True

    raw_defs: list[tuple[int, int, str, str, str]] = []  # (indent, line_idx, name, kind, sig)
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "/*", "*")):
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        for pat, kind in patterns:
            m = pat.match(stripped)
            if m:
                sym_name = m.group(1)
                if kind == "method" and (sym_name in _NON_PY_KEYWORDS or indent == 0):
                    continue
                sig = stripped.rstrip("{").strip()
                raw_defs.append((indent, idx, sym_name, kind, _compact_ws(sig, max_len=130)))
                break

    symbols: list[SymbolPointer] = []
    used_qnames: dict[str, int] = {}
    active_class: tuple[str, int] | None = None  # (class_name, class_end_0)

    for d_i, (indent, def_idx, name, kind, sig) in enumerate(raw_defs):
        if active_class is not None and def_idx > active_class[1]:
            active_class = None

        start_0, doc_headline = _extract_leading_doc_and_attrs(lines, def_idx)
        next_top_0 = len(lines) - 1
        for later_indent, later_idx, _, _, _ in raw_defs[d_i + 1 :]:
            if later_indent <= indent:
                next_top_0 = later_idx - 1
                break

        if brace_scoped:
            end_0 = _find_brace_block_end(lines, def_idx, len(lines) - 1)
        else:
            end_0 = next_top_0
            while end_0 > def_idx and not lines[end_0].strip():
                end_0 -= 1

        actual_kind = kind
        qname = name
        if kind == "class" and indent == 0:
            active_class = (name, end_0)
        elif indent > 0 and active_class is not None and def_idx <= active_class[1]:
            actual_kind = "method"
            qname = f"{active_class[0]}.{name}"

        if qname in used_qnames:
            used_qnames[qname] += 1
            qname = f"{qname}#{used_qnames[qname]}"
        else:
            used_qnames[qname] = 1

        node_text = "\n".join(lines[start_0 : end_0 + 1])
        callees: set[str] = set()
        for body_line in lines[def_idx + 1 : end_0 + 1]:
            code_part = body_line.split("//", 1)[0]
            for cm in _CALL_TOKEN_RE.finditer(code_part):
                tok = cm.group(1)
                short = tok.split(".")[-1]
                if short not in _NON_PY_KEYWORDS and tok != name:
                    callees.add(tok)

        symbols.append(
            SymbolPointer(
                qualified_name=qname,
                kind=actual_kind,
                start_line=start_0 + 1,
                end_line=end_0 + 1,
                signature=sig,
                doc_headline=doc_headline,
                calls=sorted(callees),
                content_sha256=compute_sha256(node_text),
                estimated_tokens=estimate_tokens(node_text),
            )
        )

    symbols.sort(key=lambda s: (s.start_line, -s.end_line, s.qualified_name))
    return symbols


def decompose_file(path: str | Path, content: str | None = None) -> list[SymbolPointer]:
    """Decompose a source or Markdown file into zero-LLM deterministic SymbolPointers."""
    file_path = Path(path)
    if content is None:
        content = file_path.read_text(encoding="utf-8", errors="replace")

    ext = file_path.suffix.lower()
    if ext in (".py", ".pyi"):
        return _decompose_python(content, str(file_path))
    if ext in (".md", ".mdx"):
        return _decompose_markdown(content)
    return _decompose_regex_code(content, ext=ext)


# ---------------------------------------------------------------------------
# 2. Incremental SQLite Pointer Store (`KVPointerCache`)
# ---------------------------------------------------------------------------


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY,
    mtime_ns INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    file_sha256 TEXT NOT NULL,
    raw_tokens INTEGER NOT NULL,
    indexed_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS symbols (
    path TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    signature TEXT NOT NULL,
    doc_headline TEXT NOT NULL,
    calls_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    estimated_tokens INTEGER NOT NULL,
    PRIMARY KEY (path, qualified_name),
    FOREIGN KEY (path) REFERENCES files(path) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_symbols_path_line ON symbols(path, start_line);
CREATE INDEX IF NOT EXISTS idx_symbols_qname ON symbols(qualified_name);

CREATE TABLE IF NOT EXISTS telemetry_counters (
    op TEXT PRIMARY KEY,
    calls INTEGER NOT NULL DEFAULT 0,
    cache_hits INTEGER NOT NULL DEFAULT 0,
    raw_tokens_total INTEGER NOT NULL DEFAULT 0,
    emitted_tokens_total INTEGER NOT NULL DEFAULT 0,
    saved_tokens_total INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_auto_maps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conv_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    capped_end_line INTEGER NOT NULL,
    total_lines INTEGER NOT NULL,
    saved_tokens INTEGER NOT NULL,
    map_text TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_maps_conv ON pending_auto_maps(conv_id, id);

CREATE TABLE IF NOT EXISTS guard_allowlist (
    conv_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    capped_at REAL NOT NULL,
    PRIMARY KEY (conv_id, file_path)
);
"""


class KVPointerCache:
    """Incremental SQLite-backed structural pointer store with <0.5ms warm skip."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            os.fspath(self.db_path),
            timeout=5.0,
            check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()

    def __enter__(self) -> KVPointerCache:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _record_op_telemetry(
        self,
        op: str,
        *,
        raw_tokens: int,
        emitted_tokens: int,
        cache_hit: bool,
    ) -> None:
        """Persist cumulative token savings for `map` / `slice` calls without touching `index_file`."""
        saved_tokens = max(0, int(raw_tokens) - int(emitted_tokens))
        self._conn.execute(
            """
            INSERT INTO telemetry_counters (
                op, calls, cache_hits, raw_tokens_total, emitted_tokens_total, saved_tokens_total, updated_at
            )
            VALUES (?, 1, ?, ?, ?, ?, ?)
            ON CONFLICT(op) DO UPDATE SET
                calls = calls + 1,
                cache_hits = cache_hits + excluded.cache_hits,
                raw_tokens_total = raw_tokens_total + excluded.raw_tokens_total,
                emitted_tokens_total = emitted_tokens_total + excluded.emitted_tokens_total,
                saved_tokens_total = saved_tokens_total + excluded.saved_tokens_total,
                updated_at = excluded.updated_at
            """,
            (
                op,
                1 if cache_hit else 0,
                max(0, int(raw_tokens)),
                max(0, int(emitted_tokens)),
                saved_tokens,
                time.time(),
            ),
        )
        self._conn.commit()

    def _fetch_cached_symbols(self, norm_path: str) -> list[SymbolPointer]:
        rows = self._conn.execute(
            """
            SELECT qualified_name, kind, start_line, end_line, signature,
                   doc_headline, calls_json, content_sha256, estimated_tokens
            FROM symbols
            WHERE path = ?
            ORDER BY start_line ASC, end_line DESC, qualified_name ASC
            """,
            (norm_path,),
        ).fetchall()
        return [
            SymbolPointer(
                qualified_name=r[0],
                kind=r[1],
                start_line=int(r[2]),
                end_line=int(r[3]),
                signature=r[4],
                doc_headline=r[5],
                calls=json.loads(r[6]),
                content_sha256=r[7],
                estimated_tokens=int(r[8]),
            )
            for r in rows
        ]

    def index_file(self, path: str | Path) -> dict[str, Any]:
        """Index a single file with <0.5ms warm mtime+size skip and symbol-level SHA-256 diff."""
        t0 = time.perf_counter()
        norm_path = normalize_path(path)
        st = os.stat(norm_path)
        mtime_ns = st.st_mtime_ns
        size_bytes = st.st_size

        file_row = self._conn.execute(
            "SELECT mtime_ns, size_bytes, file_sha256, raw_tokens FROM files WHERE path = ?",
            (norm_path,),
        ).fetchone()

        # Fast warm skip (<0.5ms): mtime_ns and size_bytes match SQLite
        if file_row is not None and int(file_row[0]) == mtime_ns and int(file_row[1]) == size_bytes:
            symbols = self._fetch_cached_symbols(norm_path)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return {
                "path": norm_path,
                "cache_hit": True,
                "mtime_ns": mtime_ns,
                "size_bytes": size_bytes,
                "file_sha256": file_row[2],
                "raw_tokens": int(file_row[3]),
                "symbol_count": len(symbols),
                "symbols": symbols,
                "diff": {
                    "added": [],
                    "modified": [],
                    "unchanged": [s.qualified_name for s in symbols],
                    "removed": [],
                },
                "elapsed_ms": round(elapsed_ms, 3),
            }

        # Read file content and compute file hash
        with open(norm_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        file_sha256 = compute_sha256(content, hex_chars=64)
        raw_tokens = estimate_tokens(content)

        # Load prior symbol hashes if this file was previously indexed
        old_rows = self._conn.execute(
            "SELECT qualified_name, content_sha256 FROM symbols WHERE path = ?",
            (norm_path,),
        ).fetchall()
        old_hashes: dict[str, str] = {r[0]: r[1] for r in old_rows}
        was_previously_indexed = file_row is not None

        symbols = decompose_file(norm_path, content=content)
        new_map = {s.qualified_name: s for s in symbols}

        added: list[str] = []
        modified: list[str] = []
        unchanged: list[str] = []
        removed: list[str] = []

        if not was_previously_indexed:
            added = sorted(new_map.keys())
        else:
            for qname, sym in new_map.items():
                old_hash = old_hashes.get(qname)
                if old_hash is None:
                    added.append(qname)
                elif old_hash != sym.content_sha256:
                    modified.append(qname)
                else:
                    unchanged.append(qname)
            for old_qname in old_hashes:
                if old_qname not in new_map:
                    removed.append(old_qname)
            added.sort()
            modified.sort()
            unchanged.sort()
            removed.sort()

        now = time.time()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO files (path, mtime_ns, size_bytes, file_sha256, raw_tokens, indexed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    mtime_ns = excluded.mtime_ns,
                    size_bytes = excluded.size_bytes,
                    file_sha256 = excluded.file_sha256,
                    raw_tokens = excluded.raw_tokens,
                    indexed_at = excluded.indexed_at
                """,
                (norm_path, mtime_ns, size_bytes, file_sha256, raw_tokens, now),
            )
            self._conn.execute("DELETE FROM symbols WHERE path = ?", (norm_path,))
            if symbols:
                self._conn.executemany(
                    """
                    INSERT INTO symbols (
                        path, qualified_name, kind, start_line, end_line,
                        signature, doc_headline, calls_json, content_sha256, estimated_tokens
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            norm_path,
                            s.qualified_name,
                            s.kind,
                            s.start_line,
                            s.end_line,
                            s.signature,
                            s.doc_headline,
                            json.dumps(s.calls, ensure_ascii=False),
                            s.content_sha256,
                            s.estimated_tokens,
                        )
                        for s in symbols
                    ],
                )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "path": norm_path,
            "cache_hit": False,
            "mtime_ns": mtime_ns,
            "size_bytes": size_bytes,
            "file_sha256": file_sha256,
            "raw_tokens": raw_tokens,
            "symbol_count": len(symbols),
            "symbols": symbols,
            "diff": {
                "added": added,
                "modified": modified,
                "unchanged": unchanged,
                "removed": removed,
            },
            "elapsed_ms": round(elapsed_ms, 3),
        }

    def index_directory(
        self,
        root: str | Path,
        *,
        extensions: set[str] | frozenset[str] = SUPPORTED_EXTENSIONS,
        exclude_dirs: set[str] | frozenset[str] = DEFAULT_EXCLUDE_DIRS,
    ) -> dict[str, Any]:
        """Incrementally index all supported source/doc files under `root`."""
        t0 = time.perf_counter()
        norm_root = normalize_path(root)
        seen_paths: set[str] = set()
        cache_hits = 0
        cache_misses = 0
        total_symbols = 0

        for dirpath, dirnames, filenames in os.walk(norm_root):
            dirnames[:] = sorted(
                d for d in dirnames if d not in exclude_dirs and not d.startswith(".")
            )
            for fname in sorted(filenames):
                ext = os.path.splitext(fname)[1].lower()
                if ext not in extensions:
                    continue
                fpath = normalize_path(os.path.join(dirpath, fname))
                seen_paths.add(fpath)
                res = self.index_file(fpath)
                if res["cache_hit"]:
                    cache_hits += 1
                else:
                    cache_misses += 1
                total_symbols += int(res["symbol_count"])

        # Prune deleted files under norm_root
        prefix = norm_root.rstrip("/") + "/"
        cached_under_root = self._conn.execute(
            "SELECT path FROM files WHERE path = ? OR (path >= ? AND path < ?)",
            (norm_root, prefix, prefix[:-1] + "\uffff"),
        ).fetchall()
        removed_files = sorted(r[0] for r in cached_under_root if r[0] not in seen_paths)
        if removed_files:
            with self._conn:
                self._conn.executemany(
                    "DELETE FROM files WHERE path = ?",
                    [(p,) for p in removed_files],
                )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "root": norm_root,
            "files_indexed": len(seen_paths),
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "total_symbols": total_symbols,
            "removed_files": removed_files,
            "elapsed_ms": round(elapsed_ms, 3),
        }

    # -----------------------------------------------------------------------
    # 3. KV-Cache-Safe Append-Only Query & Slice API
    # -----------------------------------------------------------------------

    def render_file_map(
        self, path: str | Path, *, record_telemetry: bool = True
    ) -> dict[str, Any]:
        """Render a deterministic, compact structural map with [Lstart-Lend] pointers."""
        idx = self.index_file(path)
        norm_path = idx["path"]
        raw_tokens = int(idx["raw_tokens"])
        symbols: list[SymbolPointer] = idx["symbols"]

        intra_short_names = {s.qualified_name.split(".")[-1] for s in symbols}
        fname = os.path.basename(norm_path)
        out_lines: list[str] = [f"# {fname} (~{raw_tokens}t) — {norm_path}"]

        if not symbols:
            out_lines.append("  (no structural symbols)")
        else:
            for sym in symbols:
                indent = "  " if "." in sym.qualified_name and sym.kind == "method" else ""
                sig = _compact_ws(sym.signature, max_len=115)
                doc_part = f" — {_compact_ws(sym.doc_headline, max_len=72)}" if sym.doc_headline else ""

                # Prioritize intra-file callees first, then external callees (capped for compactness)
                calls_part = ""
                if sym.calls:
                    intra_calls = [
                        c for c in sym.calls if c.split(".")[-1] in intra_short_names
                    ]
                    ext_calls = [
                        c for c in sym.calls if c.split(".")[-1] not in intra_short_names
                    ]
                    ordered_calls = intra_calls + ext_calls
                    shown = ordered_calls[:5]
                    extra = f" (+{len(ordered_calls) - 5})" if len(ordered_calls) > 5 else ""
                    calls_part = f" -> {', '.join(shown)}{extra}"

                out_lines.append(
                    f"{indent}[L{sym.start_line}-L{sym.end_line}] (~{sym.estimated_tokens}t) "
                    f"{sig}{doc_part}{calls_part}"
                )

        map_text = "\n".join(out_lines)
        map_tokens = estimate_tokens(map_text)
        savings_pct = (
            round(max(0.0, (1.0 - map_tokens / raw_tokens) * 100.0), 2)
            if raw_tokens > 0
            else 0.0
        )
        if record_telemetry:
            self._record_op_telemetry(
                "map",
                raw_tokens=raw_tokens,
                emitted_tokens=map_tokens,
                cache_hit=bool(idx["cache_hit"]),
            )

        return {
            "path": norm_path,
            "cache_hit": idx["cache_hit"],
            "symbol_count": len(symbols),
            "raw_tokens": raw_tokens,
            "map_tokens": map_tokens,
            "tokens_saved": max(0, raw_tokens - map_tokens),
            "savings_pct": savings_pct,
            "token_savings_pct": savings_pct,
            "llm_tokens_used": 0,
            "map_text": map_text,
            "symbols": [s.to_dict(norm_path) for s in symbols],
        }

    def locate_symbol(
        self,
        query: str,
        root: str | Path | None = None,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        """Search indexed symbols by name, signature, docstring, or callees."""
        q = query.strip()
        if not q:
            return []

        norm_root: str | None = None
        if root is not None:
            r_path = Path(root)
            if r_path.is_file():
                self.index_file(r_path)
                norm_root = normalize_path(r_path)
            elif r_path.is_dir():
                self.index_directory(r_path)
                norm_root = normalize_path(r_path)

        ql = q.lower()
        q_tokens = [t for t in re.split(r"[\s./:#]+", ql) if t]

        if norm_root is not None:
            if os.path.isfile(norm_root):
                rows = self._conn.execute(
                    """
                    SELECT path, qualified_name, kind, start_line, end_line,
                           signature, doc_headline, calls_json, content_sha256, estimated_tokens
                    FROM symbols
                    WHERE path = ?
                    """,
                    (norm_root,),
                ).fetchall()
            else:
                prefix = norm_root.rstrip("/") + "/"
                rows = self._conn.execute(
                    """
                    SELECT path, qualified_name, kind, start_line, end_line,
                           signature, doc_headline, calls_json, content_sha256, estimated_tokens
                    FROM symbols
                    WHERE path >= ? AND path < ?
                    """,
                    (prefix, prefix[:-1] + "\uffff"),
                ).fetchall()
        else:
            rows = self._conn.execute(
                """
                SELECT path, qualified_name, kind, start_line, end_line,
                       signature, doc_headline, calls_json, content_sha256, estimated_tokens
                FROM symbols
                """
            ).fetchall()

        scored: list[tuple[float, str, int, dict[str, Any]]] = []
        for r in rows:
            path_s, qname, kind, start_l, end_l, sig, doc_h, calls_json, sha, est_tok = r
            qname_l = qname.lower()
            short_l = qname_l.split(".")[-1]
            sig_l = sig.lower()
            doc_l = doc_h.lower()
            calls_l = calls_json.lower()

            score = 0.0
            if qname == q:
                score = 1.0
            elif short_l == ql and q == qname.split(".")[-1]:
                score = 0.97
            elif qname_l == ql or short_l == ql:
                score = 0.93
            elif short_l.startswith(ql) or qname_l.startswith(ql):
                score = 0.84
            elif ql in qname_l:
                score = 0.76
            elif ql in sig_l:
                score = 0.62
            elif ql in calls_l:
                score = 0.54
            elif ql in doc_l:
                score = 0.48

            if q_tokens and len(q_tokens) > 1:
                haystack = f"{qname_l} {sig_l} {doc_l} {calls_l}"
                matched = sum(1 for tok in q_tokens if tok in haystack)
                if matched > 0:
                    token_score = 0.40 + 0.45 * (matched / len(q_tokens))
                    if all(tok in qname_l for tok in q_tokens):
                        token_score += 0.10
                    score = max(score, min(0.92, token_score))

            if score <= 0.0:
                continue

            hit = {
                "path": path_s,
                "qualified_name": qname,
                "kind": kind,
                "start_line": int(start_l),
                "end_line": int(end_l),
                "pointer": f"file:///{path_s}#L{int(start_l)}-L{int(end_l)}",
                "signature": sig,
                "doc_headline": doc_h,
                "calls": json.loads(calls_json),
                "content_sha256": sha,
                "estimated_tokens": int(est_tok),
                "score": round(score, 4),
            }
            scored.append((-score, path_s, int(start_l), hit))

        scored.sort(key=lambda item: (item[0], item[1], item[2]))
        return [item[3] for item in scored[: max(1, limit)]]

    def read_slice(
        self, path: str | Path, qualified_name: str, *, record_telemetry: bool = True
    ) -> dict[str, Any]:
        """Read exact raw source lines for `qualified_name` with token savings telemetry."""
        idx = self.index_file(path)
        norm_path = idx["path"]
        symbols: list[SymbolPointer] = idx["symbols"]

        target: SymbolPointer | None = None
        for sym in symbols:
            if sym.qualified_name == qualified_name:
                target = sym
                break

        # Ergonomic fallback: unique short method/function name match
        if target is None:
            short_matches = [
                sym for sym in symbols if sym.qualified_name.split(".")[-1] == qualified_name
            ]
            if len(short_matches) == 1:
                target = short_matches[0]

        if target is None:
            available = ", ".join(s.qualified_name for s in symbols[:15])
            raise KeyError(
                f"Symbol '{qualified_name}' not found in {norm_path} (available: {available})"
            )

        with open(norm_path, "r", encoding="utf-8", errors="replace") as fh:
            full_text = fh.read()

        all_lines = full_text.splitlines()
        slice_lines = all_lines[target.start_line - 1 : target.end_line]
        slice_text = "\n".join(slice_lines)

        full_file_tokens = estimate_tokens(full_text)
        slice_tokens = estimate_tokens(slice_text)
        savings_pct = (
            round(max(0.0, (1.0 - slice_tokens / full_file_tokens) * 100.0), 2)
            if full_file_tokens > 0
            else 0.0
        )
        if record_telemetry:
            self._record_op_telemetry(
                "slice",
                raw_tokens=full_file_tokens,
                emitted_tokens=slice_tokens,
                cache_hit=bool(idx["cache_hit"]),
            )

        return {
            "path": norm_path,
            "qualified_name": target.qualified_name,
            "kind": target.kind,
            "start_line": target.start_line,
            "end_line": target.end_line,
            "pointer": target.pointer_uri(norm_path),
            "signature": target.signature,
            "doc_headline": target.doc_headline,
            "calls": list(target.calls),
            "content_sha256": target.content_sha256,
            "lines": slice_lines,
            "slice_text": slice_text,
            "content": slice_text,
            "full_file_tokens": full_file_tokens,
            "slice_tokens": slice_tokens,
            "tokens_saved": max(0, full_file_tokens - slice_tokens),
            "token_savings_pct": savings_pct,
            "savings_pct": savings_pct,
            "llm_tokens_used": 0,
        }

    def _collect_benchmark_files(self, roots: list[Path] | None) -> list[Path]:
        """Resolve target files for structural benchmarking."""
        candidates: list[Path] = []
        if roots:
            for root in roots:
                p = Path(root)
                if p.is_file():
                    if p.suffix.lower() in SUPPORTED_EXTENSIONS:
                        candidates.append(p)
                elif p.is_dir():
                    for dirpath, dirnames, filenames in os.walk(p):
                        dirnames[:] = [
                            d for d in sorted(dirnames)
                            if d not in DEFAULT_EXCLUDE_DIRS and not d.startswith(".")
                        ]
                        for fn in sorted(filenames):
                            fp = Path(dirpath) / fn
                            if fp.suffix.lower() in SUPPORTED_EXTENSIONS:
                                candidates.append(fp)
        else:
            db_rows = self._conn.execute("SELECT path FROM files ORDER BY path").fetchall()
            candidates = [Path(r[0]) for r in db_rows if os.path.isfile(r[0])]
            if not candidates:
                fallback_roots = [
                    Path("C:/Aphygo/Gry_lekstuga/fonstret"),
                    Path("C:/1projects/gry_harness/gry_core"),
                ]
                existing = [r for r in fallback_roots if r.exists()]
                if not existing:
                    cwd_src = Path.cwd()
                    if cwd_src.exists():
                        existing = [cwd_src]
                if existing:
                    return self._collect_benchmark_files(existing)

        seen: set[str] = set()
        unique_files: list[Path] = []
        for fp in candidates:
            norm = normalize_path(fp)
            if norm not in seen and os.path.isfile(norm):
                seen.add(norm)
                unique_files.append(Path(norm))
        return unique_files

    def handle_pre_tool_read(
        self,
        payload: dict[str, Any],
        *,
        max_unbounded_lines: int = DEFAULT_GUARD_MAX_LINES,
        cap_lines: int = DEFAULT_GUARD_CAP_LINES,
        allowlist_ttl_sec: float = DEFAULT_GUARD_ALLOWLIST_TTL_SEC,
    ) -> dict[str, Any]:
        """Soft-cap unbounded code reads and queue a structural pointer map for PreInvocation."""
        bypass, conv_id, norm_path = pre_tool_fast_bypass(payload)
        if bypass:
            return {"decision": "allow"}

        try:
            with open(norm_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return {"decision": "allow"}

        total_lines = len(lines)
        if total_lines <= max_unbounded_lines:
            return {"decision": "allow"}

        now = time.time()
        allow_row = self._conn.execute(
            "SELECT capped_at FROM guard_allowlist WHERE conv_id = ? AND file_path = ?",
            (conv_id, norm_path),
        ).fetchone()
        if allow_row is not None and (now - float(allow_row[0])) < allowlist_ttl_sec:
            return {"decision": "allow"}

        cap_end = min(max(1, cap_lines), total_lines)
        map_res = self.render_file_map(norm_path, record_telemetry=False)
        would_read_tokens = estimate_tokens("\n".join(lines[:800]))
        capped_tokens = estimate_tokens("\n".join(lines[:cap_end]))
        saved_tokens = max(0, would_read_tokens - capped_tokens)

        self._record_op_telemetry(
            "auto_guard",
            raw_tokens=would_read_tokens,
            emitted_tokens=capped_tokens,
            cache_hit=bool(map_res["cache_hit"]),
        )
        self._conn.execute(
            """
            INSERT INTO pending_auto_maps (
                conv_id, file_path, capped_end_line, total_lines, saved_tokens, map_text, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (conv_id, norm_path, cap_end, total_lines, saved_tokens, str(map_res["map_text"]), now),
        )
        self._conn.execute(
            """
            INSERT INTO guard_allowlist (conv_id, file_path, capped_at)
            VALUES (?, ?, ?)
            ON CONFLICT(conv_id, file_path) DO UPDATE SET capped_at = excluded.capped_at
            """,
            (conv_id, norm_path, now),
        )
        self._conn.commit()

        return {
            "decision": "allow",
            "overwrite": {
                "StartLine": 1,
                "EndLine": cap_end,
            },
        }

    def pop_pending_auto_maps(self, conv_id: str) -> str | None:
        """Drain queued structural maps for `conv_id` and format as a transient ephemeralMessage."""
        has_row = self._conn.execute(
            "SELECT 1 FROM pending_auto_maps WHERE conv_id = ? LIMIT 1",
            (conv_id,),
        ).fetchone()
        if has_row is None:
            return None

        rows = self._conn.execute(
            """
            SELECT file_path, capped_end_line, total_lines, saved_tokens, map_text
            FROM pending_auto_maps
            WHERE conv_id = ?
            ORDER BY id ASC
            """,
            (conv_id,),
        ).fetchall()
        cutoff = time.time() - 7200.0
        self._conn.execute("DELETE FROM pending_auto_maps WHERE conv_id = ?", (conv_id,))
        self._conn.execute("DELETE FROM pending_auto_maps WHERE created_at < ?", (cutoff,))
        self._conn.execute("DELETE FROM guard_allowlist WHERE capped_at < ?", (cutoff,))
        self._conn.commit()

        if not rows:
            return None

        sections: list[str] = []
        for file_path, capped_end, total_lines, saved_tokens, map_text in rows:
            fname = os.path.basename(str(file_path))
            sections.append(
                f"🗺️ [Antigravity-Cache Auto-Guard] Obegränsad läsning av `{fname}` "
                f"({int(total_lines)} rader) kapades automatiskt till `L1-L{int(capped_end)}` "
                f"(sparade ~{int(saved_tokens):,} tokens). Här är filens exakta `[Lstart-Lend]`-karta "
                f"— anropa `read_file(StartLine, EndLine)` för exakt kodblock (eller läs hela filen en andra gång för att kringgå spärren):\n"
                f"{map_text}"
            )
        return "\n\n".join(sections)

    def render_cli_map_or_inline(
        self,
        path: str | Path,
        *,
        inline_small_lines: int = DEFAULT_SMALL_INLINE_LINES,
        force_map: bool = False,
    ) -> dict[str, Any]:
        """Inline numbered source for small files (<= threshold) or render AST structural map."""
        norm_path = normalize_path(path)
        if not force_map and inline_small_lines > 0:
            with open(norm_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
            if 1 <= len(lines) <= inline_small_lines:
                raw_tokens = estimate_tokens("\n".join(lines))
                numbered = "\n".join(f"{idx}: {line}" for idx, line in enumerate(lines, start=1))
                header = (
                    f"# {os.path.basename(norm_path)} (inlined {len(lines)} lines <= {inline_small_lines}, "
                    f"~{raw_tokens}t) — {norm_path}"
                )
                return {
                    "mode": "inlined_small_file",
                    "path": norm_path,
                    "line_count": len(lines),
                    "raw_tokens": raw_tokens,
                    "text": f"{header}\n{numbered}",
                    "llm_tokens_used": 0,
                }
        res = self.render_file_map(norm_path)
        return {
            "mode": "map",
            **res,
        }

    def collect_stats_and_benchmark(
        self,
        *,
        roots: list[Path] | None = None,
        slices_per_file: int = 3,
        days: float = 3.0,
        brain_dir: str | Path = DEFAULT_BRAIN_DIR,
    ) -> dict[str, Any]:
        """Measure pointer-store telemetry, live map/slice savings, and cloud KV-cache hit rates."""
        indexed_files, indexed_raw_tokens = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(raw_tokens), 0) FROM files"
        ).fetchone()
        indexed_symbols = self._conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
        db_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0

        counter_rows = self._conn.execute(
            """
            SELECT op, calls, cache_hits, raw_tokens_total, emitted_tokens_total, saved_tokens_total
            FROM telemetry_counters
            """
        ).fetchall()
        cumulative: dict[str, Any] = {}
        tot_calls = 0
        tot_hits = 0
        tot_raw = 0
        tot_emitted = 0
        tot_saved = 0
        for op_name, calls, hits, raw_t, emit_t, saved_t in counter_rows:
            c_raw = int(raw_t or 0)
            c_saved = int(saved_t or 0)
            cumulative[str(op_name)] = {
                "calls": int(calls or 0),
                "cache_hits": int(hits or 0),
                "raw_tokens_total": c_raw,
                "emitted_tokens_total": int(emit_t or 0),
                "saved_tokens_total": c_saved,
                "savings_pct": round(100.0 * c_saved / c_raw, 2) if c_raw > 0 else 0.0,
            }
            tot_calls += int(calls or 0)
            tot_hits += int(hits or 0)
            tot_raw += c_raw
            tot_emitted += int(emit_t or 0)
            tot_saved += c_saved

        for required_op in ("map", "slice", "auto_guard"):
            cumulative.setdefault(
                required_op,
                {
                    "calls": 0,
                    "cache_hits": 0,
                    "raw_tokens_total": 0,
                    "emitted_tokens_total": 0,
                    "saved_tokens_total": 0,
                    "savings_pct": 0.0,
                },
            )
        cumulative["total"] = {
            "calls": tot_calls,
            "cache_hits": tot_hits,
            "raw_tokens_total": tot_raw,
            "emitted_tokens_total": tot_emitted,
            "saved_tokens_total": tot_saved,
            "savings_pct": round(100.0 * tot_saved / tot_raw, 2) if tot_raw > 0 else 0.0,
        }

        bench_files = self._collect_benchmark_files(roots)
        for fp in bench_files:
            self.index_file(fp)

        map_raw_sum = 0
        map_tok_sum = 0
        slice_raw_sum = 0
        slice_tok_sum = 0
        slices_tested = 0
        warm_map_ms: list[float] = []

        t_bench0 = time.perf_counter()
        for fp in bench_files:
            tm0 = time.perf_counter()
            m_res = self.render_file_map(fp, record_telemetry=False)
            warm_map_ms.append((time.perf_counter() - tm0) * 1000.0)
            map_raw_sum += int(m_res["raw_tokens"])
            map_tok_sum += int(m_res["map_tokens"])

            for sym in m_res["symbols"][: max(0, slices_per_file)]:
                sl_res = self.read_slice(fp, sym["qualified_name"], record_telemetry=False)
                slice_raw_sum += int(sl_res["full_file_tokens"])
                slice_tok_sum += int(sl_res["slice_tokens"])
                slices_tested += 1
        bench_elapsed_ms = (time.perf_counter() - t_bench0) * 1000.0

        sorted_ms = sorted(warm_map_ms)
        median_ms = sorted_ms[len(sorted_ms) // 2] if sorted_ms else 0.0
        map_saved = max(0, map_raw_sum - map_tok_sum)
        slice_saved = max(0, slice_raw_sum - slice_tok_sum)

        return {
            "pointer_store": {
                "db_path": normalize_path(self.db_path),
                "db_size_bytes": db_bytes,
                "indexed_files": int(indexed_files or 0),
                "indexed_symbols": int(indexed_symbols or 0),
                "indexed_raw_tokens": int(indexed_raw_tokens or 0),
                "cumulative_usage": cumulative,
            },
            "structural_benchmark": {
                "files_tested": len(bench_files),
                "slices_tested": slices_tested,
                "elapsed_ms": round(bench_elapsed_ms, 2),
                "warm_map_median_ms": round(median_ms, 3),
                "map_vs_full": {
                    "raw_tokens": map_raw_sum,
                    "map_tokens": map_tok_sum,
                    "tokens_saved": map_saved,
                    "savings_pct": round(100.0 * map_saved / map_raw_sum, 2) if map_raw_sum > 0 else 0.0,
                },
                "slice_vs_full": {
                    "raw_tokens": slice_raw_sum,
                    "slice_tokens": slice_tok_sum,
                    "tokens_saved": slice_saved,
                    "savings_pct": round(100.0 * slice_saved / slice_raw_sum, 2) if slice_raw_sum > 0 else 0.0,
                },
            },
            "cloud_kv_cache": scan_antigravity_kv_telemetry(brain_dir=brain_dir, days=days),
            "llm_tokens_used": 0,
        }


# Module-level convenience wrappers using the default cache DB
def render_file_map(path: str | Path, *, db_path: str | Path = DEFAULT_DB_PATH) -> dict[str, Any]:
    with KVPointerCache(db_path=db_path) as cache:
        return cache.render_file_map(path)


def locate_symbol(
    query: str,
    root: str | Path | None = None,
    limit: int = 8,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    with KVPointerCache(db_path=db_path) as cache:
        return cache.locate_symbol(query=query, root=root, limit=limit)


def read_slice(
    path: str | Path,
    qualified_name: str,
    *,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    with KVPointerCache(db_path=db_path) as cache:
        return cache.read_slice(path=path, qualified_name=qualified_name)


def scan_antigravity_kv_telemetry(
    brain_dir: str | Path = DEFAULT_BRAIN_DIR, *, days: float = 3.0
) -> dict[str, Any]:
    """Scan local Antigravity transcript logs for actual cloud KV-prefix-cache hit rates."""
    root = Path(brain_dir)
    if not root.exists():
        return {
            "brain_dir": normalize_path(root),
            "days": days,
            "conversations_scanned": 0,
            "planner_turns": 0,
            "uncached_input_tokens": 0,
            "cache_read_tokens": 0,
            "total_context_tokens": 0,
            "cache_hit_pct": 0.0,
            "latest_session": None,
        }

    cutoff_ts = (time.time() - days * 86400.0) if days > 0 else 0.0
    convs = 0
    total_turns = 0
    total_uncached = 0
    total_cached = 0
    latest_mtime = -1.0
    latest_session: dict[str, Any] | None = None

    for tp in root.glob("*/.system_generated/logs/transcript.jsonl"):
        try:
            st = tp.stat()
        except OSError:
            continue
        if cutoff_ts > 0.0 and st.st_mtime < cutoff_ts:
            continue

        turns = 0
        uncached = 0
        cached = 0
        try:
            with tp.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    if '"PLANNER_RESPONSE"' in line and '"input_tokens"' in line:
                        m_in = _TRANSCRIPT_INPUT_TOK_RE.search(line)
                        if not m_in:
                            continue
                        m_ca = _TRANSCRIPT_CACHE_TOK_RE.search(line)
                        uncached += int(m_in.group(1))
                        cached += int(m_ca.group(1)) if m_ca else 0
                        turns += 1
        except OSError:
            continue

        if turns == 0:
            continue
        convs += 1
        total_turns += turns
        total_uncached += uncached
        total_cached += cached
        if st.st_mtime > latest_mtime:
            latest_mtime = st.st_mtime
            sess_total = uncached + cached
            latest_session = {
                "conversation_id": tp.parents[2].name,
                "planner_turns": turns,
                "uncached_input_tokens": uncached,
                "cache_read_tokens": cached,
                "total_context_tokens": sess_total,
                "cache_hit_pct": round(100.0 * cached / sess_total, 2) if sess_total > 0 else 0.0,
            }

    window_total = total_uncached + total_cached
    return {
        "brain_dir": normalize_path(root),
        "days": days,
        "conversations_scanned": convs,
        "planner_turns": total_turns,
        "uncached_input_tokens": total_uncached,
        "cache_read_tokens": total_cached,
        "total_context_tokens": window_total,
        "cache_hit_pct": round(100.0 * total_cached / window_total, 2) if window_total > 0 else 0.0,
        "latest_session": latest_session,
    }


def format_stats_report(report: dict[str, Any]) -> str:
    """Render a crisp, human-readable summary of pointer-cache and KV-cache telemetry."""
    ps = report["pointer_store"]
    cum = ps["cumulative_usage"]
    tot = cum["total"]
    sb = report["structural_benchmark"]
    m_cmp = sb["map_vs_full"]
    s_cmp = sb["slice_vs_full"]
    kv = report["cloud_kv_cache"]
    latest = kv.get("latest_session")

    lines = [
        "=== KVPointerCache & Cloud KV-Prefix Telemetry (0 LLM tokens) ===",
        (
            f"[Store] {ps['indexed_files']} files, {ps['indexed_symbols']} symbols, "
            f"{ps['indexed_raw_tokens']:,} raw tokens ({ps['db_size_bytes'] / 1024.0:.1f} KB) — {ps['db_path']}"
        ),
        (
            f"[Cumulative Usage] {tot['calls']} calls ({tot['cache_hits']} warm hits) | "
            f"emitted {tot['emitted_tokens_total']:,}t vs {tot['raw_tokens_total']:,}t raw -> "
            f"saved {tot['saved_tokens_total']:,}t ({tot['savings_pct']}%)"
        ),
        (
            f"[Live Benchmark] {sb['files_tested']} files, {sb['slices_tested']} slices "
            f"in {sb['elapsed_ms']}ms (warm map median {sb['warm_map_median_ms']}ms):"
        ),
        (
            f"  - Map vs Full-file:   {m_cmp['map_tokens']:,}t vs {m_cmp['raw_tokens']:,}t "
            f"-> saved {m_cmp['tokens_saved']:,}t ({m_cmp['savings_pct']}%)"
        ),
        (
            f"  - Slice vs Full-file: {s_cmp['slice_tokens']:,}t vs {s_cmp['raw_tokens']:,}t "
            f"-> saved {s_cmp['tokens_saved']:,}t ({s_cmp['savings_pct']}%)"
        ),
        (
            f"[Cloud KV Cache ({kv['days']:g}d)] {kv['conversations_scanned']} convs, "
            f"{kv['planner_turns']} turns | {kv['cache_read_tokens']:,} cached / "
            f"{kv['total_context_tokens']:,} total ({kv['cache_hit_pct']}% cached)"
        ),
    ]
    ag = cum.get("auto_guard", {})
    if int(ag.get("calls", 0)) > 0:
        lines.insert(
            3,
            (
                f"  - Auto-Guard Shield:  {ag['calls']} unbounded reads capped -> "
                f"saved {ag['saved_tokens_total']:,}t ({ag['savings_pct']}%)"
            ),
        )
    if latest:
        lines.append(
            f"  - Latest ({latest['conversation_id'][:8]}): {latest['planner_turns']} turns | "
            f"{latest['cache_read_tokens']:,} cached / {latest['total_context_tokens']:,} total "
            f"({latest['cache_hit_pct']}% cached)"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4. CLI Interface
# ---------------------------------------------------------------------------


def _configure_utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def build_arg_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--db",
        type=Path,
        default=argparse.SUPPRESS,
        help=f"SQLite cache path (default: {DEFAULT_DB_PATH})",
    )

    parser = argparse.ArgumentParser(
        prog="kv_pointer_cache",
        description="Zero-LLM Structural Pointer Cache (KV-prefix-cache safe AST/symbol pointers).",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"SQLite cache path (default: {DEFAULT_DB_PATH})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_map = sub.add_parser("map", parents=[common], help="Render compact deterministic structural map for a file.")
    p_map.add_argument("file", type=Path, help="Target file path.")
    p_map.add_argument(
        "--inline-small-lines",
        type=int,
        default=DEFAULT_SMALL_INLINE_LINES,
        help=f"Inline numbered source when <= N lines (0 disables, default: {DEFAULT_SMALL_INLINE_LINES}).",
    )
    p_map.add_argument("--force-map", action="store_true", help="Always emit structural map even for small files.")
    p_map.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_loc = sub.add_parser("locate", parents=[common], help="Locate symbols by name, signature, docstring, or callees.")
    p_loc.add_argument("symbol_query", type=str, help="Symbol search query.")
    p_loc.add_argument("--root", type=Path, default=None, help="Optional directory/file root to index and filter.")
    p_loc.add_argument("--limit", type=int, default=8, help="Max results (default: 8).")
    p_loc.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_slice = sub.add_parser("slice", parents=[common], help="Read exact line-range slice for a symbol.")
    p_slice.add_argument("file", type=Path, help="Target file path.")
    p_slice.add_argument("qualified_name", type=str, help="Qualified symbol name (e.g. ClassName.method or func).")
    p_slice.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_idx = sub.add_parser("index", parents=[common], help="Incrementally index a file or directory.")
    p_idx.add_argument("target", type=Path, help="File or directory to index.")

    p_stats = sub.add_parser(
        "stats",
        aliases=["benchmark"],
        parents=[common],
        help="Show cumulative pointer-cache savings, structural benchmark, and cloud KV-cache telemetry.",
    )
    p_stats.add_argument("--roots", nargs="*", type=Path, default=None, help="Optional files/directories to benchmark.")
    p_stats.add_argument("--days", type=float, default=3.0, help="Days of Antigravity transcript logs to aggregate (default: 3).")
    p_stats.add_argument("--brain-dir", type=Path, default=DEFAULT_BRAIN_DIR, help="Antigravity brain logs directory.")
    p_stats.add_argument("--slices-per-file", type=int, default=3, help="Max symbols per file for slice benchmark (default: 3).")
    p_stats.add_argument("--json", action="store_true", help="Emit JSON output.")

    p_hook = sub.add_parser(
        "hook",
        parents=[common],
        help="Antigravity PreToolUse / PreInvocation lifecycle hook handler.",
    )
    p_hook.add_argument("--event", choices=["pre_tool", "pre_invocation"], required=True)
    p_hook.add_argument("--max-lines", type=int, default=DEFAULT_GUARD_MAX_LINES)
    p_hook.add_argument("--cap-lines", type=int, default=DEFAULT_GUARD_CAP_LINES)

    return parser


def _run_hook_cli(args: argparse.Namespace) -> int:
    """Execute fail-open Antigravity PreToolUse / PreInvocation hook handling."""
    default_out = '{"decision": "allow"}' if args.event == "pre_tool" else "{}"
    try:
        raw_stdin = sys.stdin.read().strip()
        payload = json.loads(raw_stdin) if raw_stdin else {}
        if not isinstance(payload, dict):
            payload = {}

        if args.event == "pre_tool":
            bypass, _, _ = pre_tool_fast_bypass(payload)
            if bypass:
                print('{"decision": "allow"}')
                return 0
            with KVPointerCache(db_path=args.db) as cache:
                res = cache.handle_pre_tool_read(
                    payload,
                    max_unbounded_lines=int(args.max_lines),
                    cap_lines=int(args.cap_lines),
                )
            print(json.dumps(res, ensure_ascii=False))
            return 0

        conv_id = str(payload.get("conversationId") or "default_session")
        with KVPointerCache(db_path=args.db) as cache:
            msg = cache.pop_pending_auto_maps(conv_id)
        if msg:
            print(json.dumps({"injectSteps": [{"ephemeralMessage": msg}]}, ensure_ascii=False))
        else:
            print("{}")
        return 0
    except Exception:
        print(default_out)
        return 0


def main(argv: list[str] | None = None) -> int:
    _configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "hook":
        return _run_hook_cli(args)

    with KVPointerCache(db_path=args.db) as cache:
        if args.command == "map":
            if args.json or args.force_map:
                res = cache.render_file_map(args.file)
                if args.json:
                    print(json.dumps(res, ensure_ascii=False, indent=2))
                else:
                    print(res["map_text"])
                    print(
                        f"\n# Telemetry: map={res['map_tokens']}t vs raw={res['raw_tokens']}t "
                        f"({res['savings_pct']}% saved, cache_hit={res['cache_hit']}, llm_tokens=0)"
                    )
            else:
                res = cache.render_cli_map_or_inline(
                    args.file,
                    inline_small_lines=int(args.inline_small_lines),
                    force_map=False,
                )
                if res["mode"] == "inlined_small_file":
                    print(res["text"])
                else:
                    print(res["map_text"])
                    print(
                        f"\n# Telemetry: map={res['map_tokens']}t vs raw={res['raw_tokens']}t "
                        f"({res['savings_pct']}% saved, cache_hit={res['cache_hit']}, llm_tokens=0)"
                    )
            return 0

        if args.command == "locate":
            hits = cache.locate_symbol(args.symbol_query, root=args.root, limit=args.limit)
            if args.json:
                print(json.dumps(hits, ensure_ascii=False, indent=2))
            elif not hits:
                print(f"No symbols matched '{args.symbol_query}'.")
            else:
                for h in hits:
                    doc = f" — {h['doc_headline']}" if h["doc_headline"] else ""
                    print(
                        f"{h['pointer']} (~{h['estimated_tokens']}t, score={h['score']}) "
                        f"{h['signature']}{doc}"
                    )
            return 0

        if args.command == "slice":
            try:
                res = cache.read_slice(args.file, args.qualified_name)
            except KeyError as exc:
                print(str(exc), file=sys.stderr)
                return 1
            if args.json:
                print(json.dumps(res, ensure_ascii=False, indent=2))
            else:
                print(
                    f"# {res['pointer']} ({res['slice_tokens']}t vs {res['full_file_tokens']}t full, "
                    f"{res['token_savings_pct']}% saved, sha256={res['content_sha256']})"
                )
                print(res["slice_text"])
            return 0

        if args.command == "index":
            target: Path = args.target
            if target.is_dir():
                res = cache.index_directory(target)
            else:
                res = cache.index_file(target)
                res = {k: v for k, v in res.items() if k != "symbols"}
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 0

        if args.command in ("stats", "benchmark"):
            report = cache.collect_stats_and_benchmark(
                roots=args.roots,
                slices_per_file=args.slices_per_file,
                days=args.days,
                brain_dir=args.brain_dir,
            )
            if args.json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(format_stats_report(report))
            return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
