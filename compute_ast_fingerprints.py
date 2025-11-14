#!/usr/bin/env python3
"""
Generate structural fingerprints for every JavaScript payload in experiment_data.
The fingerprints capture AST node distributions and depth statistics so we can
derive coarse-grained similarity scores between scripts without re-running the
parser each time.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import esprima
from tree_sitter import Parser, Language
import tree_sitter_javascript
from tqdm import tqdm


SUPPORTED_EXTENSIONS = {".js", ".mjs", ".cjs"}
HTML_SNIPPET_PATTERN = re.compile(r"<\s*(?:!DOCTYPE|html|script|body|head|div|span)", re.IGNORECASE)
MAX_PREVIEW_LINES = 400
MAX_PREVIEW_CHARS = 8000

_ts_capsule = tree_sitter_javascript.language()
TS_JAVASCRIPT_LANGUAGE = Language.__new__(Language)
Language.__init__(TS_JAVASCRIPT_LANGUAGE, _ts_capsule)
TS_JAVASCRIPT_PARSER = Parser()
TS_JAVASCRIPT_PARSER.language = TS_JAVASCRIPT_LANGUAGE

# Silence esprima's regex FutureWarning noise
warnings.filterwarnings("ignore", category=FutureWarning, module="esprima")


class NonJavaScriptError(Exception):
    """Raised when the payload is clearly not JavaScript (e.g., HTML)."""


def looks_like_html(text: str) -> bool:
    snippet = text.lstrip()
    if not snippet:
        return True
    if snippet.startswith("<"):
        return True
    return bool(HTML_SNIPPET_PATTERN.search(snippet[:200]))


def looks_like_expression(snippet: str) -> bool:
    stripped = snippet.lstrip()
    if not stripped:
        return False
    return stripped[0] in {"{", "[", "(", ".", "="}


def wrap_as_expression(code: str) -> str:
    return f"module.exports = ({code.strip()})"


@dataclass
class Fingerprint:
    script_path: Path
    output_path: Path
    script_hash: str
    file_name: str
    node_counts: Counter
    depth_histogram: Counter
    num_nodes: int
    max_depth: int
    parser: str = "esprima"
    ast_preview: str | None = None

    def to_dict(self) -> Dict[str, object]:
        if self.num_nodes <= 0:
            normalized_counts: Dict[str, float] = {}
        else:
            normalized_counts = {
                node_type: count / self.num_nodes
                for node_type, count in self.node_counts.items()
            }

        l2_norm = math.sqrt(sum(count ** 2 for count in self.node_counts.values()))
        unit_vector = {}
        if l2_norm > 0:
            unit_vector = {
                node_type: count / l2_norm
                for node_type, count in self.node_counts.items()
            }

        vector_signature = ";".join(
            f"{node}:{unit_vector.get(node, 0.0):.6f}"
            for node in sorted(unit_vector.keys())
        )
        feature_hash = hashlib.sha256(vector_signature.encode("utf-8")).hexdigest()

        return {
            "script_path": str(self.script_path),
            "file_name": self.file_name,
            "script_hash": self.script_hash,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "num_nodes": self.num_nodes,
            "max_depth": self.max_depth,
            "node_type_counts": dict(self.node_counts),
            "depth_histogram": dict(self.depth_histogram),
            "normalized_counts": normalized_counts,
            "unit_vector": unit_vector,
            "feature_hash": feature_hash,
            "parser": self.parser,
            "ast_preview": self.ast_preview,
        }


def iter_js_files(data_dir: Path) -> Iterable[Path]:
    for js_path in data_dir.rglob("*"):
        if not js_path.is_file():
            continue
        if js_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        if js_path.parent.name != "loaded_js":
            continue
        yield js_path


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_ast_dir(js_path: Path) -> Path:
    timestamp_dir = js_path.parent.parent
    ast_dir = timestamp_dir / "loaded_js_asts"
    ast_dir.mkdir(parents=True, exist_ok=True)
    return ast_dir


def parse_with_esprima(code: str) -> dict:
    """Try parsing with esprima (module or script)."""
    if looks_like_html(code):
        raise NonJavaScriptError("HTML-like payload")

    last_error: Optional[Exception] = None
    attempts = [
        ("module", code),
        ("script", code),
    ]

    if looks_like_expression(code):
        attempts.append(("script_expr", wrap_as_expression(code)))

    for mode, payload in attempts:
        try:
            if mode == "module":
                return esprima.parseModule(payload, tolerant=True, jsx=True).toDict()
            return esprima.parseScript(payload, tolerant=True, jsx=True).toDict()
        except Exception as exc:  # noqa: BLE001
            last_error = exc

    if last_error:
        raise last_error
    raise SyntaxError("esprima failed without specific error")


def parse_with_tree_sitter(code: str):
    tree = TS_JAVASCRIPT_PARSER.parse(code.encode("utf-8", "ignore"))
    return tree.root_node


def walk_esprima_ast(root, counts: Counter, depth_hist: Counter) -> Tuple[int, int]:
    """Traverse an Esprima dict AST iteratively."""
    stack = [(root, 0)]
    total_nodes = 0
    max_depth = 0

    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            node_type = node.get("type")
            if node_type:
                counts[node_type] += 1
                depth_hist[depth] += 1
                total_nodes += 1
                max_depth = max(max_depth, depth)
            for key, value in node.items():
                if key in {"range", "loc", "raw"}:
                    continue
                if isinstance(value, (dict, list)):
                    stack.append((value, depth + 1))
                elif not isinstance(value, (str, bytes, int, float, bool, type(None))):
                    stack.append((value, depth + 1))
        elif isinstance(node, list):
            for item in node:
                stack.append((item, depth))

    return total_nodes, max_depth


def walk_tree_sitter_ast(root, counts: Counter, depth_hist: Counter) -> Tuple[int, int]:
    """Traverse a Tree-sitter AST iteratively to avoid recursion limits."""
    stack = [(root, 0)]
    total_nodes = 0
    max_depth = 0

    while stack:
        node, depth = stack.pop()
        node_type = node.type
        counts[node_type] += 1
        depth_hist[depth] += 1
        total_nodes += 1
        max_depth = max(max_depth, depth)
        for child in node.children:
            stack.append((child, depth + 1))

    return total_nodes, max_depth


def build_preview_from_esprima(root, max_lines=MAX_PREVIEW_LINES, max_chars=MAX_PREVIEW_CHARS):
    lines = []
    stack = [("root", root, 0)]
    visited = 0

    while stack and visited < max_lines:
        label, node, depth = stack.pop()
        indent = "  " * depth
        if isinstance(node, dict):
            node_type = node.get("type") or label
            lines.append(f"{indent}- {node_type}")
            visited += 1
            if visited >= max_lines:
                break
            for key, value in sorted(node.items(), reverse=True):
                if key in {"range", "loc", "raw"}:
                    continue
                if isinstance(value, (dict, list)):
                    stack.append((key, value, depth + 1))
        elif isinstance(node, list) and node:
            lines.append(f"{indent}- {label}[] ({len(node)})")
            visited += 1
            for idx in range(len(node) - 1, -1, -1):
                value = node[idx]
                if isinstance(value, (dict, list)):
                    stack.append((f"{label}[{idx}]", value, depth + 1))

    preview = "\n".join(lines)
    if len(preview) > max_chars:
        preview = preview[:max_chars] + "\n... (truncated) ..."
    return preview


def build_preview_from_treesitter(root, max_lines=MAX_PREVIEW_LINES, max_chars=MAX_PREVIEW_CHARS):
    lines = []
    stack = [(root, 0)]
    visited = 0

    while stack and visited < max_lines:
        node, depth = stack.pop()
        indent = "  " * depth
        lines.append(f"{indent}- {node.type}")
        visited += 1
        children = list(node.children)
        for child in reversed(children):
            stack.append((child, depth + 1))

    preview = "\n".join(lines)
    if len(preview) > max_chars:
        preview = preview[:max_chars] + "\n... (truncated) ..."
    return preview


def fingerprint_script(js_path: Path, raw_bytes: bytes, script_hash: str) -> Fingerprint:
    try:
        code = raw_bytes.decode("utf-8", errors="ignore")
    except Exception as exc:
        raise ValueError(f"Failed to decode {js_path}: {exc}") from exc

    counts = Counter()
    depth_hist = Counter()
    parser_used = "esprima"
    preview_text = None

    try:
        tree = parse_with_esprima(code)
        num_nodes, max_depth = walk_esprima_ast(tree, counts=counts, depth_hist=depth_hist)
        preview_text = build_preview_from_esprima(tree)
    except NonJavaScriptError:
        raise
    except Exception as esprima_exc:
        try:
            parser_used = "tree-sitter"
            ts_tree = parse_with_tree_sitter(code)
            num_nodes, max_depth = walk_tree_sitter_ast(ts_tree, counts=counts, depth_hist=depth_hist)
            preview_text = build_preview_from_treesitter(ts_tree)
        except Exception as ts_exc:
            raise ValueError(f"Parsing error ({js_path}): {esprima_exc}") from ts_exc

    ast_dir = ensure_ast_dir(js_path)
    output_path = ast_dir / f"ast_{script_hash}.json"
    return Fingerprint(
        script_path=js_path,
        output_path=output_path,
        script_hash=script_hash,
        file_name=js_path.name,
        node_counts=counts,
        depth_histogram=depth_hist,
        num_nodes=num_nodes,
        max_depth=max_depth,
        parser=parser_used,
        ast_preview=preview_text,
    )


def process_js_file(js_path: Path, force: bool = False) -> Tuple[str, Optional[Path]]:
    try:
        raw_bytes = js_path.read_bytes()
    except Exception as exc:
        print(f"[!] Failed to read {js_path}: {exc}")
        return "failed", None

    script_hash = hashlib.sha256(raw_bytes).hexdigest()
    ast_dir = ensure_ast_dir(js_path)
    candidate = ast_dir / f"ast_{script_hash}.json"
    if candidate.exists() and not force:
        return "cached", candidate

    try:
        fp = fingerprint_script(js_path, raw_bytes, script_hash)
    except NonJavaScriptError:
        return "non_js", None
    except ValueError as exc:
        print(f"[!] {exc}")
        return "failed", None

    fp.output_path.write_text(json.dumps(fp.to_dict(), indent=2))
    return "written", fp.output_path


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compute AST fingerprints for every loaded_js/*.js payload."
    )
    parser.add_argument("--data-dir", default="experiment_data",
                        help="Root directory containing experiment data.")
    parser.add_argument("--force", action="store_true",
                        help="Recompute fingerprints even if cached files exist.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Only process this many files (useful for smoke tests).")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)

    data_dir = Path(args.data_dir).resolve()
    if not data_dir.exists():
        print(f"Data directory not found: {data_dir}")
        return 1

    js_files = list(iter_js_files(data_dir))
    if args.limit:
        js_files = js_files[:args.limit]

    if not js_files:
        print("No JavaScript files found under loaded_js directories.")
        return 0

    processed = 0
    cached = 0
    failures = 0
    non_js = 0

    for js_path in tqdm(js_files, desc="Generating AST fingerprints"):
        status, _ = process_js_file(js_path, force=args.force)
        if status == "written":
            processed += 1
        elif status == "cached":
            cached += 1
        elif status == "non_js":
            non_js += 1
        else:
            failures += 1

    print("\n=== AST fingerprint summary ===")
    print(f"Total JS files scanned : {len(js_files)}")
    print(f"New fingerprints       : {processed}")
    print(f"Skipped (cached)       : {cached}")
    print(f"Non-JS payloads        : {non_js}")
    print(f"Failures               : {failures}")

    if failures:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
