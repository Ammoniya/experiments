#!/usr/bin/env python3
"""Generate paired DTW/AST samples with trimmed per-script traces.

The script scans the cached AST similarity matrix and corresponding DTW
distance matrix, selects pairs that satisfy the requested similarity ranges,
and copies the underlying JavaScript plus a script-scoped trace (from
`byscripts.json`) into an output directory similar to `dtw_ast_pair_samples`.
"""

from __future__ import annotations

import argparse
import csv
import heapq
import json
import logging
import shutil
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np

LOGGER = logging.getLogger("sample_dtw_ast_pairs")
DEFAULT_OVERSAMPLE_FACTOR = 4


@dataclass(frozen=True)
class PairMatch:
    index_a: int
    index_b: int
    dtw_similarity: float
    ast_similarity: float


@dataclass
class TraceArtifacts:
    trace_id: str
    script_id: str
    script_url: str
    script_file_name: str
    source_script_path: Path
    trace_dir: Path
    events: List[Dict[str, object]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sample script pairs that satisfy AST and DTW similarity ranges."
    )
    parser.add_argument(
        "--ast-matrix",
        default="cache/ast_matrix_latest.npz",
        help="Path to the AST similarity cache (default: %(default)s)",
    )
    parser.add_argument(
        "--dtw-matrix",
        default="cache/dtw_matrix_latest.npz",
        help="Path to the DTW distance cache (default: %(default)s)",
    )
    parser.add_argument(
        "--experiment-root",
        default="experiment_data",
        help="Directory that contains <hash>/<timestamp>/ trace folders (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default="dtw_ast_pair_samples",
        help="Directory where the pair folders will be written (default: %(default)s)",
    )
    parser.add_argument("--ast-min", type=float, default=0.0, help="Minimum AST similarity (inclusive).")
    parser.add_argument(
        "--ast-max", type=float, default=1.0, help="Maximum AST similarity (inclusive)."
    )
    parser.add_argument("--dtw-min", type=float, default=0.0, help="Minimum normalized DTW similarity.")
    parser.add_argument("--dtw-max", type=float, default=1.0, help="Maximum normalized DTW similarity.")
    parser.add_argument(
        "--max-pairs",
        type=int,
        default=10,
        help="Maximum number of pair directories to export (0 = unlimited, default: %(default)s).",
    )
    parser.add_argument(
        "--oversample-factor",
        type=int,
        default=DEFAULT_OVERSAMPLE_FACTOR,
        help=(
            "How many extra matches to keep in memory (per requested pair) so we have fallbacks "
            "if copying fails (default: %(default)s)."
        ),
    )
    parser.add_argument(
        "--summary-file",
        default=None,
        help="Optional custom path for the summary file (default: <output-dir>/pairs_summary.txt).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Clear the output directory before writing new samples.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging verbosity (default: %(default)s).",
    )
    return parser.parse_args()


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def load_ast_similarity(path: Path) -> Tuple[np.ndarray, Sequence[str]]:
    if not path.exists():
        raise FileNotFoundError(f"AST similarity cache not found at {path}")
    LOGGER.info("Loading AST similarity matrix from %s", path)
    with np.load(path) as data:
        matrix = data["similarity_matrix"].astype(np.float32, copy=False)
        trace_ids = data["trace_ids"].astype(str)
    LOGGER.info("Loaded AST similarity grid with %d traces.", matrix.shape[0])
    return matrix, trace_ids.tolist()


def load_dtw_distances(path: Path) -> Tuple[np.ndarray, Sequence[str]]:
    if not path.exists():
        raise FileNotFoundError(f"DTW cache not found at {path}")
    LOGGER.info("Loading DTW distance matrix from %s", path)
    with np.load(path) as data:
        matrix = data["distance_matrix"].astype(np.float32, copy=False)
        trace_ids = data["trace_ids"].astype(str)
    LOGGER.info("Loaded DTW distance grid with %d traces.", matrix.shape[0])
    return matrix, trace_ids.tolist()


def validate_trace_alignment(ast_ids: Sequence[str], dtw_ids: Sequence[str]) -> None:
    if len(ast_ids) != len(dtw_ids):
        raise RuntimeError(
            f"Trace count mismatch between AST ({len(ast_ids)}) and DTW ({len(dtw_ids)}) matrices."
        )
    for idx, (lhs, rhs) in enumerate(zip(ast_ids, dtw_ids)):
        if lhs != rhs:
            raise RuntimeError(
                f"Trace ID mismatch at index {idx}: AST has {lhs}, DTW has {rhs}. "
                "Re-run compute_ast_similarity_matrix.py to realign the caches."
            )


def normalized_dtw(distance: float) -> float:
    if not np.isfinite(distance):
        return 0.0
    return 1.0 / (1.0 + float(distance))


def find_candidate_pairs(
    ast_matrix: np.ndarray,
    dtw_matrix: np.ndarray,
    ast_min: float,
    ast_max: float,
    dtw_min: float,
    dtw_max: float,
    requested_pairs: int,
    oversample_factor: int,
) -> List[PairMatch]:
    trace_count = ast_matrix.shape[0]
    if dtw_matrix.shape != ast_matrix.shape:
        raise RuntimeError("AST and DTW matrices must share the same shape.")

    capacity = None
    if requested_pairs > 0 and oversample_factor > 0:
        capacity = max(1, requested_pairs * oversample_factor)

    matches: List[Tuple[float, float, int, int]]
    heap: List[Tuple[float, float, int, int]] = []
    matches = [] if capacity is None else heap

    LOGGER.info(
        "Scanning %d x %d similarity grid for AST in [%0.4f, %0.4f] and DTW in [%0.4f, %0.4f].",
        trace_count,
        trace_count,
        ast_min,
        ast_max,
        dtw_min,
        dtw_max,
    )

    for i in range(trace_count - 1):
        ast_row = ast_matrix[i]
        mask = np.isfinite(ast_row)
        mask &= ast_row >= ast_min
        mask &= ast_row <= ast_max
        mask[: i + 1] = False  # keep upper triangle only
        candidate_indices = np.flatnonzero(mask)
        if not len(candidate_indices):
            if i and i % 1000 == 0:
                LOGGER.info("Processed %d/%d rows (matches kept: %d).", i, trace_count, len(matches))
            continue

        dtw_row = dtw_matrix[i]
        for j in candidate_indices:
            dtw_score = normalized_dtw(dtw_row[j])
            if dtw_score < dtw_min or dtw_score > dtw_max:
                continue
            ast_score = float(ast_row[j])
            entry = (dtw_score, ast_score, i, j)
            if capacity is None:
                matches.append(entry)
            else:
                if len(heap) < capacity:
                    heapq.heappush(heap, entry)
                elif entry > heap[0]:
                    heapq.heapreplace(heap, entry)
        if i and i % 1000 == 0:
            LOGGER.info("Processed %d/%d rows (matches kept: %d).", i, trace_count, len(matches))

    if not matches:
        return []

    matches_sorted = sorted(matches, key=lambda item: (item[0], item[1]), reverse=True)
    return [
        PairMatch(index_a=i, index_b=j, dtw_similarity=dtw_sim, ast_similarity=ast_sim)
        for dtw_sim, ast_sim, i, j in matches_sorted
    ]


def parse_trace_id(trace_id: str) -> Tuple[str, str, str]:
    parts = trace_id.rsplit("_", 2)
    if len(parts) != 3:
        raise ValueError(f"Unexpected trace_id format: {trace_id}")
    return parts[0], parts[1], parts[2]


def load_trace_index(trace_dir: Path) -> Dict[str, Dict[str, str]]:
    return _load_trace_index_cached(str(trace_dir))


@lru_cache(maxsize=4096)
def _load_trace_index_cached(trace_dir_str: str) -> Dict[str, Dict[str, str]]:
    trace_dir = Path(trace_dir_str)
    index_path = trace_dir / "loaded_js" / "index.csv"
    if not index_path.exists():
        raise FileNotFoundError(f"Missing loaded_js/index.csv under {trace_dir}")
    rows: Dict[str, Dict[str, str]] = {}
    with index_path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            script_id = row.get("script_id")
            if script_id:
                rows[str(script_id)] = row
    return rows


def load_byscripts(trace_dir: Path) -> Dict[str, Dict[str, object]]:
    return _load_byscripts_cached(str(trace_dir))


@lru_cache(maxsize=4096)
def _load_byscripts_cached(trace_dir_str: str) -> Dict[str, Dict[str, object]]:
    trace_dir = Path(trace_dir_str)
    by_path = trace_dir / "byscripts.json"
    if not by_path.exists():
        raise FileNotFoundError(f"Missing byscripts.json under {trace_dir}")
    with by_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Unexpected structure in {by_path}; expected object keyed by script_id.")
    normalized: Dict[str, Dict[str, object]] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            normalized[str(key)] = value
    return normalized


def build_trace_artifacts(trace_id: str, experiment_root: Path) -> TraceArtifacts:
    url_hash, timestamp, script_suffix = parse_trace_id(trace_id)
    trace_dir = experiment_root / url_hash / timestamp
    if not trace_dir.exists():
        raise FileNotFoundError(f"Trace directory not found: {trace_dir}")
    script_id = script_suffix
    script_rows = load_trace_index(trace_dir)
    script_meta = script_rows.get(script_id)
    if not script_meta:
        raise FileNotFoundError(f"script_id {script_id} missing from {trace_dir}/loaded_js/index.csv")
    file_name = script_meta.get("file_name") or f"{script_id}.js"
    script_path = trace_dir / "loaded_js" / file_name
    if not script_path.exists():
        raise FileNotFoundError(f"Script file not found: {script_path}")

    byscripts = load_byscripts(trace_dir)
    by_entry = byscripts.get(script_id)
    if not by_entry:
        raise FileNotFoundError(f"script_id {script_id} missing from {trace_dir}/byscripts.json")
    events = by_entry.get("events") or []
    if not isinstance(events, list):
        events = []
    script_url = (
        by_entry.get("url")
        or script_meta.get("script_url")
        or script_meta.get("url")
        or ""
    )
    return TraceArtifacts(
        trace_id=trace_id,
        script_id=script_id,
        script_url=script_url,
        script_file_name=file_name,
        source_script_path=script_path,
        trace_dir=trace_dir,
        events=list(events),
    )


def write_trace_payload(target_dir: Path, artifact: TraceArtifacts) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifact.source_script_path, target_dir / artifact.script_file_name)
    payload = {
        "trace_id": artifact.trace_id,
        "script_id": artifact.script_id,
        "script_url": artifact.script_url,
        "source_trace_dir": str(artifact.trace_dir),
        "source_script_path": str(artifact.source_script_path),
        "event_count": len(artifact.events),
        "events": artifact.events,
    }
    trace_path = target_dir / "trace_v2.json"
    with trace_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def export_pair(
    pair_dir: Path,
    trace_a: TraceArtifacts,
    trace_b: TraceArtifacts,
) -> None:
    write_trace_payload(pair_dir / f"A_{trace_a.trace_id}", trace_a)
    write_trace_payload(pair_dir / f"B_{trace_b.trace_id}", trace_b)


def write_summary(
    summary_path: Path,
    exported_pairs: List[Tuple[str, str, float, float]],
    ast_min: float,
    ast_max: float,
    dtw_min: float,
    dtw_max: float,
) -> None:
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", encoding="utf-8") as handle:
        handle.write(
            f"DTW normalized in [{dtw_min:.4f}, {dtw_max:.4f}] ; "
            f"AST similarity in [{ast_min:.4f}, {ast_max:.4f}]\n"
        )
        for trace_a, trace_b, dtw_sim, ast_sim in exported_pairs:
            handle.write(
                f"{trace_a} | {trace_b} | DTW_norm={dtw_sim:.4f}, AST={ast_sim:.4f}\n"
            )


def ensure_output_dir(path: Path, overwrite: bool) -> None:
    if path.exists():
        if not overwrite:
            raise SystemExit(
                f"Output directory {path} already exists. Use --overwrite to replace it."
            )
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def main() -> None:
    args = parse_args()
    setup_logging(args.log_level)

    ast_matrix, ast_trace_ids = load_ast_similarity(Path(args.ast_matrix))
    dtw_matrix, dtw_trace_ids = load_dtw_distances(Path(args.dtw_matrix))
    validate_trace_alignment(ast_trace_ids, dtw_trace_ids)

    requested_pairs = max(0, int(args.max_pairs))
    oversample = max(1, int(args.oversample_factor))

    matches = find_candidate_pairs(
        ast_matrix=ast_matrix,
        dtw_matrix=dtw_matrix,
        ast_min=args.ast_min,
        ast_max=args.ast_max,
        dtw_min=args.dtw_min,
        dtw_max=args.dtw_max,
        requested_pairs=requested_pairs,
        oversample_factor=oversample,
    )
    if not matches:
        LOGGER.warning("No trace pairs matched the requested similarity criteria.")
        return

    ensure_output_dir(Path(args.output_dir), args.overwrite)
    summary_path = Path(args.summary_file) if args.summary_file else Path(args.output_dir) / "pairs_summary.txt"

    exported: List[Tuple[str, str, float, float]] = []
    experiment_root = Path(args.experiment_root)
    pair_index = 0
    max_pairs_to_emit = requested_pairs or len(matches)
    padding = max(2, len(str(max_pairs_to_emit)))

    for match in matches:
        if len(exported) >= max_pairs_to_emit:
            break
        trace_a_id = ast_trace_ids[match.index_a]
        trace_b_id = ast_trace_ids[match.index_b]
        try:
            trace_a = build_trace_artifacts(trace_a_id, experiment_root)
            trace_b = build_trace_artifacts(trace_b_id, experiment_root)
        except (FileNotFoundError, ValueError) as exc:
            LOGGER.warning(
                "Skipping pair (%s, %s) due to missing artifacts: %s",
                trace_a_id,
                trace_b_id,
                exc,
            )
            continue

        pair_index += 1
        pair_dir = Path(args.output_dir) / f"pair_{pair_index:0{padding}d}"
        export_pair(pair_dir, trace_a, trace_b)
        exported.append((trace_a_id, trace_b_id, match.dtw_similarity, match.ast_similarity))
        LOGGER.info(
            "Exported pair %s (DTW=%0.4f, AST=%0.4f)",
            pair_dir.name,
            match.dtw_similarity,
            match.ast_similarity,
        )

    if not exported:
        LOGGER.warning("No pairs could be exported because all candidates were missing artifacts.")
        return

    write_summary(summary_path, exported, args.ast_min, args.ast_max, args.dtw_min, args.dtw_max)
    LOGGER.info("Wrote %d pair(s) and summary to %s", len(exported), summary_path)


if __name__ == "__main__":
    main()
