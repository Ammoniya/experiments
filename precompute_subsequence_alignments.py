#!/usr/bin/env python3
"""
Precompute subsequence DTW alignments for every clustered trace so the
visualization layer can render trace details without doing expensive work in
Dash callbacks.
"""

from __future__ import annotations

import argparse
import os
import pickle
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from tqdm import tqdm

try:
    from dtaidistance.subsequence.dtw import subsequence_alignment
except ImportError:  # pragma: no cover - optional dependency
    subsequence_alignment = None

from subsequence_alignment_cache import (
    CACHE_VERSION,
    default_cache_path,
    load_alignment_cache,
    cache_is_stale,
)

MAX_DTW_HEATMAP_CELLS = int(os.environ.get("MAX_DTW_HEATMAP_CELLS", "160000"))


def _encode_sequences(event_types: List[str], sequences: List[List[str]]) -> List[np.ndarray]:
    mapping = {label: idx for idx, label in enumerate(event_types)}
    fallback = -1.0
    numeric = []
    for seq in sequences:
        if not seq:
            numeric.append(np.array([], dtype=float))
            continue
        numeric.append(np.array([float(mapping.get(evt, fallback)) for evt in seq], dtype=float))
    return numeric


@dataclass
class Representative:
    trace_index: int
    trace_id: Optional[str]
    sequence: np.ndarray
    event_sequence: List[str]
    score: float
    script_url: Optional[str]
    num_events: Optional[int]


class AlignmentCacheBuilder:
    def __init__(self, results_path: Path, output_path: Path, max_heatmap_cells: int):
        self.results_path = results_path
        self.output_path = output_path
        self.max_heatmap_cells = max_heatmap_cells
        self.results = self._load_results()
        self.traces: List[Dict[str, Any]] = self.results["traces"]
        self.raw_sequences: List[List[str]] = self.results.get("sequences") or [
            trace.get("event_sequence", []) for trace in self.traces
        ]
        encoded_sequences = self.results.get("encoded_sequences")
        if encoded_sequences:
            self.numeric_sequences = [np.array(seq, dtype=float) for seq in encoded_sequences]
        else:
            event_types = self.results.get("event_types") or []
            self.numeric_sequences = _encode_sequences(event_types, self.raw_sequences)

        self.trace_index_lookup = {
            trace.get("trace_id"): idx for idx, trace in enumerate(self.traces)
        }
        self.cluster_representatives = self._select_cluster_representatives()

    def _load_results(self) -> Dict[str, Any]:
        with self.results_path.open("rb") as fh:
            return pickle.load(fh)

    def _select_cluster_representatives(self) -> Dict[int, Representative]:
        representatives: Dict[int, Representative] = {}
        for idx, trace in enumerate(self.traces):
            cluster_id = trace.get("cluster")
            if cluster_id in (None, -1):
                continue
            sequence = self.numeric_sequences[idx]
            if sequence.size == 0:
                continue
            silhouette = trace.get("silhouette_score")
            score = (
                float(silhouette)
                if silhouette is not None and not np.isnan(silhouette)
                else float("-inf")
            )
            best = representatives.get(cluster_id)
            if best is None or score > best.score:
                representatives[int(cluster_id)] = Representative(
                    trace_index=idx,
                    trace_id=trace.get("trace_id"),
                    sequence=sequence,
                    event_sequence=trace.get("event_sequence") or self.raw_sequences[idx],
                    score=score,
                    script_url=trace.get("script_url"),
                    num_events=trace.get("num_events"),
                )
        return representatives

    def build(self) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
        start = time.perf_counter()
        alignments: Dict[str, Dict[str, Any]] = {}
        errors = 0
        global_error = None
        if subsequence_alignment is None:
            global_error = (
                "Subsequence alignment requires dtaidistance>=2.3.0. "
                "Install it and rerun precompute_subsequence_alignments.py."
            )
            print("[WARN] dtaidistance not available - caching informative errors instead.")

        for trace in tqdm(self.traces, desc="Computing DTW cache"):
            trace_id = trace.get("trace_id")
            if not trace_id:
                continue
            trace_idx = self.trace_index_lookup.get(trace_id)
            if trace_idx is None:
                alignments[trace_id] = {"error": "Trace index lookup failed."}
                errors += 1
                continue
            info = self._compute_alignment(trace, trace_idx, global_error)
            if info.get("error"):
                errors += 1
            alignments[trace_id] = info

        elapsed = time.perf_counter() - start
        stat = self.results_path.stat()
        metadata = {
            "cache_version": CACHE_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "results_path": str(self.results_path),
            "results_mtime": stat.st_mtime,
            "results_size": stat.st_size,
            "num_traces": len(self.traces),
            "library": "dtaidistance" if subsequence_alignment else "unavailable",
            "max_heatmap_cells": self.max_heatmap_cells,
            "build_seconds": elapsed,
            "cached_entries": len(alignments),
            "cached_errors": errors,
        }
        return alignments, metadata

    def _compute_alignment(
        self,
        trace: Dict[str, Any],
        trace_idx: int,
        global_error: Optional[str],
    ) -> Dict[str, Any]:
        trace_id = trace.get("trace_id")
        if not trace_id:
            return {"error": "Trace ID missing; cannot compute alignment."}
        if global_error:
            return {"error": global_error}

        cluster_id = trace.get("cluster")
        if cluster_id in (None, -1):
            return {"error": "Noise/outlier traces skip subsequence alignment."}

        representative = self.cluster_representatives.get(int(cluster_id))
        if not representative:
            return {"error": f"No representative trace recorded for cluster {cluster_id}."}

        series = self.numeric_sequences[trace_idx]
        query = representative.sequence
        if series.size == 0 or query.size == 0:
            return {"error": "One of the sequences is empty; DTW alignment skipped."}

        series_list = series.tolist()
        query_list = query.tolist()

        try:
            sa = subsequence_alignment(query_list, series_list)
            match = sa.best_match()
        except Exception as exc:  # noqa: BLE001
            return {"error": f"Subsequence alignment failed: {exc}"}

        if not match or not match.segment:
            return {"error": "DTW did not return a valid subsequence match."}

        start_idx, end_idx = match.segment
        start_idx = int(start_idx)
        end_idx = int(end_idx)
        matched_len = max(end_idx - start_idx + 1, 0)
        series_len = len(series_list)
        head_len = max(start_idx, 0)
        tail_len = max(series_len - end_idx - 1, 0)
        coverage = matched_len / series_len if series_len else 0.0
        normalized_distance = match.distance / matched_len if matched_len else None

        trace_events = trace.get("event_sequence") or self.raw_sequences[trace_idx]
        ref_events = representative.event_sequence
        matched_events = trace_events[start_idx : end_idx + 1] if matched_len else []
        tail_events = trace_events[end_idx + 1 :] if (end_idx + 1) < len(trace_events) else []
        leading_events = trace_events[:start_idx] if start_idx > 0 else []

        target_cells = (len(query_list) + 1) * (len(series_list) + 1)
        warping_paths = None
        heatmap_reason = None
        if target_cells <= self.max_heatmap_cells:
            try:
                warping_paths = np.asarray(sa.warping_paths()).tolist()
            except Exception as exc:  # noqa: BLE001
                heatmap_reason = f"Failed to compute warping matrix: {exc}"
        else:
            heatmap_reason = (
                f"Warping path heatmap skipped "
                f"({target_cells:,} cells exceed limit of {self.max_heatmap_cells:,})."
            )

        path_points = []
        if match.path:
            for row, col in match.path:
                path_points.append((int(row), int(col)))

        return {
            "cluster_id": int(cluster_id),
            "representative_trace_id": representative.trace_id,
            "representative_script_url": representative.script_url,
            "representative_num_events": representative.num_events,
            "reference_score": representative.score,
            "start_index": start_idx,
            "end_index": end_idx,
            "matched_length": matched_len,
            "series_length": series_len,
            "head_length": head_len,
            "tail_length": tail_len,
            "coverage_ratio": coverage,
            "distance": float(match.distance),
            "normalized_distance": float(normalized_distance) if normalized_distance is not None else None,
            "path": path_points,
            "warping_paths": warping_paths,
            "warping_paths_reason": heatmap_reason,
            "matched_events": matched_events,
            "tail_events": tail_events,
            "leading_events": leading_events,
            "reference_events": ref_events,
        }


def maybe_skip_build(results_path: Path, output_path: Path, force: bool) -> bool:
    """Return True if we can safely skip rebuilding the cache."""
    if not output_path.exists() or force:
        return False

    alignments, metadata = load_alignment_cache(output_path)
    if not alignments:
        return False
    if cache_is_stale(metadata, results_path):
        return False

    print(f"Subsequence cache at {output_path} already up-to-date. Use --force to rebuild.")
    return True


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Precompute subsequence DTW alignments for clustered traces."
    )
    parser.add_argument(
        "--results",
        default="clustering_results.pkl",
        help="Path to clustering results (pickle).",
    )
    parser.add_argument(
        "--output",
        help="Explicit output path for the alignment cache. Defaults to <results>_subsequence_cache.pkl.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rebuild the cache even if it appears up-to-date.",
    )

    args = parser.parse_args(argv)
    results_path = Path(args.results).resolve()
    if not results_path.exists():
        print(f"Results file not found: {results_path}")
        return 1

    output_path = Path(args.output).resolve() if args.output else default_cache_path(results_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if maybe_skip_build(results_path, output_path, args.force):
        return 0

    builder = AlignmentCacheBuilder(results_path, output_path, MAX_DTW_HEATMAP_CELLS)
    alignments, metadata = builder.build()
    payload = {
        "version": CACHE_VERSION,
        "metadata": metadata,
        "alignments": alignments,
    }

    with output_path.open("wb") as fh:
        pickle.dump(payload, fh)

    print("")
    print(f"[OK] Cached {len(alignments)} trace alignments to {output_path}")
    error_count = metadata.get("cached_errors", 0)
    if error_count:
        print(f"  ↳ {error_count} entries contain errors (see cache for details).")
    print(f"  ↳ Build time: {metadata.get('build_seconds', 0):.1f}s")
    print(f"  ↳ Library: {metadata.get('library')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
