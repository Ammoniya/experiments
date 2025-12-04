    #!/usr/bin/env python3
"""
Compute pairwise AST cosine similarities that stay index-aligned with the
cached DTW distance matrix (cache/dtw_matrix_latest.npz by default).

The script reuses the trace ordering from the DTW cache so ast_sim[X, Y]
lines up with dtw_dist[X, Y] for every trace pair. Results are written as
an NPZ file containing:
    - similarity_matrix: float32 dense matrix with cosine similarities
    - trace_ids: numpy array of trace identifiers (same order as DTW cache)
"""

from __future__ import annotations

import argparse
import gc
import logging
import pickle
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics.pairwise import cosine_similarity


LOGGER = logging.getLogger("ast_similarity")
AST_MATRIX_GLOBAL = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compute DTW-aligned AST cosine similarity matrix."
    )
    parser.add_argument(
        "--results",
        default="cache/all-15/clustering_results.pkl",
        help="Path to clustering_results.pkl (default: %(default)s)",
    )
    parser.add_argument(
        "--dtw-cache",
        default="cache/dtw_matrix_latest.npz",
        help="DTW cache NPZ used to harvest trace ordering (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        default="cache/ast_matrix_latest.npz",
        help="Output NPZ file for AST similarities (default: %(default)s)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=256,
        help="Row chunk size when materializing the dense similarity matrix.",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=max(cpu_count() - 1, 1),
        help="Worker threads that compute similarity chunks (default: CPU-1).",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (default: %(default)s)",
    )
    return parser.parse_args()


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def load_dtw_trace_ids(path: Path) -> Tuple[np.ndarray, Tuple[int, int]]:
    if not path.exists():
        raise FileNotFoundError(f"DTW cache not found at {path}")

    LOGGER.info("Reading DTW cache metadata from %s", path)
    with np.load(path, mmap_mode="r") as data:
        trace_ids = data["trace_ids"]
        distance_shape = tuple(int(x) for x in data["distance_matrix"].shape)
    LOGGER.info(
        "DTW cache contains %d traces (%dx%d distance grid)",
        len(trace_ids),
        distance_shape[0],
        distance_shape[1],
    )
    return trace_ids, distance_shape


def load_trace_vectors(
    pickle_path: Path, expected_ids: Sequence[str]
) -> Dict[str, Dict[str, float]]:
    if not pickle_path.exists():
        raise FileNotFoundError(f"clustering_results.pkl not found at {pickle_path}")

    LOGGER.info("Loading clustering results from %s", pickle_path)
    with pickle_path.open("rb") as handle:
        results = pickle.load(handle)

    traces = results.get("traces") or []
    LOGGER.info("Loaded %d traces from pickle payload", len(traces))

    # Drop large, not-needed blobs so GC can reclaim memory sooner.
    for heavy_key in (
        "distance_matrix",
        "encoded_sequences",
        "sequences",
        "capability_sequences",
        "embedding_matrix",
        "token_embeddings",
        "clusters",
    ):
        results.pop(heavy_key, None)
    del results
    gc.collect()

    vector_lookup: Dict[str, Dict[str, float]] = {}
    for trace in traces:
        trace_id = trace.get("trace_id")
        vector = trace.get("ast_unit_vector")
        if not trace_id or not isinstance(vector, dict):
            continue
        vector_lookup[trace_id] = {str(k): float(v) for k, v in vector.items()}

    missing: List[str] = [
        trace_id for trace_id in expected_ids if trace_id not in vector_lookup
    ]
    if missing:
        sample = ", ".join(missing[:5])
        raise RuntimeError(
            f"{len(missing)} trace(s) from DTW cache missing AST vectors. "
            f"Sample missing IDs: {sample}"
        )
    LOGGER.info("AST vectors available for all %d DTW traces", len(expected_ids))
    return vector_lookup


def build_feature_matrix(
    trace_ids: Sequence[str],
    vector_lookup: Dict[str, Dict[str, float]],
) -> np.ndarray:
    LOGGER.info("Vectorizing AST fingerprints for %d traces", len(trace_ids))
    samples: List[Dict[str, float]] = [vector_lookup[trace_id] for trace_id in trace_ids]

    vectorizer = DictVectorizer(sparse=True)
    sparse_matrix = vectorizer.fit_transform(samples).astype(np.float32)
    LOGGER.info(
        "Feature matrix shape: %s (sparse nnz=%d)",
        sparse_matrix.shape,
        sparse_matrix.nnz,
    )
    return sparse_matrix


def _compute_chunk(start: int, end: int) -> Tuple[int, np.ndarray]:
    if AST_MATRIX_GLOBAL is None:
        raise RuntimeError("AST matrix was not initialized in worker thread")
    block = cosine_similarity(
        AST_MATRIX_GLOBAL[start:end], AST_MATRIX_GLOBAL, dense_output=True
    )
    block = block.astype(np.float32, copy=False)
    np.clip(block, -1.0, 1.0, out=block)
    return start, block


def compute_similarity_matrix(
    ast_matrix,
    chunk_size: int,
    max_workers: int,
) -> np.ndarray:
    n_rows = ast_matrix.shape[0]
    LOGGER.info(
        "Allocating dense similarity matrix (%dx%d, %.2f GiB)",
        n_rows,
        n_rows,
        (n_rows * n_rows * 4) / (1024**3),
    )
    similarity = np.empty((n_rows, n_rows), dtype=np.float32)

    global AST_MATRIX_GLOBAL
    AST_MATRIX_GLOBAL = ast_matrix

    ranges: List[Tuple[int, int]] = []
    for start in range(0, n_rows, chunk_size):
        ranges.append((start, min(start + chunk_size, n_rows)))

    if max_workers <= 1:
        LOGGER.info("Computing similarity chunks serially")
        for idx, (start, end) in enumerate(ranges, 1):
            _, block = _compute_chunk(start, end)
            similarity[start:end, :] = block
            LOGGER.info(
                "Completed %d/%d chunks (%.1f%%)",
                idx,
                len(ranges),
                (idx / len(ranges)) * 100.0,
            )
    else:
        LOGGER.info("Spawning %d worker thread(s) for AST similarity", max_workers)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_compute_chunk, start, end): (start, end)
                for start, end in ranges
            }
            for idx, future in enumerate(as_completed(futures), 1):
                start, block = future.result()
                similarity[start : start + block.shape[0], :] = block
                LOGGER.info(
                    "Completed %d/%d chunks (%.1f%%)",
                    idx,
                    len(ranges),
                    (idx / len(ranges)) * 100.0,
                )

    np.fill_diagonal(similarity, 1.0)
    AST_MATRIX_GLOBAL = None
    return similarity


def save_similarity_matrix(
    path: Path,
    similarity: np.ndarray,
    trace_ids: Sequence[str],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.info("Writing AST similarity matrix to %s", path)
    np.savez_compressed(path, similarity_matrix=similarity, trace_ids=np.asarray(trace_ids))


def main() -> None:
    args = parse_args()
    setup_logging(args.log_level)

    dtw_trace_ids, dtw_shape = load_dtw_trace_ids(Path(args.dtw_cache))
    results_lookup = load_trace_vectors(Path(args.results), dtw_trace_ids)

    ast_matrix = build_feature_matrix(dtw_trace_ids, results_lookup)
    similarity = compute_similarity_matrix(ast_matrix, args.chunk_size, args.max_workers)

    if similarity.shape != dtw_shape:
        raise RuntimeError(
            "AST similarity matrix shape %s does not match DTW matrix shape %s"
            % (similarity.shape, dtw_shape)
        )

    save_similarity_matrix(Path(args.output), similarity, dtw_trace_ids)
    LOGGER.info("AST similarity cache ready: %s", args.output)


if __name__ == "__main__":
    main()
