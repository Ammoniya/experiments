#!/usr/bin/env python3
"""
Precompute (and cache) t-SNE embeddings for clustering results.
Attempts to use a multi-core implementation when available.
"""

from __future__ import annotations

import argparse
import os
import pickle
import sys
import time
from multiprocessing import cpu_count
from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np


def detect_job_count(requested: int | None) -> int:
    if requested and requested > 0:
        return requested
    try:
        return max(1, cpu_count() - 1)
    except NotImplementedError:
        return 1


def load_results(path: Path) -> Dict[str, Any]:
    with path.open("rb") as fh:
        return pickle.load(fh)


def save_results(path: Path, results: Dict[str, Any]) -> None:
    tmp_path = path.with_suffix(".tmp")
    with tmp_path.open("wb") as fh:
        pickle.dump(results, fh)
    tmp_path.replace(path)


def compute_tsne(distance_matrix: np.ndarray, perplexity: float, jobs: int, seed: int) -> Tuple[np.ndarray, Dict[str, Any]]:
    """Compute t-SNE embeddings using the best available implementation."""
    dm = np.asarray(distance_matrix, dtype=float)
    n = dm.shape[0]
    if dm.ndim != 2 or dm.shape[1] != n:
        raise ValueError("Distance matrix must be a square matrix")

    method = None
    meta: Dict[str, Any] = {
        "perplexity": perplexity,
        "jobs": jobs,
        "random_state": seed,
        "n_samples": int(n),
    }

    # Try MulticoreTSNE first
    try:
        from MulticoreTSNE import MulticoreTSNE  # type: ignore

        print(f"Using MulticoreTSNE with {jobs} job(s)...")
        tsne = MulticoreTSNE(
            n_components=3,
            metric="precomputed",
            perplexity=perplexity,
            n_jobs=jobs,
            random_state=seed,
            learning_rate="auto",
            early_exaggeration=12.0,
        )
        embeddings = tsne.fit_transform(dm)
        method = "MulticoreTSNE"
    except Exception as exc:  # noqa: BLE001
        print(f"MulticoreTSNE unavailable ({exc}).")
        embeddings = None

    # Try openTSNE next
    if embeddings is None:
        try:
            from openTSNE import TSNE as OpenTSNE  # type: ignore

            print(f"Using openTSNE with {jobs} job(s)...")
            tsne = OpenTSNE(
                n_components=3,
                perplexity=perplexity,
                metric="precomputed",
                n_jobs=jobs,
                random_state=seed,
                initialization="random",
            )
            embeddings = tsne.fit(dm)
            method = "openTSNE"
        except Exception as exc:  # noqa: BLE001
            print(f"openTSNE unavailable ({exc}).")
            embeddings = None

    # Fallback to sklearn (single-threaded)
    if embeddings is None:
        from sklearn.manifold import TSNE  # type: ignore

        print("Falling back to sklearn.manifold.TSNE (single-threaded).")
        tsne = TSNE(
            n_components=3,
            metric="precomputed",
            perplexity=perplexity,
            random_state=seed,
            init="random",
        )
        embeddings = tsne.fit_transform(dm)
        method = "sklearn_TSNE"
        meta["jobs"] = 1

    meta["method"] = method
    return np.asarray(embeddings, dtype=np.float32), meta


def main() -> int:
    parser = argparse.ArgumentParser(description="Precompute t-SNE embeddings for clustering results.")
    parser.add_argument("--results", default="clustering_results.pkl", help="Path to clustering results pickle.")
    parser.add_argument("--perplexity", type=float, default=float(os.environ.get("TSNE_PERPLEXITY", 30.0)),
                        help="t-SNE perplexity (default: 30 or TSNE_PERPLEXITY env var).")
    parser.add_argument("--jobs", type=int, default=int(os.environ.get("TSNE_JOBS", "0")),
                        help="Worker count for multi-core TSNE implementations.")
    parser.add_argument("--seed", type=int, default=int(os.environ.get("TSNE_RANDOM_STATE", "42")),
                        help="Random seed for deterministic embeddings.")
    parser.add_argument("--force", action="store_true",
                        help="Recompute embeddings even if cached ones exist.")
    args = parser.parse_args()

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"Results file not found: {results_path}", file=sys.stderr)
        return 1

    results = load_results(results_path)

    if not args.force and results.get("tsne_embeddings") is not None:
        print("Cached t-SNE embeddings already exist. Use --force to recompute.")
        return 0

    distance_matrix = results.get("distance_matrix")
    if distance_matrix is None:
        print("Distance matrix missing from results file; run clustering first.", file=sys.stderr)
        return 1

    jobs = detect_job_count(args.jobs)
    perplexity = max(5.0, float(args.perplexity))
    print(f"Computing t-SNE embeddings (perplexity={perplexity}, jobs={jobs}, seed={args.seed})...")

    start = time.time()
    embeddings, meta = compute_tsne(distance_matrix, perplexity, jobs, args.seed)
    elapsed = time.time() - start
    print(f"t-SNE computation completed in {elapsed:.1f}s using {meta['method']}.")

    results["tsne_embeddings"] = embeddings
    results["tsne_metadata"] = meta
    save_results(results_path, results)

    print(f"Cached embeddings saved into {results_path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

