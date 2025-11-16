#!/usr/bin/env python3
"""
Lightweight helpers for working with cached subsequence DTW alignment results.

The heavy lifting happens in precompute_subsequence_alignments.py.  This module
simply standardizes cache locations and loading/validation logic so other tools
can rely on the cached data without importing optional DTW dependencies.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Dict, Tuple

CACHE_VERSION = 1
CACHE_SUFFIX = "_subsequence_cache.pkl"


def default_cache_path(results_path: Path | str) -> Path:
    """Return the canonical cache path for a clustering results file."""
    path = Path(results_path)
    stem = path.stem
    return path.with_name(f"{stem}{CACHE_SUFFIX}")


def load_alignment_cache(cache_path: Path | str | None) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Load a cached alignment map from disk.

    Returns (alignments, metadata). Both will be empty dicts if the cache is
    missing, corrupted, or has an incompatible version.
    """
    if not cache_path:
        return {}, {}

    path = Path(cache_path)
    if not path.exists():
        return {}, {}

    try:
        with path.open("rb") as fh:
            payload = pickle.load(fh)
    except Exception as exc:  # noqa: BLE001
        print(f"[subsequence-cache] Failed to read {path}: {exc}")
        return {}, {}

    if not isinstance(payload, dict):
        print(f"[subsequence-cache] Unexpected payload type in {path}: {type(payload)}")
        return {}, {}

    version = payload.get("version")
    if version != CACHE_VERSION:
        print(f"[subsequence-cache] Cache {path} has version {version}; expected {CACHE_VERSION}. Ignoring.")
        return {}, {}

    alignments = payload.get("alignments")
    if not isinstance(alignments, dict):
        print(f"[subsequence-cache] Cache {path} missing 'alignments'.")
        return {}, {}

    metadata = payload.get("metadata") or {}
    return alignments, metadata


def cache_is_stale(metadata: Dict[str, Any], results_path: Path | str) -> bool:
    """Return True if the cache metadata no longer matches the results file."""
    if not metadata:
        return True

    path = Path(results_path)
    try:
        stat = path.stat()
    except OSError:
        return True

    cached_mtime = metadata.get("results_mtime")
    cached_size = metadata.get("results_size")
    cached_traces = metadata.get("num_traces")
    if cached_mtime is None or cached_size is None:
        return True

    if abs(float(cached_mtime) - float(stat.st_mtime)) > 1e-6:
        return True
    if int(cached_size) != int(stat.st_size):
        return True

    if cached_traces is not None:
        try:
            cached_traces = int(cached_traces)
        except Exception:
            return True
        if cached_traces <= 0:
            return True

    return False


__all__ = [
    "CACHE_VERSION",
    "CACHE_SUFFIX",
    "default_cache_path",
    "load_alignment_cache",
    "cache_is_stale",
]
