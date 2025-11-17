"""Utilities for computing per-cluster nearest neighbor summaries."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

import numpy as np


NeighborList = List[Dict[str, float]]
NeighborLookup = Dict[int, NeighborList]


def compute_cluster_neighbors(
    distance_matrix: Any,
    traces: Sequence[Mapping[str, Any]],
    limit: Optional[int] = 5,
) -> NeighborLookup:
    """Return for every cluster the closest other clusters using average distances."""
    lookup: NeighborLookup = {}
    if distance_matrix is None:
        return lookup

    matrix = np.asarray(distance_matrix)
    if matrix.ndim != 2 or matrix.shape[0] != len(traces):
        return lookup

    cluster_indices: Dict[int, List[int]] = defaultdict(list)
    for idx, trace in enumerate(traces):
        cluster_id = trace.get("cluster")
        if cluster_id in (None, -1):
            continue
        cluster_indices[int(cluster_id)].append(idx)

    for cluster_id, indices in cluster_indices.items():
        if not indices:
            lookup[cluster_id] = []
            continue
        entries: NeighborList = []
        for other_id, other_indices in cluster_indices.items():
            if other_id == cluster_id or not other_indices:
                continue
            block = matrix[np.ix_(indices, other_indices)]
            if block.size == 0:
                continue
            avg = float(np.nanmean(block))
            if math.isnan(avg):
                continue
            entries.append({"cluster_id": int(other_id), "distance": avg})
        entries.sort(key=lambda item: item["distance"])
        lookup[cluster_id] = entries if limit is None else entries[:limit]

    return lookup


def normalize_neighbor_mapping(raw_neighbors: Any) -> NeighborLookup:
    """Normalize stored neighbor mapping to int keyed dict of {cluster_id, distance}."""
    if not raw_neighbors:
        return {}

    normalized: NeighborLookup = {}

    if isinstance(raw_neighbors, Mapping):
        items = raw_neighbors.items()
    elif isinstance(raw_neighbors, Sequence):
        items = ((entry.get("cluster_id"), entry.get("neighbors")) for entry in raw_neighbors if isinstance(entry, MutableMapping))
    else:
        return {}

    for cluster_key, neighbors in items:
        try:
            cluster_id = int(cluster_key)
        except (TypeError, ValueError):
            continue
        parsed: NeighborList = []
        if isinstance(neighbors, Sequence):
            for entry in neighbors:
                if not isinstance(entry, Mapping):
                    continue
                other_id = entry.get("cluster_id")
                distance = entry.get("distance")
                try:
                    other_id = int(other_id)
                    distance = float(distance)
                except (TypeError, ValueError):
                    continue
                parsed.append({"cluster_id": other_id, "distance": distance})
        parsed.sort(key=lambda item: item["distance"])
        normalized[cluster_id] = parsed

    return normalized


__all__ = ["compute_cluster_neighbors", "normalize_neighbor_mapping"]
