#!/usr/bin/env python3
"""
Locate the cluster ID for one or more trace IDs within a cached cluster report.

Example:
    python search.py --cluster-cache cache/all-3 --trace-id TRACE_ID
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find which cluster a given trace ID belongs to.")
    parser.add_argument(
        "--cluster-cache",
        required=True,
        help="Path to the cache directory (e.g., cache/all-3) containing cluster_report.json.",
    )
    parser.add_argument(
        "--trace-id",
        action="append",
        dest="trace_ids",
        required=True,
        help="Trace ID to search for. Repeat this flag to search for multiple IDs.",
    )
    return parser.parse_args()


def load_report(cache_dir: Path) -> Dict:
    report_path = cache_dir / "cluster_report.json"
    if not report_path.exists():
        raise SystemExit(f"No cluster_report.json found in {cache_dir}")
    with report_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def find_trace_clusters(report: Dict, trace_ids: List[str]) -> Dict[str, Optional[int]]:
    remaining = {trace_id: None for trace_id in trace_ids}
    pending = {trace_id for trace_id in trace_ids}
    for cluster in report.get("clusters", []):
        traces = cluster.get("traces") or []
        cluster_id = cluster.get("cluster_id")
        for trace in traces:
            trace_id = str(trace.get("trace_id") or "")
            if trace_id in pending:
                remaining[trace_id] = cluster_id
                pending.remove(trace_id)
                if not pending:
                    return remaining
    return remaining


def main() -> None:
    args = parse_args()
    cache_dir = Path(args.cluster_cache)
    if not cache_dir.exists():
        raise SystemExit(f"Cache directory not found: {cache_dir}")

    trace_ids = [trace_id.strip() for trace_id in args.trace_ids if trace_id and trace_id.strip()]
    if not trace_ids:
        raise SystemExit("No valid trace IDs supplied.")

    report = load_report(cache_dir)
    mapping = find_trace_clusters(report, trace_ids)

    missing: List[str] = []
    for trace_id, cluster_id in mapping.items():
        if cluster_id is None:
            missing.append(trace_id)
            print(f"{trace_id}: NOT FOUND", file=sys.stderr)
        else:
            print(f"{trace_id}: cluster {cluster_id}")

    if missing:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
