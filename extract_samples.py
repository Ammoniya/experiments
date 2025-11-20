#!/usr/bin/env python3
"""
Scan cached cluster reports and copy representative JavaScript samples for high-risk clusters.

Selection rules:
- Only clusters with strong obfuscation/eval indicators are considered.
- Samples are grouped by AST preview so we prioritize diverse implementations.
- Homogeneous clusters (≤3 ASTs) get at most 3 samples; diverse clusters get up to 15
  unique ASTs (or as many as available).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

# Keywords that often indicate heavy obfuscation or dynamic execution.
SUSPICIOUS_EVENT_KEYWORDS = [
    "atob",
    "btoa",
    "fromcharcode",
    "function constructor",
    "function(",
    "eval",
    "unescape",
    "document.write",
    "settimeout (string",
    "setinterval (string",
    "script element injected",
]

# Capability labels that should boost suspicion when present repeatedly.
SUSPICIOUS_CAPABILITIES = {
    "OBFUSCATION",
    "DOM_INJECT_HTML",
    "DOM_MUTATION",
    "HOOKING",
}

WORDPRESS_PATH_MARKERS = ("wp-content", "wp-includes", "wp-admin", "wp-json", "wordpress")


def load_json(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def compute_trace_score(trace: Dict) -> float:
    """Score how suspicious a trace looks."""
    score = float(trace.get("suspicious_event_count") or 0)

    for cap in trace.get("capability_summary") or []:
        capability = cap.get("capability")
        if capability in SUSPICIOUS_CAPABILITIES:
            score += 2.0 * float(cap.get("count") or 0)

    for event in trace.get("event_distribution") or []:
        event_name = (event.get("event") or "").lower()
        if any(keyword in event_name for keyword in SUSPICIOUS_EVENT_KEYWORDS):
            score += 3.0 * float(event.get("count") or 0)

    preview_text = " ".join(trace.get("event_sequence_preview") or []).lower()
    if any(keyword in preview_text for keyword in SUSPICIOUS_EVENT_KEYWORDS):
        score += 5.0

    capability_counts = trace.get("capability_counts") or {}
    score += 0.5 * float(capability_counts.get("OBFUSCATION") or 0)

    return score


def ast_bucket_key(trace: Dict) -> str:
    """Return a stable hash that groups traces sharing the same AST preview."""
    preview = trace.get("ast_preview")
    if isinstance(preview, str) and preview:
        return hashlib.sha1(preview.encode("utf-8")).hexdigest()

    script_sha = trace.get("script_sha256")
    if script_sha:
        return str(script_sha)

    return str(trace.get("trace_id"))


def choose_traces_by_ast(traces: Sequence[Dict], trace_scores: Dict[str, float]) -> List[Dict]:
    """Pick AST-diverse traces from a cluster."""
    grouped: Dict[str, List[Dict]] = {}
    for trace in traces:
        grouped.setdefault(ast_bucket_key(trace), []).append(trace)

    ast_count = len(grouped)
    total_traces = len(traces)
    if ast_count <= 3:
        target = min(3, total_traces)
    else:
        target = min(15, total_traces)
        if target < 10 and ast_count >= 10 and total_traces >= 10:
            target = 10

    group_items: List[Tuple[str, List[Dict], float]] = []
    for ast_hash, group in grouped.items():
        best_score = max(trace_scores.get(trace["trace_id"], 0.0) for trace in group)
        group_items.append((ast_hash, group, best_score))
    group_items.sort(key=lambda item: item[2], reverse=True)

    selected: List[Dict] = []
    selected_ids = set()
    unique_limit = min(target, len(group_items))

    for _, group, _ in group_items[:unique_limit]:
        best_trace = max(group, key=lambda t: trace_scores.get(t["trace_id"], 0.0))
        selected.append(best_trace)
        selected_ids.add(best_trace["trace_id"])

    if len(selected) >= target:
        return selected

    remaining_candidates: List[Dict] = []
    for _, group, _ in group_items:
        sorted_group = sorted(group, key=lambda t: trace_scores.get(t["trace_id"], 0.0), reverse=True)
        for entry in sorted_group:
            if entry["trace_id"] not in selected_ids:
                remaining_candidates.append(entry)

    for trace in remaining_candidates:
        if len(selected) >= target:
            break
        selected.append(trace)
        selected_ids.add(trace["trace_id"])

    return selected


@dataclass
class ClusterSelection:
    cache_key: str
    cache_dir: Path
    cluster_id: str
    cluster_score: float
    suspicious_call_count: int
    selected_traces: List[Dict]
    trace_scores: Dict[str, float]


def copy_trace(trace: Dict, dest_dir: Path, idx: int) -> Tuple[bool, str]:
    """Copy a single script file into the destination directory."""
    source = Path(trace.get("script_path") or "")
    if not source.exists():
        return False, f"Missing script file: {source}"

    dest_dir.mkdir(parents=True, exist_ok=True)

    sha = trace.get("script_sha256") or "unknown"
    filename = f"{idx:02d}_{trace.get('trace_id')}_{sha[:12]}.js"
    target = dest_dir / filename
    shutil.copy2(source, target)
    return True, filename


def write_manifest(selection: ClusterSelection, trace_scores: Dict[str, float], cluster_dir: Path) -> None:
    manifest = {
        "cache_key": selection.cache_key,
        "cluster_id": selection.cluster_id,
        "cluster_score": selection.cluster_score,
        "suspicious_call_count": selection.suspicious_call_count,
        "sample_count": len(selection.selected_traces),
        "traces": [
            {
                "trace_id": trace["trace_id"],
                "score": trace_scores.get(trace["trace_id"], 0.0),
                "script_url": trace.get("script_url"),
                "page_url": trace.get("page_url"),
                "script_sha256": trace.get("script_sha256"),
                "script_path": trace.get("script_path"),
                "suspicious_event_count": trace.get("suspicious_event_count"),
                "capabilities": trace.get("capability_summary"),
            }
            for trace in selection.selected_traces
        ],
    }
    with (cluster_dir / "manifest.json").open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)


def should_keep_cluster(trace_scores: Dict[str, float], min_cluster_score: float, min_trace_score: float, min_trace_hits: int) -> bool:
    if not trace_scores:
        return False
    cluster_score = sum(trace_scores.values()) / len(trace_scores)
    if cluster_score >= min_cluster_score:
        return True
    high_traces = sum(1 for score in trace_scores.values() if score >= min_trace_score)
    return high_traces >= min_trace_hits


def is_wordpress_trace(trace: Dict) -> bool:
    combined_path = f"{trace.get('script_url') or ''} {trace.get('script_path') or ''}".lower()
    return any(marker in combined_path for marker in WORDPRESS_PATH_MARKERS)


def apply_trace_filters(traces: Sequence[Dict], args: argparse.Namespace) -> List[Dict]:
    wordpress_threshold = getattr(args, "wordpress_malicious_threshold", None)
    if wordpress_threshold is None:
        return list(traces)

    filtered: List[Dict] = []
    for trace in traces:
        if not is_wordpress_trace(trace):
            continue
        suspicious_calls = int(trace.get("suspicious_event_count") or 0)
        if suspicious_calls >= wordpress_threshold:
            filtered.append(trace)
    return filtered


def iterate_cluster_selections(
    cache_dir: Path,
    cache_key: str,
    report_path: Path,
    thresholds: argparse.Namespace,
) -> Iterable[ClusterSelection]:
    report = load_json(report_path)
    for cluster in report.get("clusters", []):
        traces = cluster.get("traces") or []
        traces = apply_trace_filters(traces, thresholds)
        if not traces:
            continue

        trace_scores = {trace["trace_id"]: compute_trace_score(trace) for trace in traces}
        if not should_keep_cluster(
            trace_scores,
            thresholds.min_cluster_score,
            thresholds.min_trace_score,
            thresholds.min_trace_hits,
        ):
            continue

        selected = choose_traces_by_ast(traces, trace_scores)
        if not selected:
            continue

        cluster_id = str(cluster.get("cluster_id"))
        cluster_score = sum(trace_scores.values()) / len(trace_scores)
        suspicious_call_count = sum(int(trace.get("suspicious_event_count") or 0) for trace in traces)
        yield ClusterSelection(
            cache_key=cache_key,
            cache_dir=cache_dir,
            cluster_id=cluster_id,
            cluster_score=cluster_score,
            suspicious_call_count=suspicious_call_count,
            selected_traces=selected,
            trace_scores=trace_scores,
        )


def find_cache_key(cache_dir: Path) -> str:
    config_path = cache_dir / "cache_config.json"
    if config_path.exists():
        config = load_json(config_path)
        return str(config.get("cache_key") or cache_dir.name)
    return cache_dir.name


def process_cache(cache_dir: Path, output_root: Path, thresholds: argparse.Namespace) -> Tuple[int, int]:
    report_path = cache_dir / "cluster_report.json"
    if not report_path.exists():
        return 0, 0

    cache_key = find_cache_key(cache_dir)
    total_clusters = 0
    total_files = 0

    selections = list(iterate_cluster_selections(cache_dir, cache_key, report_path, thresholds))
    if not selections:
        return 0, 0

    cache_output_dir = output_root / cache_key
    cache_output_dir.mkdir(parents=True, exist_ok=True)

    ranked_selections = sorted(
        selections,
        key=lambda s: (s.suspicious_call_count, s.cluster_score),
        reverse=True,
    )

    for rank, selection in enumerate(ranked_selections, 1):
        cluster_dir = cache_output_dir / f"{rank}-cluster-{selection.cluster_id}"
        copied = 0
        for idx, trace in enumerate(selection.selected_traces, 1):
            ok, message = copy_trace(trace, cluster_dir, idx)
            if ok:
                copied += 1
            else:
                print(f"[WARN] {message}", file=sys.stderr)
        if copied:
            write_manifest(selection, selection.trace_scores, cluster_dir)
            total_clusters += 1
            total_files += copied
            print(
                "[INFO] Copied "
                f"{copied} samples for cache {cache_key} cluster {selection.cluster_id} "
                f"(rank {rank}, suspicious calls: {selection.suspicious_call_count}) -> {cluster_dir}"
            )

    return total_clusters, total_files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract suspicious JavaScript samples from cache reports.")
    parser.add_argument("--cache-root", default="cache", help="Directory containing cache subfolders.")
    parser.add_argument("--output-root", default="samples", help="Destination root for copied scripts.")
    parser.add_argument("--min-cluster-score", type=float, default=20.0, help="Minimum average cluster score to keep.")
    parser.add_argument("--min-trace-score", type=float, default=35.0, help="Minimum per-trace score to count toward the threshold.")
    parser.add_argument("--min-trace-hits", type=int, default=2, help="Minimum number of high-scoring traces needed when the cluster average is low.")
    parser.add_argument(
        "--wordpress-malicious-threshold",
        type=int,
        default=None,
        help=(
            "Only copy traces whose script URL/path references WordPress assets "
            "and have at least this many suspicious (malicious API) events."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cache_root = Path(args.cache_root)
    output_root = Path(args.output_root)
    if not cache_root.exists():
        raise SystemExit(f"Cache root not found: {cache_root}")

    processed_clusters = 0
    copied_files = 0
    for cache_dir in sorted(cache_root.iterdir()):
        if not cache_dir.is_dir():
            continue
        clusters, files = process_cache(cache_dir, output_root, args)
        processed_clusters += clusters
        copied_files += files

    print(f"\nDone. Extracted {copied_files} scripts across {processed_clusters} clusters into {output_root}/")


if __name__ == "__main__":
    main()
