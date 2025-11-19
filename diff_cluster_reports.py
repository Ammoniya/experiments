#!/usr/bin/env python3
"""
Compare two cached cluster reports and highlight how trace assignments changed.

Usage:
    ./diff_cluster_reports.py 20251112-3 20251112-5

The script inspects cache/<key>/cluster_report.json for each key and prints:
- Trace-level movements (added, removed, cluster reassignments)
- Cluster reshaping hints (potential merges and splits based on membership overlap)
- Basic stats to quickly gauge how different the runs are
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple


@dataclass(frozen=True)
class TraceRecord:
    trace_id: str
    cluster_id: int
    data: Mapping[str, Any]

    def describe(self) -> str:
        script_url = self.data.get("script_url") or "?"
        page_url = self.data.get("page_url") or "?"
        sha = self.data.get("script_sha256") or "?"
        return f"{self.trace_id} | cluster {self.cluster_id} | script={script_url} | page={page_url} | sha={sha[:12]}"


def load_report(cache_root: Path, cache_key: str) -> Dict[str, Any]:
    report_path = cache_root / cache_key / "cluster_report.json"
    if not report_path.exists():
        raise FileNotFoundError(f"Missing cluster report for cache key {cache_key}: {report_path}")
    with report_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def flatten_traces(report: Mapping[str, Any]) -> MutableMapping[str, TraceRecord]:
    trace_map: MutableMapping[str, TraceRecord] = {}
    for cluster in report.get("clusters", []):
        cluster_id = int(cluster.get("cluster_id", -1))
        for trace in cluster.get("traces", []):
            trace_id = str(trace.get("trace_id"))
            if not trace_id:
                continue
            trace_map[trace_id] = TraceRecord(
                trace_id=trace_id,
                cluster_id=cluster_id,
                data=trace,
            )
    return trace_map


def build_cluster_memberships(traces: Mapping[str, TraceRecord]) -> Dict[int, set[str]]:
    membership: Dict[int, set[str]] = {}
    for trace_id, record in traces.items():
        membership.setdefault(record.cluster_id, set()).add(trace_id)
    return membership


def summarize_trace_changes(
    old_traces: Mapping[str, TraceRecord],
    new_traces: Mapping[str, TraceRecord],
) -> Tuple[List[Tuple[TraceRecord, TraceRecord]], List[TraceRecord], List[TraceRecord]]:
    moved: List[Tuple[TraceRecord, TraceRecord]] = []
    for trace_id in sorted(set(old_traces) & set(new_traces)):
        old_rec = old_traces[trace_id]
        new_rec = new_traces[trace_id]
        if old_rec.cluster_id != new_rec.cluster_id:
            moved.append((old_rec, new_rec))

    removed = [old_traces[tid] for tid in sorted(set(old_traces) - set(new_traces))]
    added = [new_traces[tid] for tid in sorted(set(new_traces) - set(old_traces))]
    return moved, removed, added


def cluster_contributions(
    source_clusters: Mapping[int, Sequence[str]],
    target_clusters: Mapping[int, Sequence[str]],
) -> Dict[int, List[Dict[str, Any]]]:
    contributions: Dict[int, List[Dict[str, Any]]] = {}
    for target_id, target_members in target_clusters.items():
        target_set = set(target_members)
        entries: List[Dict[str, Any]] = []
        target_size = len(target_set)
        if target_size == 0:
            contributions[target_id] = []
            continue
        for source_id, source_members in source_clusters.items():
            shared = target_set & set(source_members)
            if not shared:
                continue
            source_size = len(source_members)
            entries.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "shared": len(shared),
                    "source_fraction": len(shared) / source_size if source_size else 0.0,
                    "target_fraction": len(shared) / target_size,
                }
            )
        entries.sort(key=lambda item: item["shared"], reverse=True)
        contributions[target_id] = entries
    return contributions


def summarize_merges(
    contributions: Mapping[int, Sequence[Dict[str, Any]]],
    new_membership: Mapping[int, Sequence[str]],
    min_fraction: float,
    min_shared: int,
) -> List[str]:
    messages: List[str] = []
    for new_cluster, entries in contributions.items():
        major = [
            e
            for e in entries
            if e["target_fraction"] >= min_fraction and e["shared"] >= min_shared
        ]
        if len(major) < 2:
            continue
        parts = [f"new {new_cluster} ({len(new_membership.get(new_cluster, []))} traces) <= "]
        details = [
            f"{e['shared']} from old {e['source']} ({e['target_fraction']*100:.1f}% of new cluster)"
            for e in major
        ]
        messages.append("".join(parts) + ", ".join(details))
    return messages


def summarize_splits(
    contributions: Mapping[int, Sequence[Dict[str, Any]]],
    old_membership: Mapping[int, Sequence[str]],
    min_fraction: float,
    min_shared: int,
) -> List[str]:
    messages: List[str] = []
    for old_cluster, entries in contributions.items():
        major = [
            e
            for e in entries
            if e["target_fraction"] >= min_fraction and e["shared"] >= min_shared
        ]
        if len(major) < 2:
            continue
        details = [
            f"{e['shared']} to new {e['source']} ({e['target_fraction']*100:.1f}% of old cluster)"
            for e in major
        ]
        messages.append(
            f"old {old_cluster} ({len(old_membership.get(old_cluster, []))} traces) => " + ", ".join(details)
        )
    return messages


def format_section(title: str) -> None:
    print(f"\n=== {title} ===")


def safe_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def extract_cluster_metric(report: Mapping[str, Any], field: str) -> Dict[int, float | None]:
    metrics: Dict[int, float | None] = {}
    for cluster in report.get("clusters", []):
        cluster_id = int(cluster.get("cluster_id", -1))
        metrics[cluster_id] = safe_float(cluster.get(field))
    return metrics


def extract_cluster_silhouettes(report: Mapping[str, Any]) -> Dict[int, float | None]:
    return extract_cluster_metric(report, "silhouette")


def extract_cluster_ast_similarity(report: Mapping[str, Any]) -> Dict[int, float | None]:
    return extract_cluster_metric(report, "ast_similarity")


def fmt_value(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def fmt_delta(value: float | None) -> str:
    return "-" if value is None else f"{value:+.3f}"


def format_pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    if not rows:
        print("No clusters to compare.")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))
    header_line = "  ".join(headers[idx].ljust(widths[idx]) for idx in range(len(headers)))
    divider = "  ".join("-" * widths[idx] for idx in range(len(headers)))
    print(header_line)
    print(divider)
    for row in rows:
        print("  ".join(row[idx].ljust(widths[idx]) for idx in range(len(headers))))


def build_metric_rows(
    old_metrics: Mapping[int, float | None],
    new_metrics: Mapping[int, float | None],
) -> Tuple[List[List[str]], Dict[str, int]]:
    EPS = 1e-9
    stats = {"improved": 0, "decayed": 0, "stable": 0, "new": 0, "removed": 0}
    rows: List[List[str]] = []
    cluster_ids = sorted(set(old_metrics) | set(new_metrics))
    for cluster_id in cluster_ids:
        old_val = old_metrics.get(cluster_id)
        new_val = new_metrics.get(cluster_id)
        status = "stable"
        delta: float | None = None
        if old_val is None and new_val is None:
            continue
        if old_val is None:
            status = "new cluster"
            stats["new"] += 1
        elif new_val is None:
            status = "removed cluster"
            stats["removed"] += 1
        else:
            delta = new_val - old_val
            if delta > EPS:
                status = "improved"
                stats["improved"] += 1
            elif delta < -EPS:
                status = "decayed"
                stats["decayed"] += 1
            else:
                status = "stable"
                stats["stable"] += 1
        rows.append(
            [
                str(cluster_id),
                fmt_value(old_val),
                fmt_value(new_val),
                fmt_delta(delta),
                status,
            ]
        )
    return rows, stats


def average_metric(metrics: Mapping[int, float | None]) -> float | None:
    values = [value for value in metrics.values() if value is not None]
    if not values:
        return None
    return sum(values) / len(values)


def build_transition_rows(
    contributions: Mapping[int, Sequence[Dict[str, Any]]],
    min_fraction: float,
    min_shared: int,
    per_cluster_limit: int = 5,
) -> List[List[str]]:
    rows: List[List[str]] = []
    for target_id in sorted(contributions.keys()):
        added = 0
        for entry in contributions[target_id]:
            if (
                entry["shared"] < min_shared
                and entry["target_fraction"] < min_fraction
                and entry["source_fraction"] < min_fraction
            ):
                continue
            rows.append(
                [
                    str(target_id),
                    str(entry["source"]),
                    str(entry["shared"]),
                    format_pct(entry["target_fraction"]),
                    format_pct(entry["source_fraction"]),
                ]
            )
            added += 1
            if added >= per_cluster_limit:
                break
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Diff two cached cluster reports.")
    parser.add_argument("old_key", help="Baseline cache key, e.g. 20251112-3")
    parser.add_argument("new_key", help="New cache key to compare against the baseline")
    parser.add_argument(
        "--cache-root",
        type=Path,
        default=Path("cache"),
        help="Directory containing cache/<key>/cluster_report.json (default: ./cache)",
    )
    parser.add_argument(
        "--detail-limit",
        type=int,
        default=20,
        help="Maximum per-category rows to print for detailed trace changes.",
    )
    parser.add_argument(
        "--min-shared",
        type=int,
        default=10,
        help="Minimum overlapping traces required before flagging a merge/split.",
    )
    parser.add_argument(
        "--min-fraction",
        type=float,
        default=0.25,
        help="Minimum percentage (0-1) of a cluster that must overlap before flagging a merge/split.",
    )

    args = parser.parse_args()

    old_report = load_report(args.cache_root, args.old_key)
    new_report = load_report(args.cache_root, args.new_key)

    old_traces = flatten_traces(old_report)
    new_traces = flatten_traces(new_report)

    old_membership = build_cluster_memberships(old_traces)
    new_membership = build_cluster_memberships(new_traces)

    print(f"Comparing cluster reports: {args.old_key} -> {args.new_key}")
    print(f"Old run: {len(old_report.get('clusters', []))} clusters, {len(old_traces)} traces")
    print(f"New run: {len(new_report.get('clusters', []))} clusters, {len(new_traces)} traces")

    moved, removed, added = summarize_trace_changes(old_traces, new_traces)

    format_section("Trace Movements")
    print(f"Moved traces: {len(moved)}")
    for old_rec, new_rec in moved[: args.detail_limit]:
        print(f"- {old_rec.trace_id}: cluster {old_rec.cluster_id} -> {new_rec.cluster_id} | script={old_rec.data.get('script_url')}")
    if len(moved) > args.detail_limit:
        print(f"... {len(moved) - args.detail_limit} more")

    format_section("Removed Traces")
    print(f"Removed traces: {len(removed)}")
    for record in removed[: args.detail_limit]:
        print(f"- {record.describe()}")
    if len(removed) > args.detail_limit:
        print(f"... {len(removed) - args.detail_limit} more")

    format_section("New Traces")
    print(f"New traces: {len(added)}")
    for record in added[: args.detail_limit]:
        print(f"- {record.describe()}")
    if len(added) > args.detail_limit:
        print(f"... {len(added) - args.detail_limit} more")

    format_section("Cluster Reshaping")
    merge_contribs = cluster_contributions(old_membership, new_membership)
    split_contribs = cluster_contributions(new_membership, old_membership)
    merge_msgs = summarize_merges(merge_contribs, new_membership, args.min_fraction, args.min_shared)
    split_msgs = summarize_splits(split_contribs, old_membership, args.min_fraction, args.min_shared)

    if merge_msgs:
        print("Potential merges:")
        for msg in merge_msgs:
            print(f"- {msg}")
    else:
        print("No merges above the configured thresholds.")

    if split_msgs:
        print("\nPotential splits:")
        for msg in split_msgs:
            print(f"- {msg}")
    else:
        print("\nNo splits above the configured thresholds.")

    merge_rows = build_transition_rows(merge_contribs, args.min_fraction, args.min_shared)
    if merge_rows:
        print("\nMerge mappings (new <- old):")
        render_table(["New Cluster", "Old Cluster", "Shared", "% of New", "% of Old"], merge_rows)
    else:
        print("\nNo qualifying merge mappings to display.")

    split_rows = build_transition_rows(split_contribs, args.min_fraction, args.min_shared)
    if split_rows:
        print("\nSplit mappings (old -> new):")
        render_table(["Old Cluster", "New Cluster", "Shared", "% of Old", "% of New"], split_rows)
    else:
        print("\nNo qualifying split mappings to display.")

    format_section("Silhouette Changes")
    old_overall = safe_float(old_report.get("overall_silhouette"))
    new_overall = safe_float(new_report.get("overall_silhouette"))
    overall_delta = None
    if old_overall is not None and new_overall is not None:
        overall_delta = new_overall - old_overall
    print(
        f"Overall silhouette: {fmt_value(old_overall)} -> {fmt_value(new_overall)} ({fmt_delta(overall_delta)})"
    )

    old_cluster_sil = extract_cluster_silhouettes(old_report)
    new_cluster_sil = extract_cluster_silhouettes(new_report)
    table_rows, sil_stats = build_metric_rows(old_cluster_sil, new_cluster_sil)
    render_table(["Cluster", "Old", "New", "Delta", "Status"], table_rows)
    print(
        f"\nClusters improved: {sil_stats['improved']} | decayed: {sil_stats['decayed']} | "
        f"stable: {sil_stats['stable']} | new: {sil_stats['new']} | removed: {sil_stats['removed']}"
    )

    format_section("AST Similarity Changes")
    old_cluster_ast = extract_cluster_ast_similarity(old_report)
    new_cluster_ast = extract_cluster_ast_similarity(new_report)

    old_avg_ast = average_metric(old_cluster_ast)
    new_avg_ast = average_metric(new_cluster_ast)
    avg_ast_delta = None
    if old_avg_ast is not None and new_avg_ast is not None:
        avg_ast_delta = new_avg_ast - old_avg_ast
    print(
        f"Average AST similarity: {fmt_value(old_avg_ast)} -> {fmt_value(new_avg_ast)} ({fmt_delta(avg_ast_delta)})"
    )

    ast_rows, ast_stats = build_metric_rows(old_cluster_ast, new_cluster_ast)
    render_table(["Cluster", "Old", "New", "Delta", "Status"], ast_rows)
    print(
        f"\nClusters improved: {ast_stats['improved']} | decayed: {ast_stats['decayed']} | "
        f"stable: {ast_stats['stable']} | new: {ast_stats['new']} | removed: {ast_stats['removed']}"
    )


if __name__ == "__main__":
    main()
