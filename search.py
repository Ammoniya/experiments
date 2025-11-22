#!/usr/bin/env python3
"""
Utility helpers for investigating cached cluster artifacts.

Available commands:
  * find: locate the cluster ID for one or more trace IDs
  * summarize: highlight clusters with mismatched AST/Silhouette similarity (low/high).
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect cached cluster artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    find_parser = subparsers.add_parser("find", help="Locate the cluster containing one or more trace IDs.")
    find_parser.add_argument(
        "--cluster-cache",
        required=True,
        help="Path to the cache directory (e.g., cache/all-3) containing cluster_report.json.",
    )
    find_parser.add_argument(
        "--trace-id",
        action="append",
        dest="trace_ids",
        required=True,
        help="Trace ID to search for. Repeat this flag to search for multiple IDs.",
    )

    summary_parser = subparsers.add_parser(
        "summarize",
        help="Read a sample directory and surface clusters with inverted AST/Silhouette relationships.",
    )
    summary_parser.add_argument(
        "sample_dir",
        help="Path to the sample directory (e.g., samples/all-3) or the cluster key (e.g., all-3).",
    )
    summary_parser.add_argument(
        "--summary-csv",
        help="Optional path to the cluster summary CSV. Defaults to <sample_dir>/*_summary.csv.",
    )
    summary_parser.add_argument(
        "--text-report",
        help="Optional path to the cluster summary text report. Defaults to <sample_dir>/cluster_summary_report.txt.",
    )
    summary_parser.add_argument(
        "--low-percentile",
        type=float,
        default=25.0,
        help="Percentile used to define 'very low' values (default: %(default)s).",
    )
    summary_parser.add_argument(
        "--high-percentile",
        type=float,
        default=75.0,
        help="Percentile used to define 'very high' values (default: %(default)s).",
    )
    summary_parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum clusters to print per category (default: %(default)s, 0 = unlimited).",
    )
    summary_parser.add_argument(
        "--min-gap",
        type=float,
        default=0.05,
        help="Minimum silhouette-vs-AST gap needed to count as a mismatch (default: %(default)s).",
    )
    return parser.parse_args()


def load_report(cache_dir: Path) -> Dict[str, Any]:
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


def resolve_sample_dir(sample_dir_arg: str) -> Path:
    candidate = Path(sample_dir_arg)
    if candidate.exists():
        return candidate
    fallback = Path("samples") / sample_dir_arg
    if fallback.exists():
        return fallback
    raise SystemExit(f"Sample directory not found: {sample_dir_arg}")


def find_summary_csv(sample_dir: Path, override: Optional[str]) -> Optional[Path]:
    if override:
        csv_path = Path(override)
        if not csv_path.exists():
            raise SystemExit(f"Summary CSV not found: {csv_path}")
        return csv_path
    expected = sample_dir / f"{sample_dir.name}_summary.csv"
    if expected.exists():
        return expected
    matches = sorted(sample_dir.glob("*_summary.csv"))
    return matches[0] if matches else None


def find_text_report(sample_dir: Path, override: Optional[str]) -> Optional[Path]:
    if override:
        path = Path(override)
        if not path.exists():
            raise SystemExit(f"Text report not found: {path}")
        return path
    candidate = sample_dir / "cluster_summary_report.txt"
    return candidate if candidate.exists() else None


def parse_float(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped.upper() == "N/A":
        return None
    try:
        return float(stripped)
    except ValueError:
        return None


def parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    stripped = value.strip()
    if not stripped or stripped.upper() == "N/A":
        return None
    try:
        return int(float(stripped))
    except ValueError:
        return None


def load_summary_rows_from_csv(csv_path: Path) -> List[Dict[str, Any]]:
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        rows: List[Dict[str, Any]] = []
        for row in reader:
            summary = {
                "cluster_id": parse_int(row.get("cluster id")),
                "members": parse_int(row.get("number of data points in the cluster")),
                "avg_silhouette": parse_float(row.get("Cluster Avg Silhouette Similarity")),
                "avg_ast_similarity": parse_float(row.get("Cluster Avg AST Similarity")),
                "avg_vt_detections": parse_float(row.get("Cluster Avg VT Detections")),
                "avg_trace_length": parse_float(row.get("Avg Trace Length")),
                "avg_suspicious_events": parse_float(row.get("Avg Suspicious Events per Trace")),
                "nearest_clusters": (row.get("Nearest Clusters") or "").strip(),
            }
            rows.append(summary)
    return rows


def load_summary_rows_from_text(report_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    current: Dict[str, Any] = {}
    with report_path.open("r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("Cluster "):
                if current:
                    rows.append(current)
                parts = line.split(maxsplit=1)
                cluster_id = None
                if len(parts) == 2:
                    try:
                        cluster_id = int(parts[1])
                    except ValueError:
                        cluster_id = None
                current = {"cluster_id": cluster_id}
                continue
            if ":" not in line:
                continue
            key, value = [segment.strip() for segment in line.split(":", 1)]
            if key == "Members":
                current["members"] = parse_int(value)
            elif key == "Avg Silhouette":
                current["avg_silhouette"] = parse_float(value)
            elif key == "Avg AST Similarity":
                current["avg_ast_similarity"] = parse_float(value)
            elif key == "Avg VirusTotal Detections":
                current["avg_vt_detections"] = parse_float(value)
            elif key == "Avg Suspicious Events per Trace":
                current["avg_suspicious_events"] = parse_float(value)
            elif key == "Avg Trace Length":
                current["avg_trace_length"] = parse_float(value)
            elif key == "Nearest Clusters":
                current["nearest_clusters"] = value
    if current:
        rows.append(current)
    return rows


def percentile(values: Sequence[float], percent: float) -> float:
    if not values:
        raise ValueError("Cannot compute percentile of an empty list.")
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    pct = max(0.0, min(100.0, percent))
    position = (pct / 100) * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[int(position)]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def select_clusters(
    rows: Iterable[Dict[str, Any]],
    low_pct: float,
    high_pct: float,
    min_gap: float,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, float], List[Dict[str, Any]], List[Dict[str, Any]]]:
    paired = [
        row
        for row in rows
        if row.get("avg_silhouette") is not None and row.get("avg_ast_similarity") is not None
    ]
    if not paired:
        raise SystemExit("No clusters contained both AST and Silhouette averages.")
    sil_low = percentile([row["avg_silhouette"] for row in paired], low_pct)
    sil_high = percentile([row["avg_silhouette"] for row in paired], high_pct)
    ast_low = percentile([row["avg_ast_similarity"] for row in paired], low_pct)
    ast_high = percentile([row["avg_ast_similarity"] for row in paired], high_pct)

    low_ast_high_sil: List[Dict[str, Any]] = []
    high_ast_low_sil: List[Dict[str, Any]] = []
    positive_gap: List[Dict[str, Any]] = []
    negative_gap: List[Dict[str, Any]] = []
    for row in paired:
        ast_value = row["avg_ast_similarity"]
        sil_value = row["avg_silhouette"]
        if ast_value is None or sil_value is None:
            continue
        gap = sil_value - ast_value
        row["sil_minus_ast"] = gap
        if gap >= 0:
            positive_gap.append(row)
        else:
            negative_gap.append(row)
        if ast_value <= ast_low and sil_value >= sil_high and gap >= min_gap:
            low_ast_high_sil.append(row)
        if ast_value >= ast_high and sil_value <= sil_low and gap <= -min_gap:
            high_ast_low_sil.append(row)

    low_ast_high_sil.sort(key=lambda row: (row["avg_ast_similarity"], -row["avg_silhouette"]))
    high_ast_low_sil.sort(key=lambda row: (-row["avg_ast_similarity"], row["avg_silhouette"]))
    positive_gap.sort(key=lambda row: row["sil_minus_ast"], reverse=True)
    negative_gap.sort(key=lambda row: row["sil_minus_ast"])
    thresholds = {
        "ast_low": ast_low,
        "ast_high": ast_high,
        "sil_low": sil_low,
        "sil_high": sil_high,
    }
    return low_ast_high_sil, high_ast_low_sil, thresholds, positive_gap, negative_gap


def format_value(value: Optional[float]) -> str:
    if value is None:
        return "N/A"
    return f"{value:.3f}"


def render_cluster_summary(cluster: Dict[str, Any]) -> str:
    parts = [
        f"Cluster {cluster.get('cluster_id', 'N/A')}",
        f"members={cluster.get('members', 'N/A')}",
        f"avg_silhouette={format_value(cluster.get('avg_silhouette'))}",
        f"avg_ast={format_value(cluster.get('avg_ast_similarity'))}",
    ]
    if cluster.get("avg_vt_detections") is not None:
        parts.append(f"vt={format_value(cluster['avg_vt_detections'])}")
    if cluster.get("avg_suspicious_events") is not None:
        parts.append(f"suspicious={format_value(cluster['avg_suspicious_events'])}")
    if cluster.get("avg_trace_length") is not None:
        parts.append(f"trace_len={format_value(cluster['avg_trace_length'])}")
    gap = cluster.get("sil_minus_ast")
    if gap is not None:
        parts.append(f"gap={gap:+.3f}")
    if cluster.get("nearest_clusters"):
        parts.append(f"nearest={cluster['nearest_clusters']}")
    return " | ".join(parts)


def print_summary_report(
    sample_dir: Path,
    csv_path: Optional[Path],
    text_path: Optional[Path],
    low_pct: float,
    high_pct: float,
    min_gap: float,
    limit: int,
) -> None:
    rows: List[Dict[str, Any]] = []
    if csv_path:
        rows = load_summary_rows_from_csv(csv_path)
    if not rows and text_path:
        rows = load_summary_rows_from_text(text_path)
    if not rows:
        raise SystemExit("No cluster summary data found (tried CSV and text report).")

    (
        low_ast_high_sil,
        high_ast_low_sil,
        thresholds,
        positive_gap,
        negative_gap,
    ) = select_clusters(rows, low_pct, high_pct, min_gap)

    header = f"Sample directory: {sample_dir} (low_pct={low_pct}%, high_pct={high_pct}%)"
    print(header)
    print("-" * len(header))
    print(
        "Thresholds -> "
        f"AST low <= {thresholds['ast_low']:.3f}, AST high >= {thresholds['ast_high']:.3f}, "
        f"Silhouette low <= {thresholds['sil_low']:.3f}, Silhouette high >= {thresholds['sil_high']:.3f}"
    )
    print()

    def print_section(
        title: str,
        clusters: List[Dict[str, Any]],
        fallback_rows: List[Dict[str, Any]],
        fallback_desc: str,
        fallback_predicate,
    ) -> None:
        print(title)
        print("-" * len(title))
        if not clusters:
            if not fallback_rows:
                print("No clusters had the necessary metrics for this analysis.\n")
                return
            print(
                f"No clusters met the percentile+gap criteria (gap >= {min_gap:.3f}). "
                f"Showing {fallback_desc}:"
            )
            filtered_rows = [row for row in fallback_rows if fallback_predicate(row)]
            if not filtered_rows:
                filtered_rows = fallback_rows
            display = filtered_rows if limit <= 0 else filtered_rows[:limit]
            for cluster in display:
                print(f"- {render_cluster_summary(cluster)}")
            remaining = len(filtered_rows) - len(display)
            if remaining > 0:
                print(f"... {remaining} more not shown (use --limit 0 to show all)")
            print()
            return
        display = clusters if limit <= 0 else clusters[:limit]
        for cluster in display:
            print(f"- {render_cluster_summary(cluster)}")
        remaining = len(clusters) - len(display)
        if remaining > 0:
            print(f"... {remaining} more not shown (use --limit 0 to show all)")
        print()

    print_section(
        "Low AST similarity but high Silhouette score",
        low_ast_high_sil,
        positive_gap,
        "top silhouette-minus-AST gaps",
        lambda row: (row.get("sil_minus_ast") or 0.0) >= min_gap,
    )
    print_section(
        "High AST similarity but low Silhouette score",
        high_ast_low_sil,
        negative_gap,
        "top AST-minus-silhouette gaps",
        lambda row: (row.get("sil_minus_ast") or 0.0) <= -min_gap,
    )


def main() -> None:
    args = parse_args()
    if args.command == "find":
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
        return

    if args.command == "summarize":
        sample_dir = resolve_sample_dir(args.sample_dir)
        csv_path = find_summary_csv(sample_dir, args.summary_csv)
        text_path = find_text_report(sample_dir, args.text_report)
        print_summary_report(
            sample_dir=sample_dir,
            csv_path=csv_path,
            text_path=text_path,
            low_pct=args.low_percentile,
            high_pct=args.high_percentile,
            min_gap=args.min_gap,
            limit=args.limit,
        )
        return

    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
