#!/usr/bin/env python3
"""
Aggregate per-cache cluster reports into a single summary table and HTML dashboard.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def summarize_cache(cache_dir: Path) -> List[Dict[str, Any]]:
    report_path = cache_dir / "cluster_report.json"
    if not report_path.exists():
        return []

    config_path = cache_dir / "cache_config.json"
    config = load_json(config_path) if config_path.exists() else {}
    timestamp_key = config.get("timestamp_key") or cache_dir.name.split("-")[0]
    cache_key = config.get("cache_key") or cache_dir.name
    timestamp_filters = config.get("timestamp_filters") or []
    timestamp_display = " ".join(timestamp_filters) if timestamp_filters else timestamp_key
    reuse_cmd = f"./run_clustering.sh --use-cache --cache-key {cache_key} --timestamp {timestamp_display}"

    report = load_json(report_path)
    clusters = report.get("clusters", [])

    rows: List[Dict[str, Any]] = []
    for cluster in clusters:
        traces = cluster.get("traces", [])
        suspicious_total = sum(t.get("suspicious_event_count", 0) or 0 for t in traces)
        count = cluster.get("count") or 0
        suspicious_avg = suspicious_total / count if count else 0.0
        silhouette = cluster.get("silhouette")
        ast_similarity = cluster.get("ast_similarity")

        interesting_score = (suspicious_avg * 2.0) + (silhouette or 0.0) + (0.1 * count)
        rows.append({
            "cache_key": cache_key,
            "timestamp_key": timestamp_key,
            "cluster_id": cluster.get("cluster_id"),
            "count": count,
            "avg_events": cluster.get("average_events_per_script"),
            "silhouette": silhouette,
            "ast_similarity": ast_similarity,
            "suspicious_avg": suspicious_avg,
            "interesting_score": interesting_score,
            "report_path": str(report_path),
            "reuse_command": reuse_cmd,
        })

    return rows


def collect_rows(cache_root: Path) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for child in sorted(cache_root.iterdir()):
        if child.is_dir():
            rows.extend(summarize_cache(child))
    if not rows:
        return pd.DataFrame(columns=[
            "cache_key", "timestamp_key", "cluster_id", "count", "avg_events",
            "silhouette", "ast_similarity", "suspicious_avg",
            "interesting_score", "report_path", "reuse_command",
        ])
    df = pd.DataFrame(rows)
    return df


def build_html(df: pd.DataFrame, top_n: int, cache_root: Path) -> str:
    parts = [
        "<html>",
        "<head>",
        "<meta charset='utf-8' />",
        "<title>Cluster Summary Dashboard</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 2rem; }",
        "table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }",
        "th, td { border: 1px solid #ccc; padding: 0.5rem; text-align: left; }",
        "th { background-color: #f2f2f2; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>Cluster Summary Dashboard</h1>",
        f"<p>Cache root: {cache_root}</p>",
    ]

    if df.empty:
        parts.append("<p>No cluster reports found. Run ./run_clustering.sh first.</p>")
        parts.append("</body></html>")
        return "\n".join(parts)

    for timestamp_key, group in df.groupby("timestamp_key"):
        subset = group.sort_values("interesting_score", ascending=False).head(top_n).copy()
        subset["report"] = subset["report_path"].apply(
            lambda p: f'<a href="{Path(p)}" target="_blank">JSON</a>'
        )
        subset["reuse"] = subset["reuse_command"].apply(
            lambda cmd: f"<code>{cmd}</code>"
        )
        display_cols = [
            "cache_key", "cluster_id", "count", "avg_events",
            "silhouette", "ast_similarity", "suspicious_avg",
            "report", "reuse",
        ]
        parts.append(f"<h2>Timestamps: {timestamp_key}</h2>")
        parts.append(subset[display_cols].to_html(index=False, escape=False))

    parts.append("</body></html>")
    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate cluster reports into a dashboard.")
    parser.add_argument("--cache-root", default="cache", help="Directory containing cache subfolders.")
    parser.add_argument("--output", default="cache_summary.html", help="Path to write the HTML dashboard.")
    parser.add_argument("--top-n", type=int, default=5, help="Top clusters per timestamp key.")
    args = parser.parse_args()

    cache_root = Path(args.cache_root)
    if not cache_root.exists():
        raise SystemExit(f"Cache root not found: {cache_root}")

    df = collect_rows(cache_root)
    html = build_html(df, args.top_n, cache_root)

    output_path = Path(args.output)
    output_path.write_text(html, encoding="utf-8")
    print(f"Dashboard saved to {output_path}")


if __name__ == "__main__":
    main()
