#!/usr/bin/env python3
"""
Generate a text-based report for every cluster, mirroring the data surfaced
in the Dash dashboard (metadata, WordPress assets, event summaries, etc.).
"""

from __future__ import annotations

import argparse
import json
import pickle
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Any


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def load_results(results_path: Path) -> Dict[str, Any]:
    with results_path.open("rb") as fh:
        return pickle.load(fh)


def summarize_event_sequence(events: List[str], limit: int = 20) -> str:
    if not events:
        return "No events recorded"
    tokens = events[:limit]
    suffix = "" if len(events) <= limit else ", …"
    return ", ".join(tokens) + suffix


def summarize_events_counter(events: List[str], limit: int = 10) -> str:
    if not events:
        return "None"
    counter = Counter(events)
    lines = [
        f"{event}: {count}"
        for event, count in counter.most_common(limit)
    ]
    return "\n        ".join(lines)


def summarize_capabilities(cap_counts: Dict[str, int], limit: int = 8) -> str:
    if not cap_counts:
        return "None"
    counter = Counter(cap_counts)
    lines = [
        f"{cap}: {count}"
        for cap, count in counter.most_common(limit)
    ]
    return "\n        ".join(lines)


def format_wp_trace(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "None"

    grouped = defaultdict(Counter)
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not name:
            continue
        version = item.get("version") or "unspecified"
        grouped[name][version] += 1

    if not grouped:
        return "None"

    lines = []
    for name in sorted(grouped.keys()):
        version_counts = grouped[name]
        version_parts = []
        for version, count in version_counts.most_common():
            label = version if version != "unspecified" else "unspecified"
            version_parts.append(f"{label} ×{count}" if count > 1 else label)
        lines.append(f"{name}: {', '.join(version_parts)}")
    return "\n        ".join(lines)


def build_cluster_wp_distribution(traces: List[Dict[str, Any]]) -> Tuple[Counter, Counter]:
    plugins = Counter()
    themes = Counter()

    for trace in traces:
        for item in trace.get("wordpress_plugins", []):
            label = item.get("name")
            version = item.get("version")
            if not label:
                continue
            if version:
                plugins[f"{label} ({version})"] += 1
            else:
                plugins[label] += 1
        for item in trace.get("wordpress_themes", []):
            label = item.get("name")
            version = item.get("version")
            if not label:
                continue
            if version:
                themes[f"{label} ({version})"] += 1
            else:
                themes[label] += 1

    return plugins, themes


def format_counter(counter: Counter, title: str, limit: int = 10) -> str:
    if not counter:
        return f"{title}: None"
    lines = [
        f"{item}: {count}"
        for item, count in counter.most_common(limit)
    ]
    return f"{title}:\n        " + "\n        ".join(lines)


def script_path(trace: Dict[str, Any], data_dir: Path) -> str:
    file_name = trace.get("file_name")
    if not file_name:
        return "Unavailable"
    url_hash = trace.get("url_hash")
    timestamp = trace.get("timestamp")
    if not url_hash or not timestamp:
        return "Unavailable"
    path = data_dir / url_hash / timestamp / "loaded_js" / file_name
    return str(path)


# --------------------------------------------------------------------------- #
# Report generation
# --------------------------------------------------------------------------- #

def generate_report(results_path: Path, data_dir: Path) -> None:
    results = load_results(results_path)
    traces: List[Dict[str, Any]] = results["traces"]

    clusters: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for trace in traces:
        cluster_id = int(trace.get("cluster", -1))
        clusters[cluster_id].append(trace)

    for cluster_id in sorted(clusters.keys()):
        members = clusters[cluster_id]
        plugin_counts, theme_counts = build_cluster_wp_distribution(members)

        print("=" * 100)
        print(f"CLUSTER {cluster_id}")
        print("=" * 100)
        print(f"Count: {len(members)}")
        avg_events = (
            sum(t.get("num_events", 0) for t in members) / len(members)
            if members else 0
        )
        print(f"Average events per script: {avg_events:.1f}\n")

        print(format_counter(plugin_counts, "Cluster WordPress Plugins"))
        print(format_counter(theme_counts, "Cluster WordPress Themes"))
        print()

        for idx, trace in enumerate(sorted(members, key=lambda t: t.get("script_id")), start=1):
            print(f"{idx}. Trace ID: {trace.get('trace_id')}")
            print(f"   Cluster: {trace.get('cluster')}")
            print(f"   Script ID: {trace.get('script_id')}")
            print(f"   Script Loaded From: {trace.get('script_url')}")
            print(f"   Scanned Page URL: {trace.get('page_url') or 'Unknown'}")
            print(f"   URL Hash: {trace.get('url_hash')}")
            print(f"   Timestamp: {trace.get('timestamp')}")
            print(f"   Script SHA256: {trace.get('hash') or 'Unavailable'}")
            print(f"   Script Path: {script_path(trace, data_dir)}")
            print(f"   Module: {trace.get('is_module')}")
            print(f"   # Events: {trace.get('num_events')}")
            print(f"   Suspicious Events: {trace.get('suspicious_event_count', 0)}")
            print("   Capability Counts:")
            print(f"        {summarize_capabilities(trace.get('capability_counts', {}))}")
            print("   Event Type Distribution:")
            print(f"        {summarize_events_counter(trace.get('event_sequence', []))}")
            print("   Event Sequence (first 20):")
            print(f"        {summarize_event_sequence(trace.get('event_sequence', []))}")
            print("   WordPress Assets (Trace) - Plugins:")
            print(f"        {format_wp_trace(trace.get('wordpress_plugins'))}")
            print("   WordPress Assets (Trace) - Themes:")
            print(f"        {format_wp_trace(trace.get('wordpress_themes'))}")
            print()


def main():
    parser = argparse.ArgumentParser(description="Generate text cluster report with full metadata.")
    parser.add_argument("--results", default="clustering_results.pkl",
                        help="Path to clustering results pickle file")
    parser.add_argument("--data-dir", default="experiment_data",
                        help="Experiment data directory (for script paths)")
    args = parser.parse_args()

    results_path = Path(args.results).resolve()
    data_dir = Path(args.data_dir).resolve()

    if not results_path.exists():
        raise SystemExit(f"Results file not found: {results_path}")
    if not data_dir.exists():
        raise SystemExit(f"Data directory not found: {data_dir}")

    generate_report(results_path, data_dir)


if __name__ == "__main__":
    main()
