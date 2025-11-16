#!/usr/bin/env python3
"""
Generate a text-based report for every cluster, mirroring the data surfaced
in the Dash dashboard (metadata, WordPress assets, event summaries, etc.).
"""

from __future__ import annotations

import argparse
import json
import math
import pickle
from collections import Counter, defaultdict
from contextlib import redirect_stdout
from pathlib import Path
from typing import Dict, List, Tuple, Any

from subsequence_alignment_cache import (
    cache_is_stale,
    default_cache_path,
    load_alignment_cache,
)

try:
    from dtaidistance.subsequence.dtw import subsequence_alignment
except ImportError:  # pragma: no cover - optional dependency
    subsequence_alignment = None

DTW_PREVIEW_LIMIT = 15


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


def format_metric(value: Any) -> str:
    if isinstance(value, (int, float)):
        if math.isnan(value):
            return "n/a"
        return f"{value:.3f}"
    return "n/a"


def build_event_mapping(results: Dict[str, Any]) -> Dict[str, int]:
    event_types = results.get("event_types")
    if not event_types:
        encoder = results.get("encoder")
        if encoder is not None and hasattr(encoder, "classes_"):
            event_types = list(encoder.classes_)
        else:
            event_types = []
    return {label: idx for idx, label in enumerate(event_types)}


def encode_sequences(sequences: List[List[str]], mapping: Dict[str, int]) -> List[List[float]]:
    encoded: List[List[float]] = []
    for seq in sequences:
        if not seq:
            encoded.append([])
            continue
        encoded.append([float(mapping.get(evt, -1.0)) for evt in seq])
    return encoded


def select_cluster_representatives(
    traces: List[Dict[str, Any]],
    numeric_sequences: List[List[float]]
) -> Dict[int, Dict[str, Any]]:
    representatives: Dict[int, Dict[str, Any]] = {}
    for idx, trace in enumerate(traces):
        cluster_id = int(trace.get("cluster", -1))
        if cluster_id in (-1, None):
            continue
        sequence = numeric_sequences[idx]
        if not sequence:
            continue
        sil = trace.get("silhouette_score")
        try:
            score = float(sil)
        except (TypeError, ValueError):
            score = float("-inf")
        best = representatives.get(cluster_id)
        if best is None or score > best["score"]:
            representatives[cluster_id] = {
                "trace_id": trace.get("trace_id"),
                "script_url": trace.get("script_url"),
                "score": score,
                "sequence": sequence,
                "num_events": trace.get("num_events"),
                "trace_index": idx,
            }
    return representatives


def format_event_preview(events: List[str], limit: int = DTW_PREVIEW_LIMIT) -> str:
    if not events:
        return "None"
    snippet = " -> ".join(events[:limit])
    if len(events) > limit:
        snippet += " -> ..."
    return snippet


def compute_dtw_alignment(
    trace: Dict[str, Any],
    trace_idx: int,
    numeric_sequences: List[List[float]],
    raw_sequences: List[List[str]],
    cluster_reps: Dict[int, Dict[str, Any]],
    cache: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    trace_id = trace.get("trace_id")
    if not trace_id:
        return {"error": "Missing trace ID; cannot compute alignment."}

    if trace_id in cache:
        return cache[trace_id]

    if subsequence_alignment is None:
        info = {"error": "Subsequence DTW unavailable (install dtaidistance>=2.3)."}
        cache[trace_id] = info
        return info

    if trace_idx is None or trace_idx < 0 or trace_idx >= len(numeric_sequences):
        info = {"error": "Trace index not found for alignment."}
        cache[trace_id] = info
        return info

    cluster_id = int(trace.get("cluster", -1))
    if cluster_id in (-1, None):
        info = {"error": "Noise/outlier traces skip subsequence alignment."}
        cache[trace_id] = info
        return info

    representative = cluster_reps.get(cluster_id)
    if not representative:
        info = {"error": f"No representative trace available for cluster {cluster_id}."}
        cache[trace_id] = info
        return info

    series = numeric_sequences[trace_idx]
    query = representative.get("sequence") or []
    if not query or not series:
        info = {"error": "One of the event sequences is empty; alignment skipped."}
        cache[trace_id] = info
        return info

    try:
        sa = subsequence_alignment(query, series)
        match = sa.best_match()
    except Exception as exc:  # noqa: BLE001
        info = {"error": f"Alignment failed: {exc}"}
        cache[trace_id] = info
        return info

    if not match or not match.segment:
        info = {"error": "DTW did not yield a valid subsequence match."}
        cache[trace_id] = info
        return info

    start, end = match.segment
    start = int(start)
    end = int(end)
    matched_len = max(end - start + 1, 0)
    total_len = len(series)
    coverage = matched_len / total_len if total_len else 0.0
    norm_cost = match.distance / matched_len if matched_len else None
    tail_len = max(total_len - end - 1, 0)

    events = trace.get("event_sequence") or raw_sequences[trace_idx]
    tail_events = events[end + 1:] if events and end + 1 < len(events) else []

    info = {
        "representative_trace_id": representative.get("trace_id"),
        "representative_url": representative.get("script_url"),
        "start_index": start,
        "end_index": end,
        "matched_length": matched_len,
        "series_length": total_len,
        "coverage_ratio": coverage,
        "tail_length": tail_len,
        "distance": float(match.distance),
        "normalized_distance": float(norm_cost) if norm_cost is not None else None,
        "tail_preview": format_event_preview(tail_events),
    }

    cache[trace_id] = info
    return info


def format_alignment_lines(alignment: Dict[str, Any]) -> List[str]:
    if not alignment:
        return ["Alignment not computed."]
    error = alignment.get("error")
    if error:
        return [error]

    coverage_pct = alignment.get("coverage_ratio", 0.0) * 100
    tail_len = alignment.get("tail_length", 0)
    total_len = alignment.get("series_length", 0) or 1
    tail_pct = (tail_len / total_len) * 100 if total_len else 0.0
    lines = [
        f"Reference Trace: {alignment.get('representative_trace_id', 'n/a')}",
        f"Matched Segment: {alignment.get('start_index')} → {alignment.get('end_index')} "
        f"({alignment.get('matched_length')}/{alignment.get('series_length')} events, "
        f"{coverage_pct:.1f}% coverage)",
        f"Tail Length: {tail_len} events ({tail_pct:.1f}%)",
        f"DTW Distance: {format_metric(alignment.get('distance'))}",
    ]
    norm_cost = alignment.get("normalized_distance")
    if norm_cost is not None:
        lines.append(f"Normalized Cost: {format_metric(norm_cost)}")
    tail_preview = alignment.get("tail_preview")
    if tail_preview and tail_preview != "None":
        lines.append(f"Tail Events: {tail_preview}")
    return lines


# --------------------------------------------------------------------------- #
# Report generation
# --------------------------------------------------------------------------- #

def generate_report(results_path: Path, data_dir: Path) -> None:
    results = load_results(results_path)
    traces: List[Dict[str, Any]] = results["traces"]
    raw_sequences: List[List[str]] = results.get("sequences") or [
        trace.get("event_sequence", []) for trace in traces
    ]
    event_mapping = build_event_mapping(results)
    numeric_sequences = encode_sequences(raw_sequences, event_mapping)
    cluster_representatives = select_cluster_representatives(traces, numeric_sequences)
    cache_path = default_cache_path(results_path)
    cached_alignments, cache_meta = load_alignment_cache(cache_path)
    alignment_cache: Dict[str, Dict[str, Any]] = {}
    if cached_alignments:
        alignment_cache.update(cached_alignments)
        if cache_is_stale(cache_meta, results_path):
            print(f"[WARN] Alignment cache at {cache_path} appears stale; recomputing entries on demand.")
        else:
            print(f"Loaded subsequence alignment cache from {cache_path}")
    trace_index_lookup = {trace.get("trace_id"): idx for idx, trace in enumerate(traces)}
    cluster_metadata: Dict[str, Any] = results.get("cluster_metadata", {}) or {}
    silhouette_lookup = cluster_metadata.get("silhouette_per_cluster", {}) or {}
    overall_silhouette = cluster_metadata.get("silhouette_overall")
    ast_similarity_lookup = cluster_metadata.get("ast_similarity", {}) or {}
    ast_counts = cluster_metadata.get("ast_counts", {}) or {}

    clusters: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for trace in traces:
        cluster_id = int(trace.get("cluster", -1))
        clusters[cluster_id].append(trace)

    if overall_silhouette is not None:
        print(f"Overall silhouette (avg similarity across clusters): {overall_silhouette:.3f}\n")

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
        sil_score = silhouette_lookup.get(cluster_id)
        if sil_score is not None:
            print(f"Average similarity (silhouette): {sil_score:.3f}\n")
        else:
            print("Average similarity (silhouette): n/a\n")
        ast_score = ast_similarity_lookup.get(cluster_id)
        ast_scripts = sum(1 for t in members if t.get("ast_unit_vector"))
        ast_total = ast_counts.get(cluster_id, ast_scripts)
        if ast_scripts >= 2 and isinstance(ast_score, (int, float)):
            print(f"AST average similarity: {ast_score:.3f} ({ast_scripts}/{len(members)} scripts with AST)\n")
        elif ast_scripts:
            print(f"AST average similarity: n/a ({ast_scripts}/{len(members)} scripts with AST)\n")
        else:
            print("AST average similarity: n/a (no AST fingerprints)\n")

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
            print(f"   Trace Silhouette: {format_metric(trace.get('silhouette_score'))}")
            print(f"   Trace AST Similarity: {format_metric(trace.get('ast_similarity'))}")
            ast_fp = trace.get('ast_fingerprint') or {}
            if ast_fp:
                node_count = ast_fp.get('num_nodes', 0)
                max_depth = ast_fp.get('max_depth', 0)
                print(f"   AST Nodes: {node_count} | Max Depth: {max_depth}")
                node_counts = ast_fp.get('node_type_counts') or {}
                top_nodes = sorted(node_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
                if top_nodes:
                    node_summary = ", ".join(f"{k}:{v}" for k, v in top_nodes)
                    print(f"   AST Top Node Types: {node_summary}")
            else:
                print("   AST Fingerprint: unavailable")
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
            trace_idx = trace_index_lookup.get(trace.get("trace_id"), -1)
            alignment = compute_dtw_alignment(
                trace,
                trace_idx,
                numeric_sequences,
                raw_sequences,
                cluster_representatives,
                alignment_cache,
            )
            print("   Subsequence Alignment:")
            for line in format_alignment_lines(alignment):
                print(f"        {line}")
            print()


def main():
    parser = argparse.ArgumentParser(description="Generate text cluster report with full metadata.")
    parser.add_argument("--results", default="clustering_results.pkl",
                        help="Path to clustering results pickle file")
    parser.add_argument("--data-dir", default="experiment_data",
                        help="Experiment data directory (for script paths)")
    parser.add_argument("--output",
                        help="Optional path to write the report instead of stdout")
    args = parser.parse_args()

    results_path = Path(args.results).resolve()
    data_dir = Path(args.data_dir).resolve()

    if not results_path.exists():
        raise SystemExit(f"Results file not found: {results_path}")
    if not data_dir.exists():
        raise SystemExit(f"Data directory not found: {data_dir}")

    output_path = Path(args.output).resolve() if args.output else None
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as fh, redirect_stdout(fh):
            generate_report(results_path, data_dir)
    else:
        generate_report(results_path, data_dir)


if __name__ == "__main__":
    main()
