#!/usr/bin/env python3
"""
Build a structured JSON report for every cluster, mirroring the data surfaced
in the Dash dashboard (metadata, WordPress assets, event summaries, etc.).
"""

from __future__ import annotations

import argparse
import json
import pickle
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from cluster_neighbors import compute_cluster_neighbors, normalize_neighbor_mapping

from subsequence_alignment_cache import (
    cache_is_stale,
    default_cache_path,
    load_alignment_cache,
)

from scan_cluster import (
    convert_wordfence_constraints,
    describe_constraint_groups,
    expand_slug_variations,
    format_vuln_identifier,
    normalize_version,
    parse_label,
    slugify_label,
    version_satisfies,
)

try:
    from dtaidistance.subsequence.dtw import subsequence_alignment
except ImportError:  # pragma: no cover - optional dependency
    subsequence_alignment = None

DTW_PREVIEW_LIMIT = 15
PLUGIN_VULN_FALLBACK_LIMIT = 3


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def load_results(results_path: Path) -> Dict[str, Any]:
    with results_path.open("rb") as fh:
        return pickle.load(fh)


def summarize_event_sequence(events: List[str], limit: int = 20) -> List[str]:
    if not events:
        return []
    return events[:limit]


def summarize_events_counter(events: List[str], limit: int = 10) -> List[Dict[str, Any]]:
    counter = Counter(events or [])
    return [{"event": event, "count": count} for event, count in counter.most_common(limit)]


def summarize_capabilities(cap_counts: Dict[str, int], limit: int = 8) -> List[Dict[str, Any]]:
    counter = Counter(cap_counts or {})
    return [{"capability": cap, "count": count} for cap, count in counter.most_common(limit)]


def counter_to_entries(counter: Counter, limit: int | None = None) -> List[Dict[str, Any]]:
    if not counter:
        return []
    pairs = counter.most_common(limit) if limit is not None else counter.most_common()
    return [{"label": item, "count": count} for item, count in pairs]


def safe_float(value: Any) -> Any:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


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


def _parse_published_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    candidates = [text]
    if " " in text:
        candidates.append(text.replace(" ", "T"))
    for candidate in candidates:
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    return None


def load_wordfence_vuln_map(path: Path | None) -> dict[str, list[dict[str, Any]]]:
    if path is None or not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return {}

    vulns: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def _ingest_entry(entry: Mapping[str, Any]) -> None:
        software_items = entry.get("software") or []
        if not isinstance(software_items, Sequence):
            return
        for software in software_items:
            if not isinstance(software, Mapping):
                continue
            sw_type = str(software.get("type") or "").lower()
            if sw_type and sw_type != "plugin":
                continue
            slug_candidates = {
                slugify_label(str(value))
                for value in (software.get("slug"), software.get("name"))
                if value
            }
            slug_candidates.discard("")
            if not slug_candidates:
                continue
            groups = convert_wordfence_constraints(software.get("affected_versions") or {})
            base_payload = {
                "cve": entry.get("cve"),
                "wordfence_uuid": entry.get("id"),
                "title": entry.get("title") or "",
                "references": entry.get("references") or [],
                "published": entry.get("published"),
                "published_ts": _parse_published_timestamp(entry.get("published")),
                "constraint_groups": groups,
            }
            for slug in slug_candidates:
                variants = expand_slug_variations(slug) or {slug}
                for alias in variants:
                    vulns[alias].append(base_payload)

    if isinstance(payload, Mapping):
        for entry in payload.values():
            if isinstance(entry, Mapping):
                _ingest_entry(entry)
    elif isinstance(payload, Sequence):
        for entry in payload:
            if isinstance(entry, Mapping):
                _ingest_entry(entry)

    for slug, entries in vulns.items():
        entries.sort(key=lambda item: item.get("published_ts") or datetime.min, reverse=True)
    return vulns


def _normalize_vuln_record(vuln: Mapping[str, Any]) -> Dict[str, Any]:
    references = vuln.get("references") or []
    reference = None
    for ref in references:
        if isinstance(ref, str) and ref:
            reference = ref
            break
    return {
        "id": format_vuln_identifier(vuln),
        "title": vuln.get("title") or "Wordfence advisory",
        "note": describe_constraint_groups(vuln.get("constraint_groups") or []),
        "published": vuln.get("published") or "Unknown date",
        "reference": reference,
    }


def _dedupe_vuln_records(records: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    unique: List[Dict[str, Any]] = []
    for record in records or []:
        identifier = record.get("id")
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        unique.append(dict(record))
    return unique


def _unique_plugin_assets(items: Sequence[Mapping[str, Any]] | None) -> List[Dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    assets: List[Dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, Mapping):
            continue
        name = (item.get("name") or "").strip()
        if not name:
            continue
        slug = slugify_label(name)
        if not slug:
            continue
        raw_version = item.get("version")
        version = str(raw_version).strip() if raw_version not in (None, "") else None
        key = (slug, version or "")
        if key in seen:
            continue
        seen.add(key)
        assets.append({"name": name, "slug": slug, "version": version})
    assets.sort(key=lambda asset: asset["name"])
    return assets


def summarize_plugins_for_trace(trace: Mapping[str, Any], vuln_map: Mapping[str, Sequence[Mapping[str, Any]]]) -> List[Dict[str, Any]]:
    assets = _unique_plugin_assets(trace.get("wordpress_plugins"))
    if not assets or not vuln_map:
        return []
    summary: List[Dict[str, Any]] = []
    for asset in assets:
        slug = asset["slug"]
        version_text = asset.get("version")
        entry = {
            "name": asset["name"],
            "slug": slug,
            "version": version_text,
            "status": "no_wordfence",
            "matches": [],
            "fallback": [],
        }
        vulns = vuln_map.get(slug)
        if not vulns:
            summary.append(entry)
            continue
        compare_version = normalize_version(version_text) if version_text else None
        compare_version = compare_version or version_text
        if compare_version:
            matched = [
                _normalize_vuln_record(v)
                for v in vulns
                if version_satisfies(str(compare_version), v.get("constraint_groups") or [])
            ]
        else:
            matched = []
        if matched:
            entry["status"] = "matched"
            entry["matches"] = _dedupe_vuln_records(matched)
            summary.append(entry)
            continue
        fallback = [_normalize_vuln_record(v) for v in vulns[:PLUGIN_VULN_FALLBACK_LIMIT]]
        if compare_version:
            entry["status"] = "no_matching_version"
        elif version_text:
            entry["status"] = "version_missing"
        else:
            entry["status"] = "version_missing"
        entry["fallback"] = fallback
        summary.append(entry)
    return summary


def aggregate_cluster_plugin_vulns(
    cluster_traces: Sequence[Mapping[str, Any]],
    trace_plugin_lookup: Mapping[str, Sequence[Mapping[str, Any]]],
) -> List[Dict[str, Any]]:
    summary: Dict[str, Dict[str, Any]] = {}
    for trace in cluster_traces:
        trace_id = trace.get("trace_id")
        entries = trace_plugin_lookup.get(trace_id) or []
        for plugin_entry in entries:
            slug = plugin_entry.get("slug")
            if not slug:
                continue
            record = summary.setdefault(slug, {
                "name": plugin_entry.get("name"),
                "slug": slug,
                "trace_ids": set(),
                "matched_trace_ids": set(),
                "match_records": [],
                "fallback_records": [],
            })
            record["trace_ids"].add(trace_id)
            matches = plugin_entry.get("matches") or []
            fallback = plugin_entry.get("fallback") or []
            if matches:
                record["matched_trace_ids"].add(trace_id)
                record["match_records"].extend(matches)
            elif fallback:
                record["fallback_records"].extend(fallback)
    aggregated: List[Dict[str, Any]] = []
    for values in summary.values():
        item = {
            "name": values.get("name"),
            "slug": values.get("slug"),
            "total_traces": len(values["trace_ids"]),
            "matched_traces": len(values["matched_trace_ids"]),
            "matches": _dedupe_vuln_records(values.get("match_records")),
            "fallback": _dedupe_vuln_records(values.get("fallback_records"))[:PLUGIN_VULN_FALLBACK_LIMIT],
        }
        aggregated.append(item)
    aggregated.sort(key=lambda entry: (entry["matched_traces"], entry["total_traces"], entry["name"] or ""), reverse=True)
    return aggregated


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


# --------------------------------------------------------------------------- #
# Report generation
# --------------------------------------------------------------------------- #

def _serialize_neighbors(entries: List[Any]) -> List[Dict[str, Any]]:
    serialized: List[Dict[str, Any]] = []
    for entry in entries or []:
        if isinstance(entry, dict):
            other = entry.get("cluster_id")
            distance = entry.get("distance")
        else:
            other, distance = entry
        try:
            other_label = int(other)
            distance_val = float(distance)
        except (TypeError, ValueError):
            continue
        serialized.append({"cluster_id": other_label, "distance": distance_val})
    return serialized


def generate_report(results_path: Path, data_dir: Path, wordfence_path: Path | None = None) -> Dict[str, Any]:
    results = load_results(results_path)
    traces: List[Dict[str, Any]] = results["traces"]
    distance_matrix = results.get("distance_matrix")
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
    wordfence_vuln_map = load_wordfence_vuln_map(wordfence_path)
    trace_plugin_vulns: Dict[str, List[Dict[str, Any]]] = {}
    if wordfence_vuln_map:
        for trace in traces:
            summary = summarize_plugins_for_trace(trace, wordfence_vuln_map)
            if summary:
                trace_plugin_vulns[trace.get("trace_id")] = summary

    clusters: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for trace in traces:
        cluster_id = int(trace.get("cluster", -1))
        clusters[cluster_id].append(trace)

    cluster_neighbors = normalize_neighbor_mapping(cluster_metadata.get("cluster_neighbors"))
    if not cluster_neighbors:
        cluster_neighbors = compute_cluster_neighbors(distance_matrix, traces, limit=5)

    report: Dict[str, Any] = {
        "results_path": str(results_path),
        "data_dir": str(data_dir),
        "overall_silhouette": safe_float(overall_silhouette),
        "wordfence_db": str(wordfence_path) if wordfence_path else None,
        "cluster_count": len(clusters),
        "clusters": [],
    }

    for cluster_id in sorted(clusters.keys()):
        members = clusters[cluster_id]
        plugin_counts, theme_counts = build_cluster_wp_distribution(members)

        avg_events = (
            sum(t.get("num_events", 0) for t in members) / len(members)
            if members else 0
        )
        vt_counts = []
        for trace in members:
            vt_info = trace.get("virustotal")
            if not vt_info:
                continue
            verdict_count = vt_info.get("verdict_count")
            if verdict_count is None:
                continue
            try:
                vt_counts.append(float(verdict_count))
            except (TypeError, ValueError):
                continue
        vt_trace_count = len(vt_counts)
        vt_average = sum(vt_counts) / vt_trace_count if vt_trace_count else None
        sil_score = silhouette_lookup.get(cluster_id)
        ast_score = ast_similarity_lookup.get(cluster_id)
        ast_scripts = sum(1 for t in members if t.get("ast_unit_vector"))
        ast_total = ast_counts.get(cluster_id, ast_scripts)
        neighbor_entries = _serialize_neighbors(cluster_neighbors.get(cluster_id) or [])

        plugin_vuln_summary = aggregate_cluster_plugin_vulns(members, trace_plugin_vulns) if trace_plugin_vulns else []

        cluster_entry: Dict[str, Any] = {
            "cluster_id": cluster_id,
            "count": len(members),
            "average_events_per_script": avg_events,
            "silhouette": safe_float(sil_score),
            "ast_similarity": safe_float(ast_score),
            "ast_script_count": ast_scripts,
            "ast_total_scripts": ast_total,
            "closest_clusters": neighbor_entries,
            "virustotal_average_verdict_count": safe_float(vt_average),
            "virustotal_trace_count": vt_trace_count,
            "virustotal_trace_coverage": safe_float(
                (vt_trace_count / len(members)) if members else None
            ),
            "wordpress_plugins": counter_to_entries(plugin_counts, limit=20),
            "wordpress_themes": counter_to_entries(theme_counts, limit=20),
            "wordpress_plugin_cves": plugin_vuln_summary,
            "traces": [],
        }

        for trace in sorted(members, key=lambda t: t.get("script_id")):
            trace_idx = trace_index_lookup.get(trace.get("trace_id"), -1)
            alignment = compute_dtw_alignment(
                trace,
                trace_idx,
                numeric_sequences,
                raw_sequences,
                cluster_representatives,
                alignment_cache,
            )
            ast_fp = trace.get("ast_fingerprint") or {}
            top_nodes = []
            node_counts = ast_fp.get("node_type_counts") or {}
            if node_counts:
                top_nodes = [
                    {"node_type": label, "count": count}
                    for label, count in sorted(node_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
                ]

            vt_summary = trace.get("virustotal")

            trace_entry = {
                "trace_id": trace.get("trace_id"),
                "cluster": trace.get("cluster"),
                "script_id": trace.get("script_id"),
                "script_url": trace.get("script_url"),
                "page_url": trace.get("page_url"),
                "url_hash": trace.get("url_hash"),
                "timestamp": trace.get("timestamp"),
                "script_sha256": trace.get("hash"),
                "script_path": script_path(trace, data_dir),
                "is_module": trace.get("is_module"),
                "num_events": trace.get("num_events"),
                "suspicious_event_count": trace.get("suspicious_event_count", 0),
                "trace_silhouette": safe_float(trace.get("silhouette_score")),
                "trace_ast_similarity": safe_float(trace.get("ast_similarity")),
                "capability_counts": trace.get("capability_counts", {}),
                "capability_summary": summarize_capabilities(trace.get("capability_counts", {})),
                "event_sequence_preview": summarize_event_sequence(trace.get("event_sequence", [])),
                "event_distribution": summarize_events_counter(trace.get("event_sequence", [])),
                "wordpress_plugins": trace.get("wordpress_plugins", []),
                "wordpress_themes": trace.get("wordpress_themes", []),
                "virustotal": vt_summary or None,
                "virustotal_verdict": trace.get("virustotal_verdict") or (vt_summary or {}).get("verdict"),
                "virustotal_verdict_count": trace.get("virustotal_verdict_count") or (vt_summary or {}).get("verdict_count"),
                "wordpress_plugin_cves": trace_plugin_vulns.get(trace.get("trace_id"), []),
                "alignment": alignment,
                "ast_preview": trace.get("ast_preview"),
                "ast_fingerprint_summary": {
                    "num_nodes": ast_fp.get("num_nodes"),
                    "max_depth": ast_fp.get("max_depth"),
                    "top_node_types": top_nodes,
                } if ast_fp else None,
            }

            cluster_entry["traces"].append(trace_entry)

        report["clusters"].append(cluster_entry)

    return report


def render_text_report(report: Dict[str, Any], max_traces_per_cluster: int = 3) -> str:
    lines: List[str] = []
    results_path = report.get("results_path")
    overall_sil = report.get("overall_silhouette")
    lines.append("Cluster Report Summary")
    if results_path:
        lines.append(f"Results file: {results_path}")
    lines.append(f"Overall silhouette: {overall_sil:.3f}" if isinstance(overall_sil, (int, float)) and overall_sil is not None else "Overall silhouette: n/a")
    lines.append("")

    clusters = sorted(report.get("clusters", []), key=lambda c: c.get("cluster_id", 0))
    for cluster in clusters:
        cluster_id = cluster.get("cluster_id")
        count = cluster.get("count", 0)
        avg_events = cluster.get("average_events_per_script")
        sil = cluster.get("silhouette")
        vt_avg = cluster.get("virustotal_average_verdict_count")
        vt_cov = cluster.get("virustotal_trace_count", 0)
        vt_line = None
        if vt_cov:
            try:
                vt_line = f"VT avg verdict count: {vt_avg:.2f} ({vt_cov}/{count} traces scanned)"
            except (TypeError, ValueError):
                vt_line = f"VT scans: {vt_cov}/{count} traces"
        elif count:
            vt_line = "VT scans: 0 traces with data"

        lines.append(f"Cluster {cluster_id} — {count} script(s)")
        lines.append(f"  Avg events/script: {avg_events:.1f}" if isinstance(avg_events, (int, float)) else "  Avg events/script: n/a")
        if sil is not None:
            lines.append(f"  Silhouette: {sil:.3f}")
        if vt_line:
            lines.append(f"  {vt_line}")

        traces = cluster.get("traces", [])[:max_traces_per_cluster]
        for trace in traces:
            vt = trace.get("virustotal") or {}
            vt_verdict = vt.get("verdict") or trace.get("virustotal_verdict")
            vt_count = vt.get("verdict_count")
            vt_display = vt_verdict or "n/a"
            if vt_count is not None:
                vt_display = f"{vt_display} ({vt_count} detections)"
            script_url = trace.get("script_url") or "unknown URL"
            lines.append(f"    - {trace.get('trace_id')}: {vt_display} | {script_url}")

        lines.append("")

    if not clusters:
        lines.append("No clusters available in the report.")

    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Generate JSON cluster report with full metadata.")
    parser.add_argument("--results", default="clustering_results.pkl",
                        help="Path to clustering results pickle file")
    parser.add_argument("--data-dir", default="experiment_data",
                        help="Experiment data directory (for script paths)")
    parser.add_argument("--output",
                        help="Optional path to write the report instead of stdout")
    parser.add_argument("--text-output",
                        help="Optional path for a plaintext summary (defaults to OUTPUT with .txt suffix)")
    parser.add_argument("--wordfence-db", default="wordfence_db.json",
                        help="Path to the Wordfence vulnerability database JSON (default: wordfence_db.json)")
    args = parser.parse_args()

    results_path = Path(args.results).resolve()
    data_dir = Path(args.data_dir).resolve()

    if not results_path.exists():
        raise SystemExit(f"Results file not found: {results_path}")
    if not data_dir.exists():
        raise SystemExit(f"Data directory not found: {data_dir}")

    output_path = Path(args.output).resolve() if args.output else None
    text_output_path = Path(args.text_output).resolve() if args.text_output else None
    wordfence_path = Path(args.wordfence_db).resolve() if args.wordfence_db else None
    report = generate_report(results_path, data_dir, wordfence_path)
    text_summary = render_text_report(report)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")

        if text_output_path is None:
            if output_path.suffix:
                text_output_path = output_path.with_suffix('.txt')
            else:
                text_output_path = Path(str(output_path) + '.txt')

    if text_output_path:
        text_output_path.parent.mkdir(parents=True, exist_ok=True)
        text_output_path.write_text(text_summary, encoding="utf-8")
    elif not output_path:
        json.dump(report, sys.stdout, indent=2)
        print()
        print(text_summary, file=sys.stderr)
        return

    if not output_path:
        json.dump(report, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
