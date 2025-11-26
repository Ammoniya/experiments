#!/usr/bin/env python3
"""
Copy JavaScript samples from a previous cluster extraction into the latest clusters.

Given an "old" sample cache key (e.g., all-5) and a "new" cache key (e.g., all-7),
the script performs the following tasks:

* Walk ``samples/<old_key>/cluster-*`` manifests to collect the trace IDs that were
  previously exported.
* Load ``cache/<new_key>/cluster_report.json`` to discover which cluster now owns
  each trace.
* Copy the JavaScript payloads from ``experiment_data`` into
  ``samples/<new_key>/cluster-<id>`` so the latest clusters contain matching JS.
* Automatically export any novel traces that appear in the new clusters so the
  sample directories reflect the latest cluster membership counts.
* Emit both per-cluster metadata (``imported_from_<old>.json``) and a global mapping
  file that explains how traces moved between clusters.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from extract_samples import (
    ClusterSelection,
    build_cluster_summary,
    compute_trace_score,
    write_cluster_summary_files,
    write_manifest,
    write_network_report,
)

# Cap the number of trace identifiers we embed verbatim in metadata to avoid giant files.
TRACE_SAMPLE_LIMIT = 50

# Clusters labeled -1 correspond to outliers from the clustering step.
OUTLIER_CLUSTER_ID = "-1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Map/export JS samples from an old cluster extraction onto a new cluster run.")
    parser.add_argument("old_cache_key", help="Cache/sample identifier that already has extracted samples (e.g., all-5).")
    parser.add_argument("new_cache_key", help="Cache identifier for the latest clustering run (e.g., all-7).")
    parser.add_argument(
        "--samples-root",
        default="samples",
        help="Directory that holds extracted samples (default: samples).",
    )
    parser.add_argument(
        "--cache-root",
        default="cache",
        help="Directory containing the cached cluster reports (default: cache).",
    )
    parser.add_argument(
        "--mapping-file",
        help="Optional path to write the old->new cluster mapping JSON (default: samples/<new>/mapping_from_<old>.json).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be copied without writing files.",
    )
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


@dataclass
class OldTrace:
    trace_id: str
    old_cluster_id: str
    script_path: Path | None


def describe_old_only_trace(
    trace_id: str,
    new_trace_index: Mapping[str, Dict[str, Any]],
    new_cache_key: str,
) -> Dict[str, Any]:
    """
    Provide diagnostic context for traces that disappeared from the old cluster.
    """
    trace_entry = new_trace_index.get(trace_id)
    if trace_entry is None:
        return {
            "trace_id": trace_id,
            "status": "missing_from_new_cache",
            "new_cluster_id": None,
            "reason": (
                f"Trace not present in {new_cache_key}'s cluster_report.json; "
                "it was removed earlier in the pipeline."
            ),
        }

    new_cluster_id = str(trace_entry.get("cluster_id"))
    status = "reclassified_as_outlier" if new_cluster_id == OUTLIER_CLUSTER_ID else "unmapped_in_new_cluster"
    alignment_info = trace_entry.get("alignment")
    if not isinstance(alignment_info, dict):
        alignment_info = None

    alignment_error = alignment_info.get("error") if alignment_info else None
    alignment_distance = alignment_info.get("normalized_distance") if alignment_info else None
    alignment_coverage = alignment_info.get("coverage_ratio") if alignment_info else None

    reason_parts = []
    if status == "reclassified_as_outlier":
        reason_parts.append("Trace reclassified as noise/outlier (-1).")
    else:
        reason_parts.append(
            f"Trace assigned to cluster {new_cluster_id} in {new_cache_key} but excluded from sample export."
        )
    if alignment_error:
        reason_parts.append(f"Subsequence DTW: {alignment_error}")
    elif alignment_distance is not None or alignment_coverage is not None:
        stats = []
        if alignment_distance is not None:
            stats.append(f"normalized_distance={alignment_distance}")
        if alignment_coverage is not None:
            stats.append(f"coverage_ratio={alignment_coverage}")
        if stats:
            reason_parts.append("Subsequence DTW stats: " + ", ".join(stats))

    details: Dict[str, Any] = {
        "trace_id": trace_id,
        "status": status,
        "new_cluster_id": new_cluster_id,
        "reason": " ".join(reason_parts),
    }
    if alignment_error:
        details["alignment_error"] = alignment_error
    if alignment_distance is not None:
        details["alignment_normalized_distance"] = alignment_distance
    if alignment_coverage is not None:
        details["alignment_coverage_ratio"] = alignment_coverage
    return details


def describe_new_only_trace(
    trace_id: str,
    old_trace_index: Mapping[str, Dict[str, Any]],
    old_cache_key: str,
) -> Dict[str, Any]:
    """Explain whether a novel trace is brand new or previously mapped elsewhere."""
    trace_entry = old_trace_index.get(trace_id)
    if trace_entry is None:
        return {
            "trace_id": trace_id,
            "status": "new_to_dataset",
            "old_cluster_id": None,
            "reason": f"Trace absent from {old_cache_key}'s cluster_report.json; likely first appearance.",
        }
    old_cluster_id = str(trace_entry.get("cluster_id"))
    return {
        "trace_id": trace_id,
        "status": "moved_from_previous_cluster",
        "old_cluster_id": old_cluster_id,
        "reason": (
            f"Trace existed in cluster {old_cluster_id} of {old_cache_key} but was not exported previously."
        ),
    }


def iter_old_traces(samples_root: Path, cache_key: str) -> Iterable[OldTrace]:
    base = samples_root / cache_key
    if not base.exists():
        raise SystemExit(f"Old samples directory not found: {base}")
    cluster_dirs = sorted(p for p in base.iterdir() if p.is_dir() and p.name.startswith("cluster-"))
    if not cluster_dirs:
        raise SystemExit(f"No cluster-* folders found under {base}")

    for cluster_dir in cluster_dirs:
        manifest_path = cluster_dir / "manifest.json"
        trace_blocks: List[Dict[str, Any]] = []
        cluster_id = cluster_dir.name.split("-", 1)[-1]
        if manifest_path.exists():
            data = load_json(manifest_path)
            cluster_id = str(data.get("cluster_id") or cluster_id)
            trace_blocks.extend(data.get("traces") or [])
        else:
            imported_files = sorted(cluster_dir.glob("imported_from_*.json"))
            if not imported_files:
                print(f"[warn] Skipping {cluster_dir} (missing manifest/imported metadata)", file=sys.stderr)
                continue
            for imported_path in imported_files:
                payload = load_json(imported_path)
                cluster_id = str(payload.get("cluster_id") or cluster_id)
                trace_blocks.extend(payload.get("traces") or [])

        for trace in trace_blocks:
            trace_id = str(trace.get("trace_id") or "").strip()
            if not trace_id:
                continue
            script_path = trace.get("script_path")
            yield OldTrace(
                trace_id=trace_id,
                old_cluster_id=str(cluster_id),
                script_path=Path(script_path) if isinstance(script_path, str) and script_path else None,
            )


def load_cluster_index(cache_root: Path, cache_key: str) -> Tuple[Path, Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    report_path = cache_root / cache_key / "cluster_report.json"
    if not report_path.exists():
        raise SystemExit(f"Cluster report not found for cache key {cache_key}: {report_path}")
    report = load_json(report_path)
    trace_index: Dict[str, Dict[str, Any]] = {}
    clusters: Dict[str, Dict[str, Any]] = {}
    for cluster in report.get("clusters") or []:
        cluster_id = str(cluster.get("cluster_id"))
        traces: List[Dict[str, Any]] = []
        for trace in cluster.get("traces") or []:
            trace_id = str(trace.get("trace_id") or "").strip()
            if not trace_id:
                continue
            entry = dict(trace)
            entry["cluster_id"] = cluster_id
            traces.append(entry)
            trace_index[trace_id] = entry
        clusters[cluster_id] = {
            "cluster_id": cluster_id,
            "count": len(traces),
            "silhouette": cluster.get("silhouette"),
            "ast_similarity": cluster.get("ast_similarity"),
            "traces": traces,
            "trace_ids": [trace["trace_id"] for trace in traces],
        }
    return report_path, clusters, trace_index


def ensure_dir(path: Path, dry_run: bool) -> None:
    if dry_run:
        return
    path.mkdir(parents=True, exist_ok=True)


def unique_destination(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    counter = 1
    while True:
        candidate = path.with_name(f"{stem}_{counter}{suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def copy_script(src: Path, dst: Path, dry_run: bool) -> None:
    if dry_run:
        if not src.exists():
            raise FileNotFoundError(src)
        print(f"[dry-run] Would copy {src} -> {dst}")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def format_output_filename(index: int, trace_id: str, script_sha: str | None) -> str:
    sha_prefix = (script_sha or "unknown")[:12]
    safe_trace_id = trace_id.replace("/", "_")
    return f"{index:02d}_{safe_trace_id}_{sha_prefix}.js"


def write_json(path: Path, data: Mapping[str, Any], dry_run: bool) -> None:
    if dry_run:
        print(f"[dry-run] Would write {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)


def main() -> None:
    args = parse_args()
    samples_root = Path(args.samples_root)
    cache_root = Path(args.cache_root)
    new_samples_root = samples_root / args.new_cache_key
    ensure_dir(new_samples_root, args.dry_run)

    new_report_path, new_clusters, new_trace_index = load_cluster_index(cache_root, args.new_cache_key)
    old_report_path, old_clusters, old_trace_index = load_cluster_index(cache_root, args.old_cache_key)
    print(f"[info] Loaded {len(new_trace_index):,} traces from {new_report_path}")

    per_new_cluster_records: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    per_new_cluster_trace_entries: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    per_new_cluster_outputs: Dict[str, Dict[str, str]] = defaultdict(dict)
    per_new_cluster_scores: Dict[str, Dict[str, float]] = defaultdict(dict)
    per_new_cluster_copied: Dict[str, List[Tuple[Dict[str, Any], str]]] = defaultdict(list)
    new_cluster_counters: Dict[str, int] = defaultdict(int)
    old_to_new_map: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    manifest_traces_by_cluster: Dict[str, set[str]] = defaultdict(set)
    novel_traces_by_cluster: Dict[str, Dict[str, Any]] = {}

    missing_traces: List[str] = []
    total_copied = 0
    exported_trace_ids: set[str] = set()

    for old_trace in iter_old_traces(samples_root, args.old_cache_key):
        trace_entry = new_trace_index.get(old_trace.trace_id)
        exported_trace_ids.add(old_trace.trace_id)
        manifest_traces_by_cluster[old_trace.old_cluster_id].add(old_trace.trace_id)

        if not trace_entry:
            missing_traces.append(old_trace.trace_id)
            continue
        new_cluster_id = str(trace_entry.get("cluster_id"))
        if new_cluster_id == OUTLIER_CLUSTER_ID:
            continue
        old_to_new_map[old_trace.old_cluster_id][new_cluster_id].append(old_trace.trace_id)

        script_path = trace_entry.get("script_path")
        candidate_paths = [script_path, old_trace.script_path]
        resolved_src: Path | None = None
        for candidate in candidate_paths:
            if isinstance(candidate, str) and candidate:
                candidate_path = Path(candidate)
                if candidate_path.exists():
                    resolved_src = candidate_path
                    break
        if resolved_src is None:
            raise SystemExit(f"Unable to locate script file for trace {old_trace.trace_id}")

        new_cluster_dir = new_samples_root / f"cluster-{new_cluster_id}"
        ensure_dir(new_cluster_dir, args.dry_run)
        new_cluster_counters[new_cluster_id] += 1
        file_index = new_cluster_counters[new_cluster_id]
        dest_name = format_output_filename(file_index, old_trace.trace_id, trace_entry.get("script_sha256"))
        dest_path = unique_destination(new_cluster_dir / dest_name)
        copy_script(resolved_src, dest_path, args.dry_run)
        total_copied += 1

        trace_data = dict(trace_entry)
        trace_data["output_file"] = dest_path.name
        per_new_cluster_trace_entries[new_cluster_id].append(trace_data)
        per_new_cluster_outputs[new_cluster_id][old_trace.trace_id] = dest_path.name
        per_new_cluster_copied[new_cluster_id].append((trace_data, dest_path.name))
        per_new_cluster_scores[new_cluster_id][old_trace.trace_id] = compute_trace_score(trace_data)

        trace_record = {
            "trace_id": old_trace.trace_id,
            "old_cluster_id": old_trace.old_cluster_id,
            "new_cluster_id": new_cluster_id,
            "script_url": trace_entry.get("script_url"),
            "page_url": trace_entry.get("page_url"),
            "script_sha256": trace_entry.get("script_sha256"),
            "script_path": str(resolved_src),
            "output_file": dest_path.name,
        }
        per_new_cluster_records[new_cluster_id].append(trace_record)

    for new_cluster_id, records in per_new_cluster_records.items():
        if new_cluster_id == OUTLIER_CLUSTER_ID:
            continue
        cluster_info = new_clusters.get(new_cluster_id, {})
        cluster_dir = new_samples_root / f"cluster-{new_cluster_id}"
        cluster_trace_ids = cluster_info.get("trace_ids") or []
        novel_trace_ids = [
            trace_id for trace_id in cluster_trace_ids if trace_id not in exported_trace_ids
        ]

        if novel_trace_ids:
            ensure_dir(cluster_dir, args.dry_run)
            for trace_id in novel_trace_ids:
                trace_entry = new_trace_index.get(trace_id)
                if not trace_entry:
                    continue
                script_path = trace_entry.get("script_path")
                if not isinstance(script_path, str) or not script_path:
                    raise SystemExit(
                        f"Trace {trace_id} in cluster {new_cluster_id} from {args.new_cache_key} "
                        "is missing a script_path."
                    )
                resolved_src = Path(script_path)
                new_cluster_counters[new_cluster_id] += 1
                file_index = new_cluster_counters[new_cluster_id]
                dest_name = format_output_filename(
                    file_index,
                    trace_id,
                    trace_entry.get("script_sha256"),
                )
                dest_path = unique_destination(cluster_dir / dest_name)
                copy_script(resolved_src, dest_path, args.dry_run)
                total_copied += 1

                trace_data = dict(trace_entry)
                trace_data["output_file"] = dest_path.name
                per_new_cluster_trace_entries[new_cluster_id].append(trace_data)
                per_new_cluster_outputs[new_cluster_id][trace_id] = dest_path.name
                per_new_cluster_copied[new_cluster_id].append((trace_data, dest_path.name))
                per_new_cluster_scores[new_cluster_id][trace_id] = compute_trace_score(trace_data)
                per_new_cluster_records[new_cluster_id].append(
                    {
                        "trace_id": trace_id,
                        "old_cluster_id": None,
                        "new_cluster_id": new_cluster_id,
                        "script_url": trace_entry.get("script_url"),
                        "page_url": trace_entry.get("page_url"),
                        "script_sha256": trace_entry.get("script_sha256"),
                        "script_path": str(resolved_src),
                        "output_file": dest_path.name,
                    }
                )

        novel_details = [
            describe_new_only_trace(trace_id, old_trace_index, args.old_cache_key) for trace_id in novel_trace_ids
        ]

        novel_traces_by_cluster[new_cluster_id] = {
            "trace_ids": novel_trace_ids,
            "sample": novel_trace_ids[:TRACE_SAMPLE_LIMIT],
            "total": len(novel_trace_ids),
            "details": novel_details,
        }

        selected_traces = per_new_cluster_trace_entries[new_cluster_id]
        trace_scores = per_new_cluster_scores[new_cluster_id]
        output_files = per_new_cluster_outputs[new_cluster_id]
        copied_pairs = per_new_cluster_copied[new_cluster_id]

        if not copied_pairs:
            continue

        suspicious_call_count = sum(int(trace.get("suspicious_event_count") or 0) for trace in selected_traces)
        cluster_score = sum(trace_scores.values()) / len(trace_scores) if trace_scores else 0.0
        selection = ClusterSelection(
            cache_key=args.new_cache_key,
            cache_dir=cache_root / args.new_cache_key,
            cluster_id=new_cluster_id,
            cluster_score=cluster_score,
            suspicious_call_count=suspicious_call_count,
            selected_traces=selected_traces,
            trace_scores=trace_scores,
        )
        cluster_dir = new_samples_root / f"cluster-{new_cluster_id}"

        if args.dry_run:
            print(f"[dry-run] Would write manifest/network/summary for {cluster_dir}")
        else:
            write_manifest(selection, trace_scores, cluster_dir, output_files)
            write_network_report(copied_pairs, cluster_dir)
            summary = build_cluster_summary(args.new_cache_key, cluster_info or {}, selected_traces)
            summary["copied_file_count"] = len(copied_pairs)
            write_cluster_summary_files(summary, cluster_dir)

    mapped_trace_total = sum(
        len(trace_ids) for cluster_map in old_to_new_map.values() for trace_ids in cluster_map.values()
    )

    cluster_mappings: List[Dict[str, Any]] = []
    seen_new_clusters: set[str] = set()
    processed_old_clusters = sorted(manifest_traces_by_cluster.keys())
    for old_cluster_id in processed_old_clusters:
        old_entry = old_clusters.get(old_cluster_id, {})
        cluster_map = old_to_new_map.get(old_cluster_id, {})
        manifest_traces = manifest_traces_by_cluster.get(old_cluster_id, set())
        mapped_ids: set[str] = set()
        for trace_ids in cluster_map.values():
            mapped_ids.update(trace_ids)
        removed_traces = sorted(trace_id for trace_id in manifest_traces if trace_id not in new_trace_index)
        unmapped_traces = sorted(manifest_traces - mapped_ids)
        old_only_traces = sorted(set(removed_traces).union(unmapped_traces))
        old_only_details = [
            describe_old_only_trace(trace_id, new_trace_index, args.new_cache_key) for trace_id in old_only_traces
        ]

        if not cluster_map:
            cluster_mappings.append(
                {
                    "old_cluster_id": old_cluster_id,
                    "old_cluster_metrics": {
                        "total_members": old_entry.get("count"),
                        "silhouette": old_entry.get("silhouette"),
                        "ast_similarity": old_entry.get("ast_similarity"),
                    },
                    "new_cluster_id": None,
                    "new_cluster_metrics": None,
                    "trace_ids_in_both_clusters": [],
                    "trace_ids_only_in_new_cluster": [],
                    "trace_ids_only_in_old_cluster": old_only_traces,
                    "trace_ids_only_in_old_cluster_details": old_only_details,
                    "trace_ids_only_in_new_cluster_details": [],
                }
            )
            continue

        for new_cluster_id, trace_ids in sorted(cluster_map.items()):
            new_entry = new_clusters.get(new_cluster_id, {})
            novel_info = novel_traces_by_cluster.get(
                new_cluster_id, {"trace_ids": [], "sample": [], "total": 0}
            )
            novel_details = novel_info.get("details", [])
            cluster_mappings.append(
                {
                    "old_cluster_id": old_cluster_id,
                    "old_cluster_metrics": {
                        "total_members": old_entry.get("count"),
                        "silhouette": old_entry.get("silhouette"),
                        "ast_similarity": old_entry.get("ast_similarity"),
                    },
                    "new_cluster_id": new_cluster_id,
                    "new_cluster_metrics": {
                        "total_members": new_entry.get("count"),
                        "silhouette": new_entry.get("silhouette"),
                        "ast_similarity": new_entry.get("ast_similarity"),
                    },
                    "trace_ids_in_both_clusters": trace_ids,
                    "trace_ids_only_in_new_cluster": novel_info["trace_ids"],
                    "trace_ids_only_in_old_cluster": old_only_traces,
                    "trace_ids_only_in_old_cluster_details": old_only_details,
                    "trace_ids_only_in_new_cluster_details": novel_details,
                }
            )
            seen_new_clusters.add(new_cluster_id)

    for new_cluster_id, info in novel_traces_by_cluster.items():
        if new_cluster_id == OUTLIER_CLUSTER_ID or new_cluster_id in seen_new_clusters:
            continue
        new_entry = new_clusters.get(new_cluster_id, {})
        cluster_mappings.append(
            {
                "old_cluster_id": None,
                "old_cluster_metrics": None,
                "new_cluster_id": new_cluster_id,
                "new_cluster_metrics": {
                    "total_members": new_entry.get("count"),
                    "silhouette": new_entry.get("silhouette"),
                    "ast_similarity": new_entry.get("ast_similarity"),
                },
                "trace_ids_in_both_clusters": [],
                "trace_ids_only_in_new_cluster": info["trace_ids"],
                "trace_ids_only_in_old_cluster": [],
                "trace_ids_only_in_new_cluster_details": info.get("details", []),
            }
        )

    mapping_output = {
        "cluster_mappings": cluster_mappings,
    }

    if not args.mapping_file:
        mapping_path = new_samples_root / f"mapping_from_{args.old_cache_key}.json"
    else:
        mapping_path = Path(args.mapping_file)
    write_json(mapping_path, mapping_output, args.dry_run)

    print(f"[info] Copied {total_copied} traces across {len(per_new_cluster_records)} new clusters.")
    if missing_traces:
        print(f"[warn] {len(missing_traces)} traces from {args.old_cache_key} did not exist in {args.new_cache_key}.")


if __name__ == "__main__":
    main()
