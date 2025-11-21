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
from urllib.parse import urlparse
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

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

# Capabilities/event labels that indicate outbound network activity such as
# XHR/Fetch/WebSocket traffic.
NETWORK_CAPABILITIES = {
    "NET_XHR",
    "NET_FETCH",
    "NET_WS",
    "NET_WEBSOCKET",
    "NET_BEACON",
    "NET_SOCKET",
    "NET_WEBRTC",
    "NET_REQUEST",
}

NETWORK_EVENT_TYPES = {
    "fetch request",
    "xhr request",
    "networkrequest",
    "beacon api call",
}


def load_json(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def is_network_event(event_name: str) -> bool:
    event_type = event_name.split("|", 1)[0].strip().lower()
    if event_type.startswith("websocket"):
        return True
    return event_type in NETWORK_EVENT_TYPES


def parse_network_event_details(event_name: str) -> Dict[str, str]:
    parts = event_name.split("|")
    metadata: Dict[str, str] = {}
    for token in parts[1:]:
        token = token.strip()
        if not token:
            continue
        if "=" in token:
            key, value = token.split("=", 1)
        elif ":" in token:
            key, value = token.split(":", 1)
        else:
            continue
        metadata[key.strip().lower()] = value.strip()

    host = metadata.get("weak_host") or metadata.get("host")
    domain = metadata.get("weak_domain") or metadata.get("domain")
    path = metadata.get("weak_path") or metadata.get("path")
    method = metadata.get("method")
    resource = metadata.get("resource")
    initiator = metadata.get("initiator")
    scheme = metadata.get("scheme")
    url = metadata.get("url")

    if not url and host:
        prefix = ""
        if scheme and not scheme.endswith("://"):
            prefix = f"{scheme}://"
        elif scheme:
            prefix = scheme
        elif not host.startswith("http"):
            prefix = "https://"
        url = f"{prefix}{host}"
        if path:
            if not path.startswith("/") and not url.endswith("/"):
                url += "/"
            url += path
    elif not url and path:
        url = path

    return {
        "method": method.upper() if isinstance(method, str) else None,
        "host": host,
        "path": path,
        "domain": domain,
        "resource": resource,
        "initiator": initiator,
        "url": url,
    }


def collect_network_request_entries(trace: Dict) -> List[Dict]:
    entries: List[Dict] = []
    for event in trace.get("event_distribution") or []:
        event_name = event.get("event")
        if not isinstance(event_name, str) or not is_network_event(event_name):
            continue
        details = parse_network_event_details(event_name)
        entry: Dict[str, object] = {
            "event": event_name,
            "count": int(event.get("count") or 0),
        }
        for key, value in details.items():
            if value:
                entry[key] = value
        entries.append(entry)
    return entries


def get_network_request_entries(trace: Dict) -> List[Dict]:
    cache_key = "_network_request_entries"
    if cache_key in trace:
        cached = trace[cache_key]
        if isinstance(cached, list):
            return cached
    entries = collect_network_request_entries(trace)
    trace[cache_key] = entries
    return entries


def entry_is_xhr_request(entry: Dict) -> bool:
    event_name = str(entry.get("event") or "").split("|", 1)[0].strip().lower()
    if event_name == "xhr request":
        return True
    resource = str(entry.get("resource") or "").lower()
    return event_name == "networkrequest" and resource == "xhr"


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


def write_manifest(
    selection: ClusterSelection,
    trace_scores: Dict[str, float],
    cluster_dir: Path,
    output_files: Optional[Dict[str, str]] = None,
) -> None:
    manifest = {
        "cache_key": selection.cache_key,
        "cluster_id": selection.cluster_id,
        "cluster_score": selection.cluster_score,
        "suspicious_call_count": selection.suspicious_call_count,
        "sample_count": len(selection.selected_traces),
        "traces": [],
    }
    for trace in selection.selected_traces:
        entry = {
            "trace_id": trace["trace_id"],
            "score": trace_scores.get(trace["trace_id"], 0.0),
            "script_url": trace.get("script_url"),
            "page_url": trace.get("page_url"),
            "script_sha256": trace.get("script_sha256"),
            "script_path": trace.get("script_path"),
            "suspicious_event_count": trace.get("suspicious_event_count"),
            "capabilities": trace.get("capability_summary"),
        }
        if output_files and trace["trace_id"] in output_files:
            entry["output_file"] = output_files[trace["trace_id"]]
        manifest["traces"].append(entry)
    with (cluster_dir / "manifest.json").open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)


def write_network_report(copied_traces: Sequence[Tuple[Dict, str]], cluster_dir: Path) -> None:
    report_entries: List[Dict] = []
    for trace, filename in copied_traces:
        requests = get_network_request_entries(trace)
        report_entries.append(
            {
                "trace_id": trace["trace_id"],
                "script_url": trace.get("script_url"),
                "page_url": trace.get("page_url"),
                "output_file": filename,
                "request_count": len(requests),
                "requests": requests,
            }
        )
    with (cluster_dir / "network_requests.json").open("w", encoding="utf-8") as fh:
        json.dump({"scripts": report_entries}, fh, indent=2)


def split_wordpress_asset_label(label: str) -> Tuple[str, str]:
    label = (label or "").strip()
    if not label:
        return "unknown", "unspecified"
    if label.endswith(")") and "(" in label:
        base, version = label[:-1].rsplit("(", 1)
        base = base.strip() or "unknown"
        version = version.strip() or "unspecified"
        return base, version
    return label, "unspecified"


def aggregate_wordpress_assets(entries: Optional[Sequence[Dict]]) -> List[Dict]:
    grouped: Dict[str, Dict[str, int]] = {}
    if not entries:
        return []
    for entry in entries:
        label = entry.get("label")
        count_value = entry.get("count")
        try:
            count = int(count_value)
        except (TypeError, ValueError):
            continue
        if count <= 0:
            continue
        name, version = split_wordpress_asset_label(label)
        bucket = grouped.setdefault(name, {})
        bucket[version] = bucket.get(version, 0) + count
    aggregated: List[Dict] = []
    for name, versions in grouped.items():
        total = sum(versions.values())
        sorted_versions = sorted(versions.items(), key=lambda item: (-item[1], item[0]))
        aggregated.append(
            {
                "name": name,
                "total": total,
                "versions": [{"label": version, "count": count} for version, count in sorted_versions],
            }
        )
    aggregated.sort(key=lambda item: (-item["total"], item["name"]))
    return aggregated


def format_wordpress_distribution_text(distribution: Sequence[Dict]) -> str:
    if not distribution:
        return "None"
    parts: List[str] = []
    for asset in distribution:
        version_bits = ", ".join(f"{version['label']}: {version['count']}" for version in asset.get("versions", []))
        if version_bits:
            parts.append(f"{asset.get('name', 'unknown')} ({version_bits})")
        else:
            parts.append(str(asset.get("name", "unknown")))
    return "; ".join(parts)


def format_float_value(value: Optional[float], precision: int = 3) -> str:
    if value is None:
        return "N/A"
    return f"{float(value):.{precision}f}"


def format_nearest_clusters_text(nearest: Sequence[Dict]) -> str:
    if not nearest:
        return "None"
    parts: List[str] = []
    for entry in nearest:
        cluster_id = entry.get("cluster_id")
        distance = entry.get("distance")
        if distance is None:
            parts.append(str(cluster_id))
        else:
            parts.append(f"{cluster_id} ({float(distance):.4f})")
    return "; ".join(parts)


def extract_unique_urls_and_domains(traces: Sequence[Dict]) -> Tuple[List[str], List[str]]:
    url_set = set()
    for trace in traces:
        url = (trace.get("script_url") or "").strip()
        if url:
            url_set.add(url)
    unique_urls = sorted(url_set)
    domain_set = set()
    for url in unique_urls:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        domain = domain.strip().lower()
        if domain:
            domain_set.add(domain)
    unique_domains = sorted(domain_set)
    return unique_urls, unique_domains


def build_cluster_summary(cache_key: str, cluster: Dict, traces: Sequence[Dict]) -> Dict[str, object]:
    plugin_distribution = aggregate_wordpress_assets(cluster.get("wordpress_plugins"))
    theme_distribution = aggregate_wordpress_assets(cluster.get("wordpress_themes"))

    def average(field: str) -> Optional[float]:
        values: List[float] = []
        for trace in traces:
            value = trace.get(field)
            if value is None:
                continue
            try:
                values.append(float(value))
            except (TypeError, ValueError):
                continue
        if not values:
            return None
        return sum(values) / len(values)

    unique_urls, unique_domains = extract_unique_urls_and_domains(traces)
    avg_trace_length = cluster.get("average_events_per_script")
    if avg_trace_length is None:
        avg_trace_length = average("num_events")

    avg_virustotal = cluster.get("virustotal_average_verdict_count")
    if avg_virustotal is None:
        avg_virustotal = average("virustotal_verdict_count")

    summary = {
        "cache_key": cache_key,
        "cluster_id": cluster.get("cluster_id"),
        "members": int(cluster.get("count") or len(traces)),
        "avg_silhouette": cluster.get("silhouette"),
        "avg_ast_similarity": cluster.get("ast_similarity"),
        "avg_virustotal_detections": avg_virustotal,
        "avg_suspicious_events_per_trace": average("suspicious_event_count"),
        "avg_trace_length": avg_trace_length,
        "nearest_clusters": [
            {"cluster_id": entry.get("cluster_id"), "distance": entry.get("distance")}
            for entry in cluster.get("closest_clusters") or []
        ],
        "wordpress_plugins": plugin_distribution,
        "wordpress_themes": theme_distribution,
        "unique_url_count": len(unique_urls),
        "unique_urls": unique_urls,
        "unique_domain_count": len(unique_domains),
        "unique_domains": unique_domains,
    }
    return summary


def format_cluster_summary_text(summary: Dict[str, object]) -> str:
    lines = [
        f"Cache Key: {summary.get('cache_key')}",
        f"Cluster ID: {summary.get('cluster_id')}",
        f"Members: {summary.get('members')}",
        f"Avg Silhouette: {format_float_value(summary.get('avg_silhouette'))}",
        f"Avg AST Similarity: {format_float_value(summary.get('avg_ast_similarity'))}",
        f"Avg VirusTotal Detections: {format_float_value(summary.get('avg_virustotal_detections'))}",
        f"Avg Suspicious Events per Trace: {format_float_value(summary.get('avg_suspicious_events_per_trace'))}",
        f"Avg Trace Length: {format_float_value(summary.get('avg_trace_length'))}",
        f"Nearest Clusters: {format_nearest_clusters_text(summary.get('nearest_clusters') or [])}",
        "",
        "WordPress Plugin Distribution:",
        f"  {format_wordpress_distribution_text(summary.get('wordpress_plugins') or [])}",
        "",
        "WordPress Theme Distribution:",
        f"  {format_wordpress_distribution_text(summary.get('wordpress_themes') or [])}",
        "",
        f"Unique Script URLs ({summary.get('unique_url_count', 0)}):",
    ]
    for url in summary.get("unique_urls") or []:
        lines.append(f"  - {url}")
    lines.append("")
    lines.append(f"Unique Domains ({summary.get('unique_domain_count', 0)}):")
    for domain in summary.get("unique_domains") or []:
        lines.append(f"  - {domain}")
    lines.append("")
    return "\n".join(lines)


def write_cluster_summary_files(summary: Dict[str, object], cluster_dir: Path) -> None:
    with (cluster_dir / "cluster_summary.json").open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    with (cluster_dir / "cluster_summary.txt").open("w", encoding="utf-8") as fh:
        fh.write(format_cluster_summary_text(summary))


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


def trace_has_network_request(trace: Dict) -> bool:
    return bool(get_network_request_entries(trace))


def trace_has_xhr_request(trace: Dict) -> bool:
    return any(entry_is_xhr_request(entry) for entry in get_network_request_entries(trace))


def apply_trace_filters(traces: Sequence[Dict], args: argparse.Namespace) -> List[Dict]:
    filtered = list(traces)
    if getattr(args, "require_network_requests", False):
        filtered = [trace for trace in filtered if trace_has_network_request(trace)]
    if getattr(args, "require_xhr_request", False):
        filtered = [trace for trace in filtered if trace_has_xhr_request(trace)]

    min_suspicious_events = max(0, int(getattr(args, "min_suspicious_events", 0) or 0))
    if min_suspicious_events:
        filtered = [
            trace
            for trace in filtered
            if int(trace.get("suspicious_event_count") or 0) >= min_suspicious_events
        ]

    wordpress_threshold = getattr(args, "wordpress_malicious_threshold", None)
    if wordpress_threshold is None:
        return filtered

    wp_filtered: List[Dict] = []
    for trace in filtered:
        if not is_wordpress_trace(trace):
            continue
        suspicious_calls = int(trace.get("suspicious_event_count") or 0)
        if suspicious_calls >= wordpress_threshold:
            wp_filtered.append(trace)
    return wp_filtered


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
        copied_traces: List[Tuple[Dict, str]] = []
        output_files: Dict[str, str] = {}
        for idx, trace in enumerate(selection.selected_traces, 1):
            ok, message = copy_trace(trace, cluster_dir, idx)
            if ok:
                copied += 1
                copied_traces.append((trace, message))
                output_files[trace["trace_id"]] = message
            else:
                print(f"[WARN] {message}", file=sys.stderr)
        if copied:
            write_manifest(selection, selection.trace_scores, cluster_dir, output_files)
            write_network_report(copied_traces, cluster_dir)
            total_clusters += 1
            total_files += copied
            print(
                "[INFO] Copied "
                f"{copied} samples for cache {cache_key} cluster {selection.cluster_id} "
                f"(rank {rank}, suspicious calls: {selection.suspicious_call_count}) -> {cluster_dir}"
            )

    return total_clusters, total_files


def extract_specific_cluster(cache_dir: Path, cluster_id: int, output_root: Path) -> None:
    report_path = cache_dir / "cluster_report.json"
    if not report_path.exists():
        raise SystemExit(f"No cluster_report.json found in {cache_dir}")

    cache_key = find_cache_key(cache_dir)
    report = load_json(report_path)
    str_cluster_id = str(cluster_id)
    cluster = None
    for entry in report.get("clusters", []):
        if str(entry.get("cluster_id")) == str_cluster_id:
            cluster = entry
            break
    if not cluster:
        raise SystemExit(f"Cluster {cluster_id} not found in {cache_dir}")

    traces = cluster.get("traces") or []
    if not traces:
        raise SystemExit(f"Cluster {cluster_id} in {cache_dir} does not contain any traces.")

    trace_scores = {trace["trace_id"]: compute_trace_score(trace) for trace in traces}
    cluster_score = sum(trace_scores.values()) / len(trace_scores) if trace_scores else 0.0
    suspicious_call_count = sum(int(trace.get("suspicious_event_count") or 0) for trace in traces)

    selection = ClusterSelection(
        cache_key=cache_key,
        cache_dir=cache_dir,
        cluster_id=str_cluster_id,
        cluster_score=cluster_score,
        suspicious_call_count=suspicious_call_count,
        selected_traces=list(traces),
        trace_scores=trace_scores,
    )

    cluster_dir = output_root / cache_key / f"cluster-{str_cluster_id}"
    cluster_dir.mkdir(parents=True, exist_ok=True)

    copied_traces: List[Tuple[Dict, str]] = []
    output_files: Dict[str, str] = {}
    copied_count = 0
    for idx, trace in enumerate(selection.selected_traces, 1):
        ok, filename = copy_trace(trace, cluster_dir, idx)
        if ok:
            copied_count += 1
            copied_traces.append((trace, filename))
            output_files[trace["trace_id"]] = filename
        else:
            print(f"[WARN] {filename}", file=sys.stderr)

    if copied_count:
        write_manifest(selection, selection.trace_scores, cluster_dir, output_files)
        write_network_report(copied_traces, cluster_dir)

    summary = build_cluster_summary(cache_key, cluster, traces)
    summary["copied_file_count"] = copied_count
    write_cluster_summary_files(summary, cluster_dir)

    print(
        "[INFO] Extracted "
        f"{copied_count} scripts for cache {cache_key} cluster {str_cluster_id} -> {cluster_dir}"
    )


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
    parser.add_argument(
        "--require-network-requests",
        action="store_true",
        help="Restrict samples to traces that issue Fetch/XHR/WebSocket/Beacon calls and emit a URL report per cluster.",
    )
    parser.add_argument(
        "--require-xhr-request",
        action="store_true",
        help="Only keep traces whose recorded network activity includes an explicit XHR request.",
    )
    parser.add_argument(
        "--min-suspicious-events",
        type=int,
        default=0,
        help="Discard traces with fewer than this many suspicious (malicious API) events before sampling (default: %(default)s).",
    )
    parser.add_argument(
        "--cluster-cache",
        help="Path to a specific cache directory (e.g., cache/all-3) to extract a single cluster.",
    )
    parser.add_argument(
        "--cluster-id",
        type=int,
        help="Cluster ID to extract when using --cluster-cache.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_root = Path(args.output_root)

    if args.cluster_cache:
        if args.cluster_id is None:
            raise SystemExit("--cluster-id must be provided when --cluster-cache is used.")
        cache_dir = Path(args.cluster_cache)
        if not cache_dir.exists():
            raise SystemExit(f"Cluster cache not found: {cache_dir}")
        extract_specific_cluster(cache_dir, args.cluster_id, output_root)
        return

    cache_root = Path(args.cache_root)
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
