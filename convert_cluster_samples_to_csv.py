#!/usr/bin/env python3
"""
Convert sampled cluster summaries into a CSV table enriched with plugin vulnerability details.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple
from urllib.parse import parse_qsl, urlparse

from scan_cluster import slugify_label


MATCHED_VERSION_RE = re.compile(r"\[matched versions:\s*([^\]]+)\]", re.IGNORECASE)
DEFAULT_COLUMNS = [
    "cache_key",
    "cluster_id",
    "members",
    "avg_silhouette",
    "avg_ast_similarity",
    "avg_virustotal_detections",
    "avg_suspicious_events_per_trace",
    "avg_trace_length",
    "copied_file_count",
    "unique_url_count",
    "unique_urls",
    "unique_domain_count",
    "unique_domains",
    "exact_plugin_matches",
    "recent_plugin_alerts",
    "top_plugin_domain_counts",
]
ROUND_DIGITS = 4
MULTILINE_FIELDS = {"unique_urls", "unique_domains", "exact_plugin_matches", "recent_plugin_alerts", "top_plugin_domain_counts"}
MULTILINE_SEPARATOR = "\n"
RECENT_VERSION_LABEL = "unspecified"
PLUGIN_PATH_MARKER = "/wp-content/plugins/"


def split_top_level(text: str, delimiter: str = ";") -> List[str]:
    """Split a string on a delimiter while ignoring delimiters inside parentheses."""
    if not text:
        return []
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(depth - 1, 0)
        if char == delimiter and depth == 0:
            piece = "".join(current).strip()
            if piece:
                parts.append(piece)
            current = []
            continue
        current.append(char)
    piece = "".join(current).strip()
    if piece:
        parts.append(piece)
    return parts


def parse_int(value: str) -> int:
    try:
        return int(float(value.strip()))
    except (TypeError, ValueError, AttributeError):
        return 0


def parse_asset_distribution(text: str) -> Dict[str, Dict[str, int]]:
    distribution: Dict[str, Dict[str, int]] = {}
    if not text or text.strip().lower() == "none":
        return distribution
    for entry in split_top_level(text):
        if not entry:
            continue
        entry = entry.strip()
        if "(" in entry and entry.endswith(")"):
            name, versions_text = entry.split("(", 1)
            name = name.strip()
            versions_text = versions_text[:-1]
            version_counts: Dict[str, int] = {}
            for chunk in versions_text.split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                if ":" in chunk:
                    version, count_text = chunk.split(":", 1)
                    version_counts[version.strip()] = parse_int(count_text)
            if version_counts:
                distribution[name] = version_counts
            continue
        if ":" in entry:
            name, count_text = entry.split(":", 1)
            name = name.strip()
            counts = distribution.setdefault(name, {})
            counts["unspecified"] = counts.get("unspecified", 0) + parse_int(count_text)
    return distribution


def parse_vulnerable_plugins(text: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    if not text or text.strip().lower() == "none":
        return entries
    for entry in split_top_level(text):
        if ":" not in entry:
            continue
        plugin, detail = entry.split(":", 1)
        plugin = plugin.strip()
        detail = detail.strip()
        match = MATCHED_VERSION_RE.search(detail)
        matched_versions: List[str] = []
        if match:
            matched_versions = [version.strip() for version in match.group(1).split(",") if version.strip()]
        detail_no_match = MATCHED_VERSION_RE.sub("", detail).strip()
        detail_no_match = detail_no_match.strip("[]").strip()
        vuln_id = detail_no_match.split()[0] if detail_no_match else ""
        entries.append(
            {
                "plugin": plugin,
                "detail": detail,
                "vuln_id": vuln_id,
                "matched_versions": matched_versions,
            }
        )
    return entries


def normalize_version_key(value: Any) -> str:
    text = str(value).strip().lower() if value not in (None, "") else ""
    return text or "unspecified"


def clamp_count(value: int, limit: int) -> int:
    if limit <= 0:
        return max(value, 0)
    return max(min(value, limit), 0)


def build_vuln_columns(
    vuln_entries: Sequence[Dict[str, Any]],
    plugin_distribution: Dict[str, Dict[str, int]],
    plugin_presence: Dict[str, Dict[str, Dict[str, Any]]],
    unique_domain_count: int,
) -> Tuple[List[str], List[str]]:
    excluded_plugins = {"elementor", "contact-form-7"}
    grouped_matches: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    grouped_recent: Dict[Tuple[str, str], List[str]] = defaultdict(list)

    def distribution_count(plugin: str, version: str | None = None) -> int:
        counts = plugin_distribution.get(plugin, {})
        if version is None:
            return sum(counts.values())
        count = counts.get(version)
        if count is None:
            normalized = normalize_version_key(version)
            if normalized == "unspecified":
                count = counts.get("unspecified", 0)
        return count or 0

    def domain_count(slug: str, version: str | None = None) -> Tuple[int, str]:
        entries = plugin_presence.get(slug) or {}
        if not entries:
            return 0, RECENT_VERSION_LABEL if version is None else (version or RECENT_VERSION_LABEL)
        if version is None:
            observed: Set[str] = set()
            for payload in entries.values():
                observed.update(payload.get("domains", set()))
            label = RECENT_VERSION_LABEL
            if len(entries) == 1:
                payload = next(iter(entries.values()))
                label = payload.get("label") or RECENT_VERSION_LABEL
            return len(observed), label
        normalized = normalize_version_key(version)
        payload = entries.get(normalized)
        if not payload and normalized == "unspecified":
            payload = entries.get("unspecified")
        if not payload:
            return 0, version or RECENT_VERSION_LABEL
        return len(payload.get("domains", set())), payload.get("label") or version or RECENT_VERSION_LABEL

    for entry in vuln_entries:
        plugin_label = entry["plugin"]
        if plugin_label.lower() in excluded_plugins:
            continue
        vuln_id = entry["vuln_id"] or "unknown"
        plugin_slug = slugify_label(plugin_label)
        matched_versions = entry.get("matched_versions") or []
        if matched_versions:
            for version in matched_versions:
                count, _ = domain_count(plugin_slug, version)
                if count <= 0:
                    count = clamp_count(distribution_count(plugin_label, version), unique_domain_count)
                if count <= 0:
                    continue
                grouped_matches[(plugin_label, version)].append(f"{vuln_id}:{count}")
            continue
        count, label = domain_count(plugin_slug, None)
        if count <= 0:
            count = clamp_count(distribution_count(plugin_label, None), unique_domain_count)
        if count <= 0:
            continue
        grouped_recent[(plugin_label, label or RECENT_VERSION_LABEL)].append(f"{vuln_id}:{count}")

    def serialize(grouped: Dict[Tuple[str, str], List[str]]) -> List[str]:
        entries: List[str] = []
        for (plugin, version), values in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1])):
            entries.append(f"{plugin}:{version}:{','.join(values)}")
        return entries

    return serialize(grouped_matches), serialize(grouped_recent)


def sanitize_header(text: str) -> str:
    text = text.strip().lower()
    chars: List[str] = []
    prev_underscore = False
    for char in text:
        if char.isalnum():
            chars.append(char)
            prev_underscore = False
        else:
            if not prev_underscore:
                chars.append("_")
                prev_underscore = True
    sanitized = "".join(chars).strip("_")
    return sanitized or "field"


def flatten_cluster_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
    row: Dict[str, Any] = {}
    for key, value in summary.items():
        if isinstance(value, (dict, list)):
            row[key] = json.dumps(value, sort_keys=True)
        else:
            row[key] = value
    return row


def load_cluster_summaries(sample_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for cluster_dir in sorted(sample_dir.glob("cluster-*")):
        summary_path = cluster_dir / "cluster_summary.json"
        if not summary_path.exists():
            continue
        with summary_path.open("r", encoding="utf-8") as fh:
            summary = json.load(fh)
        row = flatten_cluster_summary(summary)
        row["cluster_summary_path"] = str(summary_path)
        rows.append(row)
    return rows


def extract_domain(url: str | None) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    return parsed.netloc.lower()


def load_cluster_trace_info(sample_dir: Path) -> Dict[str, Dict[str, Any]]:
    info: Dict[str, Dict[str, Any]] = {}
    for cluster_dir in sorted(sample_dir.glob("cluster-*")):
        manifest_path = cluster_dir / "manifest.json"
        if not manifest_path.exists():
            continue
        with manifest_path.open("r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        cluster_id = str(manifest.get("cluster_id") or cluster_dir.name.split("-", 1)[-1])
        traces = manifest.get("traces") or []
        trace_ids: Set[str] = set()
        domain_map: Dict[str, str] = {}
        fingerprint_map: Dict[str, Path] = {}
        for trace in traces:
            if not isinstance(trace, dict):
                continue
            trace_id = trace.get("trace_id")
            if not trace_id:
                continue
            trace_ids.add(trace_id)
            page_url = trace.get("page_url") or trace.get("script_url")
            domain = extract_domain(page_url)
            if domain:
                domain_map[trace_id] = domain
            script_path = trace.get("script_path")
            if script_path:
                script_dir = Path(script_path).parent.parent
                fingerprint_map[trace_id] = script_dir / "fingerprint.json"
        info[cluster_id] = {"trace_ids": trace_ids, "domains": domain_map, "fingerprints": fingerprint_map}
    return info


def load_summary_rows(summary_csv: Path, cluster_ids: Iterable[str]) -> Dict[str, Dict[str, str]]:
    lookup: Dict[str, Dict[str, str]] = {}
    if not summary_csv.exists():
        return lookup
    wanted = {str(cid) for cid in cluster_ids}
    with summary_csv.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cluster_id = (row.get("cluster id") or "").strip()
            if not cluster_id or (wanted and cluster_id not in wanted):
                continue
            lookup[cluster_id] = row
    return lookup


def extract_plugin_from_url(url: str) -> Tuple[str, str | None]:
    try:
        parsed = urlparse(url)
    except ValueError:
        return "", None
    lower_path = parsed.path.lower()
    idx = lower_path.find(PLUGIN_PATH_MARKER)
    if idx == -1:
        return "", None
    remainder = lower_path[idx + len(PLUGIN_PATH_MARKER):]
    slug = remainder.split("/", 1)[0].strip()
    if not slug:
        return "", None
    version = None
    query = parsed.query
    if query:
        if "=" not in query:
            version = query
        else:
            for key, value in parse_qsl(query, keep_blank_values=True):
                if key == "ver" and value:
                    version = value
                    break
    return slugify_label(slug), version


def parse_fingerprint_plugins(fingerprint_path: Path) -> List[Dict[str, Any]]:
    try:
        with fingerprint_path.open("r", encoding="utf-8") as fh:
            fingerprint = json.load(fh)
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as exc:
        print(f"[WARN] Failed to parse fingerprint {fingerprint_path}: {exc}", file=sys.stderr)
        return []
    plugin_versions: Dict[str, Set[str]] = defaultdict(set)
    for url in fingerprint.get("resource_urls_with_wp_paths") or []:
        slug, version = extract_plugin_from_url(url)
        if not slug:
            continue
        plugin_versions[slug].add((version or RECENT_VERSION_LABEL).strip())
    plugins: List[Dict[str, Any]] = []
    for slug, versions in plugin_versions.items():
        for version in versions:
            plugins.append(
                {
                    "slug": slug,
                    "version": None if version == RECENT_VERSION_LABEL else version,
                }
            )
    return plugins


def build_cluster_plugin_presence(
    cluster_trace_info: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    presence: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for cluster_id, info in cluster_trace_info.items():
        trace_ids: Set[str] = info.get("trace_ids", set())  # type: ignore[assignment]
        domain_map: Dict[str, str] = info.get("domains", {})
        fingerprint_map: Dict[str, Path] = info.get("fingerprints", {})
        plugin_map: Dict[str, Dict[str, Any]] = {}
        for trace_id in trace_ids or []:
            domain = domain_map.get(trace_id)
            if not domain:
                continue
            fingerprint_path = fingerprint_map.get(trace_id)
            plugins = parse_fingerprint_plugins(fingerprint_path) if fingerprint_path else []
            for plugin in plugins:
                if not isinstance(plugin, dict):
                    continue
                slug = plugin.get("slug")
                if not slug:
                    continue
                version = plugin.get("version")
                normalized = normalize_version_key(version)
                label = str(version).strip() if version not in (None, "") else RECENT_VERSION_LABEL
                plugin_entry = plugin_map.setdefault(slug, {})
                version_entry = plugin_entry.setdefault(normalized, {"label": label, "domains": set()})
                version_entry["domains"].add(domain)
        presence[cluster_id] = plugin_map
    return presence


def summarize_top_plugins_by_domain(plugin_data: Dict[str, Dict[str, Any]], limit: int = 5) -> List[str]:
    entries: List[Tuple[str, int]] = []
    for slug, versions in plugin_data.items():
        domains: Set[str] = set()
        for payload in versions.values():
            domains.update(payload.get("domains", set()))
        if domains:
            entries.append((slug, len(domains)))
    entries.sort(key=lambda item: (-item[1], item[0]))
    return [f"{slug}:{count}" for slug, count in entries[:max(limit, 0)]]


def enrich_with_summary_data(
    rows: List[Dict[str, Any]],
    summary_rows: Dict[str, Dict[str, str]],
    plugin_presence: Dict[str, Dict[str, Dict[str, Any]]],
) -> None:
    for row in rows:
        cluster_id = str(row.get("cluster_id"))
        summary_row = summary_rows.get(cluster_id)
        if not summary_row:
            row["exact_plugin_matches"] = ""
            row["recent_plugin_alerts"] = ""
            continue
        for key, value in summary_row.items():
            if not key:
                continue
            sanitized = f"report_{sanitize_header(key)}"
            row[sanitized] = value
        plugin_distribution = parse_asset_distribution(summary_row.get("Cluster WordPress Distribution - Plugins", ""))
        vuln_entries = parse_vulnerable_plugins(summary_row.get("Vulnerable Plugins", ""))
        cluster_plugins = plugin_presence.get(cluster_id) or {}
        unique_domain_count = parse_int(str(row.get("unique_domain_count"))) if row.get("unique_domain_count") is not None else 0
        exact_entries, recent_alerts = build_vuln_columns(
            vuln_entries,
            plugin_distribution,
            cluster_plugins,
            unique_domain_count,
        )
        row["exact_plugin_matches"] = " | ".join(exact_entries)
        row["recent_plugin_alerts"] = " | ".join(recent_alerts)
        top_plugin_entries = summarize_top_plugins_by_domain(cluster_plugins, limit=5)
        row["top_plugin_domain_counts"] = " | ".join(top_plugin_entries)


def format_numeric(value: Any, digits: int) -> str:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{numeric:.{digits}f}"


def format_multiline(value: Any, separator: str) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ""
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return separator.join(str(item) for item in parsed)
        except json.JSONDecodeError:
            pass
        if " | " in text:
            return text.replace(" | ", separator)
        return text
    if isinstance(value, list):
        return separator.join(str(item) for item in value)
    return str(value)


def apply_formatting(
    rows: List[Dict[str, Any]],
    digits: int | None,
    multiline_fields: Sequence[str],
    separator: str,
) -> None:
    multiline_set = {field.strip() for field in multiline_fields if field}
    for row in rows:
        for key, value in list(row.items()):
            formatted = value
            if digits is not None and isinstance(value, (int, float)):
                formatted = format_numeric(value, digits)
            if key in multiline_set:
                formatted = format_multiline(formatted, separator)
            row[key] = formatted


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert cluster summaries to CSV.")
    parser.add_argument("--cache-id", required=True, help="Cache identifier (e.g., all-15).")
    parser.add_argument(
        "--samples-root",
        default="samples",
        help="Directory containing per-cache sample folders.",
    )
    parser.add_argument(
        "--summary-csv",
        help="Path to the cache summary CSV (defaults to <samples>/<cache-id>/<cache-id>_summary.csv).",
    )
    parser.add_argument(
        "--output",
        help="Path to the aggregated CSV (defaults to <samples>/<cache-id>/<cache-id>_clusters.csv).",
    )
    args = parser.parse_args()

    sample_dir = Path(args.samples_root) / args.cache_id
    if not sample_dir.exists():
        raise SystemExit(f"Sample directory not found: {sample_dir}")

    rows = load_cluster_summaries(sample_dir)
    if not rows:
        raise SystemExit(f"No cluster_summary.json files found in {sample_dir}")

    summary_csv = Path(args.summary_csv) if args.summary_csv else sample_dir / f"{args.cache_id}_summary.csv"
    summary_rows = load_summary_rows(summary_csv, {str(row.get("cluster_id")) for row in rows})

    cluster_trace_info = load_cluster_trace_info(sample_dir)
    plugin_presence = build_cluster_plugin_presence(cluster_trace_info)

    enrich_with_summary_data(rows, summary_rows, plugin_presence)

    apply_formatting(rows, ROUND_DIGITS, MULTILINE_FIELDS, MULTILINE_SEPARATOR)

    output_path = Path(args.output) if args.output else sample_dir / f"{args.cache_id}_sampled_clusters.csv"
    fieldnames = DEFAULT_COLUMNS
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in fieldnames})
    print(f"Wrote {len(rows)} rows to {output_path}")


if __name__ == "__main__":
    main()
