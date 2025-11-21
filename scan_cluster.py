#!/usr/bin/env python3
"""
Fast cluster summary exporter.

Given a cache key such as ``all-1`` this script reads the corresponding
``cluster_report.json`` and emits a CSV with the most relevant metrics so the
result can be reviewed or shared quickly.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from textwrap import fill
from typing import Any, Iterable, Mapping, Sequence

try:
    from tqdm import tqdm
except ImportError as exc:  # pragma: no cover - optional dependency
    tqdm = None

try:
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover - optional dependency
    Version = None
    InvalidVersion = Exception


def load_report(cache_root: Path, cache_key: str) -> Sequence[Mapping]:
    report_path = cache_root / cache_key / "cluster_report.json"
    if not report_path.exists():
        raise FileNotFoundError(f"cluster report not found: {report_path}")
    with report_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    clusters = payload.get("clusters") or []
    return clusters


def format_neighbors(neighbors: Iterable[Mapping]) -> str:
    entries = []
    for item in neighbors or []:
        cid = item.get("cluster_id")
        distance = item.get("distance")
        if cid is None:
            continue
        if distance is None:
            entries.append(f"{cid}")
        else:
            entries.append(f"{cid} ({float(distance):.4f})")
    return "; ".join(entries)


LABEL_PATTERN = re.compile(r"^(?P<name>.+?)\s*\((?P<version>[^()]+)\)\s*$")
VERSION_PATTERN = re.compile(r"^[0-9A-Za-z._-]+$")
RANGE_VERSION_PATTERN = re.compile(r"([0-9][0-9A-Za-z._-]*)\s*[\-–—]\s*([0-9][0-9A-Za-z._-]*)")
OP_VERSION_PATTERN = re.compile(r"(<=|>=|<|>|=)\s*([0-9][0-9A-Za-z._-]*)")


def parse_label(label: str) -> tuple[str, str | None]:
    match = LABEL_PATTERN.match(label)
    if not match:
        return label.strip(), None
    return match.group("name").strip(), match.group("version").strip()


def normalize_version(version: str | None) -> str | None:
    if not version:
        return None
    return version if VERSION_PATTERN.match(version) else None


def aggregate_distribution(items: Iterable[Mapping]) -> list[dict[str, object]]:
    aggregates: dict[str, dict[str | None, float]] = {}
    for item in items or []:
        label = item.get("label")
        count = item.get("count")
        if not label:
            continue
        try:
            count_val = float(count)
        except (TypeError, ValueError):
            continue
        base, version = parse_label(label)
        version = normalize_version(version)
        version_map = aggregates.setdefault(base, {})
        version_map[version] = version_map.get(version, 0.0) + count_val

    entries: list[dict[str, object]] = []
    for base, versions in aggregates.items():
        total = sum(versions.values())
        entries.append({"base": base, "total": total, "versions": versions})
    entries.sort(key=lambda entry: (-entry["total"], entry["base"]))
    return entries


def format_distribution(entries: list[dict[str, object]]) -> str:
    parts = []
    for entry in entries:
        base = entry["base"]
        total = float(entry["total"])
        versions: dict[str | None, float] = entry["versions"]
        if len(versions) <= 1 and None in versions:
            value = int(total) if total.is_integer() else total
            parts.append(f"{base}: {value}")
            continue
        segments = []
        for version, subtotal in sorted(versions.items(), key=lambda kv: (-kv[1], kv[0] or "")):
            label = version or "unspecified"
            value = int(subtotal) if subtotal.is_integer() else subtotal
            segments.append(f"{label}: {value}")
        parts.append(f"{base} ({', '.join(segments)})")
    return "; ".join(parts)


def summarize_top(entries: list[dict[str, object]], limit: int = 3) -> str:
    parts = []
    for entry in entries[:limit]:
        total = float(entry["total"])
        value = int(total) if total.is_integer() else total
        parts.append(f"{entry['base']}: {value}")
    return "; ".join(parts)


def format_float(value: Any, precision: int = 3) -> str:
    if value is None or value == "":
        return "N/A"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{number:.{precision}f}"


def wrap_text(value: Any) -> str:
    text = "None" if value is None or value == "" else str(value)
    return fill(text, width=TEXT_WIDTH, drop_whitespace=False)


WORDFENCE_API_URL = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities"
WORDFENCE_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 "
        "Mobile/15E148 Safari/604.1"
    ),
    "Accept": "application/json",
}

SECTION_SEPARATOR = "-" * 72
TEXT_WIDTH = 100


def ensure_tqdm_available() -> None:
    if tqdm is None:
        raise SystemExit("tqdm is required. Install it via `pip install tqdm`.")


def progress_iter(iterable: Sequence[Any], description: str) -> Iterable[Any]:
    if tqdm is None:
        return iterable
    return tqdm(iterable, desc=description, total=len(iterable))


def collect_active_slugs(clusters: Sequence[Mapping]) -> set[str]:
    slugs: set[str] = set()
    for cluster in clusters:
        for key in ("wordpress_plugins", "wordpress_themes"):
            for item in cluster.get(key) or []:
                label = item.get("label")
                if not label:
                    continue
                base, _ = parse_label(label)
                slugs.add(slugify_label(base))
    return slugs


def slugify_label(label: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
    return slug


def load_vulnerability_map(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    normalized: dict[str, Any] = {}
    for key, entries in raw.items():
        if not entries:
            continue
        slug = key.strip().lower()
        processed = []
        for entry in entries:
            if not entry:
                continue
            constraints = parse_constraints(entry.get("title") or "")
            processed.append({
                "cve": entry.get("cve"),
                "wordfence_uuid": entry.get("wordfence_uuid"),
                "title": entry.get("title") or "",
                "constraint_groups": wrap_constraint_groups(constraints),
            })
        if processed:
            normalized[slug] = processed
    return normalized


def parse_constraints(text: str) -> list[dict[str, str]]:
    constraints: list[dict[str, str]] = []
    for match in RANGE_VERSION_PATTERN.finditer(text):
        constraints.append({"type": "range", "low": match.group(1), "high": match.group(2)})
    for match in OP_VERSION_PATTERN.finditer(text):
        constraints.append({"type": "op", "op": match.group(1), "version": match.group(2)})
    return constraints


def wrap_constraint_groups(constraints: list[dict[str, str]]) -> list[list[dict[str, str]]]:
    return [constraints] if constraints else []


def _split_version(value: str) -> list[Any]:
    tokens = []
    for part in re.split(r"[._-]", value):
        if not part:
            continue
        if part.isdigit():
            tokens.append(int(part))
        else:
            tokens.append(part.lower())
    return tokens or [value]


def _compare_token(x: Any, y: Any) -> int:
    if isinstance(x, int) and isinstance(y, int):
        return (x > y) - (x < y)
    xs = str(x)
    ys = str(y)
    return (xs > ys) - (xs < ys)


def compare_versions(a: str, b: str) -> int:
    if not a or not b:
        return 0
    if Version is not None:
        try:
            va = Version(a)
            vb = Version(b)
            if va < vb:
                return -1
            if va > vb:
                return 1
            return 0
        except InvalidVersion:
            pass

    seq_a = _split_version(a)
    seq_b = _split_version(b)
    max_len = max(len(seq_a), len(seq_b))
    for idx in range(max_len):
        val_a = seq_a[idx] if idx < len(seq_a) else 0
        val_b = seq_b[idx] if idx < len(seq_b) else 0
        cmp = _compare_token(val_a, val_b)
        if cmp != 0:
            return cmp
    return 0


def version_sort_key(value: str) -> Any:
    if Version is not None:
        try:
            return (0, Version(value))
        except InvalidVersion:
            pass
    def token_key(token: Any) -> tuple[int, Any]:
        if isinstance(token, int):
            return (0, token)
        return (1, str(token))

    return (1, tuple(token_key(token) for token in _split_version(value)))


def version_satisfies(version: str, constraint_groups: list[list[dict[str, Any]]]) -> bool:
    if not constraint_groups:
        return True
    for group in constraint_groups:
        if all(_constraint_match(version, constraint) for constraint in group):
            return True
    return False


def _constraint_match(version: str, constraint: Mapping[str, Any]) -> bool:
    kind = constraint.get("type")
    if kind == "range":
        low = constraint.get("low")
        high = constraint.get("high")
        low_inclusive = constraint.get("low_inclusive", True)
        high_inclusive = constraint.get("high_inclusive", True)
        if low:
            cmp = compare_versions(version, low)
            if cmp < 0 or (cmp == 0 and not low_inclusive):
                return False
        if high:
            cmp = compare_versions(version, high)
            if cmp > 0 or (cmp == 0 and not high_inclusive):
                return False
        return True
    if kind == "op":
        op = constraint.get("op")
        target = constraint.get("version")
        if not op or not target:
            return True
        cmp = compare_versions(version, target)
        if op == "<=":
            return cmp <= 0
        if op == "<":
            return cmp < 0
        if op == ">=":
            return cmp >= 0
        if op == ">":
            return cmp > 0
        if op == "=":
            return cmp == 0
    return True


def format_vuln_identifier(vuln: Mapping[str, Any]) -> str:
    cve = vuln.get("cve")
    if cve:
        return cve
    uuid = vuln.get("wordfence_uuid")
    return f"WF-{uuid}" if uuid else "unknown"


def summarize_vulnerabilities(entries: list[dict[str, object]], vuln_map: Mapping[str, Any]) -> str:
    segments: list[str] = []
    for entry in entries:
        slug = slugify_label(str(entry["base"]))
        vulns = vuln_map.get(slug)
        if not vulns:
            continue
        versions: dict[str | None, float] = entry.get("versions", {})  # type: ignore[assignment]
        for version in sorted((str(v) for v in versions.keys() if v), key=version_sort_key):
            matched = [
                vuln for vuln in vulns
                if version_satisfies(version, vuln.get("constraint_groups") or [])
            ]
            if not matched:
                continue
            ids = ", ".join(format_vuln_identifier(v) for v in matched)
            segments.append(f"{entry['base']} {version}: {ids}")
        if None in versions:
            unconstrained = [vuln for vuln in vulns if not vuln.get("constraint_groups")]
            if unconstrained:
                ids = ", ".join(format_vuln_identifier(v) for v in unconstrained)
                segments.append(f"{entry['base']}: {ids}")
    return "; ".join(segments)


def verify_with_wordfence(
    slugs: Sequence[str],
    delay: float,
    timeout: float,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    if not slugs:
        return results
    ensure_tqdm_available()
    iterator = progress_iter(list(slugs), "Verifying CVEs")
    for idx, slug in enumerate(iterator):
        if idx > 0 and delay > 0:
            time.sleep(delay)
        try:
            entries = fetch_wordfence_entries(slug, timeout)
        except urllib.error.HTTPError as err:  # pragma: no cover - network failure
            if err.code == 429:
                retry_delay = max(5.0, delay * 2)
                time.sleep(retry_delay)
                try:
                    entries = fetch_wordfence_entries(slug, timeout)
                except Exception as exc:  # pragma: no cover - network failure
                    print(f"Warning: Wordfence lookup failed for {slug}: {exc}", file=sys.stderr)
                    continue
            else:
                print(f"Warning: Wordfence lookup failed for {slug}: {err}", file=sys.stderr)
                continue
        except urllib.error.URLError as err:  # pragma: no cover - network failure
            is_timeout = isinstance(err.reason, socket.timeout) or "timed out" in str(err.reason).lower()
            if is_timeout:
                print(f"Warning: Wordfence timeout for {slug}, resting 300s...", file=sys.stderr)
                time.sleep(300)
                try:
                    entries = fetch_wordfence_entries(slug, timeout)
                except Exception as exc:  # pragma: no cover - network failure
                    print(f"Warning: Wordfence lookup failed for {slug}: {exc}", file=sys.stderr)
                    continue
            else:
                print(f"Warning: Wordfence lookup failed for {slug}: {err}", file=sys.stderr)
                continue
        except Exception as exc:  # pragma: no cover - network failure
            print(f"Warning: Wordfence lookup failed for {slug}: {exc}", file=sys.stderr)
            continue
        if entries:
            results[slug] = entries
    return results


def fetch_wordfence_entries(slug: str, timeout: float) -> list[dict[str, Any]]:
    params = urllib.parse.urlencode({"search": slug})
    url = f"{WORDFENCE_API_URL}?{params}"
    request = urllib.request.Request(url, headers=WORDFENCE_HEADERS)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        payload = json.load(response)

    normalized: list[dict[str, Any]] = []
    for entry in payload.values():
        cve = entry.get("cve")
        uuid = entry.get("id")
        title = entry.get("title") or ""
        for software in entry.get("software", []):
            target_slug = (software.get("slug") or "").strip().lower()
            fallback_slug = slugify_label(software.get("name", ""))
            if slug not in (target_slug, fallback_slug):
                continue
            groups = convert_wordfence_constraints(software.get("affected_versions") or {})
            normalized.append({
                "cve": cve,
                "wordfence_uuid": uuid,
                "title": title,
                "constraint_groups": groups,
            })
    return normalized


def convert_wordfence_constraints(affected_versions: Mapping[str, Any]) -> list[list[dict[str, Any]]]:
    groups: list[list[dict[str, Any]]] = []
    for details in affected_versions.values():
        low = details.get("from_version")
        high = details.get("to_version")
        low = None if not low or low == "*" else low
        high = None if not high or high == "*" else high
        constraint = {
            "type": "range",
            "low": low,
            "high": high,
            "low_inclusive": details.get("from_inclusive", True),
            "high_inclusive": details.get("to_inclusive", True),
        }
        groups.append([constraint])
    return groups


def load_wordfence_cache(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError:
            return {}
    normalized: dict[str, Any] = {}
    for key, entries in data.items():
        if isinstance(entries, list):
            normalized[key] = entries
    return normalized


def save_wordfence_cache(path: Path | None, cache: Mapping[str, Any]) -> None:
    if path is None:
        return
    snapshot = {key: value for key, value in cache.items() if value}
    tmp_path = path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
    tmp_path.replace(path)


def average_from_traces(traces: Sequence[Mapping], key: str) -> float | None:
    total = 0.0
    count = 0
    for trace in traces or []:
        value = trace.get(key)
        if value is None:
            continue
        try:
            total += float(value)
            count += 1
        except (TypeError, ValueError):
            continue
    return (total / count) if count else None


def build_rows(clusters: Sequence[Mapping], vuln_map: Mapping[str, Any]) -> list[dict[str, str]]:
    ensure_tqdm_available()
    rows = []
    cluster_list = list(clusters)
    for cluster in progress_iter(cluster_list, "Summarizing clusters"):
        traces = cluster.get("traces") or []
        avg_suspicious = average_from_traces(traces, "suspicious_event_count")
        avg_trace_len = cluster.get("average_events_per_script")
        if avg_trace_len is None:
            avg_trace_len = average_from_traces(traces, "num_events")
        plugin_entries = aggregate_distribution(cluster.get("wordpress_plugins"))
        theme_entries = aggregate_distribution(cluster.get("wordpress_themes"))
        rows.append({
            "cluster id": cluster.get("cluster_id"),
            "number of data points in the cluster": cluster.get("count"),
            "Cluster Avg Silhouette Similarity": cluster.get("silhouette"),
            "Cluster Avg AST Similarity": cluster.get("ast_similarity"),
            "Cluster Avg VT Detections": cluster.get("virustotal_average_verdict_count"),
            "Avg Suspicious Events per Trace": avg_suspicious,
            "Avg Trace Length": avg_trace_len,
            "Nearest Clusters": format_neighbors(cluster.get("closest_clusters")),
            "Cluster WordPress Distribution - Plugins": format_distribution(plugin_entries),
            "Cluster WordPress Distribution - Thmes": format_distribution(theme_entries),
            "Top 3 Plugins": summarize_top(plugin_entries),
            "Top 3 Themes": summarize_top(theme_entries),
            "Vulnerable Plugins": summarize_vulnerabilities(plugin_entries, vuln_map),
            "Vulnerable Themes": summarize_vulnerabilities(theme_entries, vuln_map),
        })
    return rows


def write_csv(rows: Sequence[Mapping], output_path: Path) -> None:
    if not rows:
        output_path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_text_block(row: Mapping[str, Any]) -> str:
    lines = [
        f"Cluster {row.get('cluster id', 'Unknown')}",
        SECTION_SEPARATOR,
        f"Members: {row.get('number of data points in the cluster', 'N/A')}",
        f"Avg Silhouette: {format_float(row.get('Cluster Avg Silhouette Similarity', ''))}",
        (
            "Avg AST Similarity: "
            f"{format_float(row.get('Cluster Avg AST Similarity', ''), precision=6)}"
        ),
        f"Avg VirusTotal Detections: {format_float(row.get('Cluster Avg VT Detections', ''))}",
        f"Avg Suspicious Events per Trace: {format_float(row.get('Avg Suspicious Events per Trace', ''))}",
        f"Avg Trace Length: {format_float(row.get('Avg Trace Length', ''))}",
        f"Nearest Clusters: {row.get('Nearest Clusters') or 'None'}",
        "",
        "WordPress Plugin Distribution:",
        wrap_text(row.get('Cluster WordPress Distribution - Plugins', '')),
        "",
        "WordPress Theme Distribution:",
        wrap_text(row.get('Cluster WordPress Distribution - Thmes', '')),
        "",
        "Top Plugins:",
        wrap_text(row.get('Top 3 Plugins', '')),
        "",
        "Top Themes:",
        wrap_text(row.get('Top 3 Themes', '')),
        "",
        "Known Vulnerable Plugins:",
        wrap_text(row.get('Vulnerable Plugins', '')),
        "",
        "Known Vulnerable Themes:",
        wrap_text(row.get('Vulnerable Themes', '')),
    ]
    return "\n".join(lines)


def write_text_report(rows: Sequence[Mapping], output_path: Path) -> None:
    blocks = [build_text_block(row) for row in rows]
    report = "\n\n\n".join(blocks)
    output_path.write_text(report, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a cached cluster report and export key metrics to CSV."
    )
    parser.add_argument("cluster_key", help="Cluster/cache identifier (e.g. all-1).")
    parser.add_argument(
        "--cache-root",
        default="cache",
        help="Directory containing cluster cache folders (default: cache).",
    )
    parser.add_argument(
        "--output",
        help="Path to write CSV (default: <cluster_key>_summary.csv).",
    )
    parser.add_argument(
        "--vuln-data",
        default="plugin_vulnerabilities.json",
        help="Path to plugin/theme vulnerability JSON (default: plugin_vulnerabilities.json).",
    )
    parser.add_argument(
        "--wordfence-cache",
        default="wordfence_cache.json",
        help="Path to store Wordfence API results (default: wordfence_cache.json).",
    )
    parser.add_argument(
        "--no-verify-cves",
        action="store_true",
        help="Skip verifying CVEs against the Wordfence API.",
    )
    parser.add_argument(
        "--wordfence-delay",
        type=float,
        default=3.0,
        help="Delay between Wordfence API requests, in seconds (default: 3).",
    )
    parser.add_argument(
        "--wordfence-timeout",
        type=float,
        default=30.0,
        help="Timeout for Wordfence API requests, in seconds (default: 30).",
    )
    parser.add_argument(
        "--text-report",
        default="cluster_summary_report.txt",
        help="Path to write the text report (default: %(default)s).",
    )
    parser.add_argument(
        "--no-text-report",
        action="store_true",
        help="Disable text report generation.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_tqdm_available()
    cache_root = Path(args.cache_root)
    vuln_path = Path(args.vuln_data) if args.vuln_data else None
    cache_path = Path(args.wordfence_cache) if args.wordfence_cache else None
    clusters = list(load_report(cache_root, args.cluster_key))
    active_slugs = sorted(collect_active_slugs(clusters))
    vuln_map = load_vulnerability_map(vuln_path)
    wordfence_cache = load_wordfence_cache(cache_path)
    for slug, entries in wordfence_cache.items():
        vuln_map[slug] = entries
    if not args.no_verify_cves:
        slugs_to_verify = [slug for slug in active_slugs if slug not in wordfence_cache]
        fetched = verify_with_wordfence(slugs_to_verify, args.wordfence_delay, args.wordfence_timeout)
        if fetched:
            for slug, entries in fetched.items():
                vuln_map[slug] = entries
                wordfence_cache[slug] = entries
            save_wordfence_cache(cache_path, wordfence_cache)
    rows = build_rows(clusters, vuln_map)
    output_path = Path(args.output or f"{args.cluster_key}_summary.csv")
    write_csv(rows, output_path)
    if not args.no_text_report:
        text_path = Path(args.text_report)
        write_text_report(rows, text_path)
        print(f"Saved text report to {text_path}")
    print(f"Saved {len(rows)} clusters to {output_path}")


if __name__ == "__main__":
    main()
