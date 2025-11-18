#!/usr/bin/env python3
"""
Correlate suspicious capability clusters with recurring WordPress plugins/themes.

The script loads ``clustering_results.pkl`` (or another pickle in the same
format), determines which traces look suspicious, and then reports plugins/themes
that almost always appear alongside those traces inside each cluster.  This
helps spot potential supply-chain pivots where a compromised plugin drags the
same malicious payload into every site that uses it.
"""

from __future__ import annotations

import argparse
import pickle
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Set, Tuple


# Capabilities that should flag a trace as suspicious even if the heuristic
# detector did not emit explicit "suspicious events".
DEFAULT_HIGH_RISK_CAPABILITIES = {
    "DOM_INJECT_SCRIPT",
    "DOM_INJECT_IFRAME",
    "DOM_INJECT_HTML",
    "DOM_INJECT_CSS",
    "DOM_INJECT_NODE",
    "DOM_INJECT_STYLE",
    "DOM_INJECT_WORKER",
    "DOM_INJECT_IMAGE",
    "DOM_INJECT_SOURCE",
    "DOM_INJECT_EVENT",
    "DOM_INJECT_PROP",
    "DOM_INJECT_STORAGE",
    "NET_XHR",
    "NET_FETCH",
    "NET_SOCKET",
    "NET_BEACON",
    "NET_WEBSOCKET",
    "NET_WEBRTC",
    "NET_REQUEST",
    "OBFUSCATION",
    "FINGERPRINTING",
    "CLIPBOARD",
    "WORKLET",
    "WORKER",
    "BLOB",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Highlight plugins/themes that consistently appear with suspicious traces."
    )
    parser.add_argument(
        "--results",
        default="clustering_results.pkl",
        help="Path to clustering results pickle (default: %(default)s)",
    )
    parser.add_argument(
        "--min-support",
        type=int,
        default=3,
        help="Minimum number of suspicious traces per plugin/theme to keep (default: %(default)s)",
    )
    parser.add_argument(
        "--min-ratio",
        type=float,
        default=0.6,
        help="Minimum suspicious/total ratio per plugin/theme to include (default: %(default)s)",
    )
    parser.add_argument(
        "--min-suspicious-events",
        type=int,
        default=1,
        help="Treat traces with at least this many suspicious events as malicious (default: %(default)s)",
    )
    parser.add_argument(
        "--risk-capability",
        action="append",
        dest="risk_capabilities",
        default=None,
        help="Additional capability label that should mark a trace as suspicious "
        "(may be supplied multiple times). Defaults to a built-in high-risk list.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Maximum number of plugins/themes to show per cluster and in the global summary (default: %(default)s)",
    )
    return parser.parse_args()


def unique_asset_names(items: Iterable[Mapping[str, object] | None]) -> List[str]:
    names: List[str] = []
    seen: Set[str] = set()
    for item in items or []:
        if not item:
            continue
        raw = item.get("name")  # type: ignore[attr-defined]
        if not isinstance(raw, str):
            continue
        label = raw.strip()
        if not label or label in seen:
            continue
        seen.add(label)
        names.append(label)
    return names


def is_suspicious_trace(
    trace: Mapping[str, object],
    min_susp_events: int,
    risk_capabilities: Set[str],
) -> bool:
    try:
        susp_events = int(trace.get("suspicious_event_count", 0))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        susp_events = 0
    if susp_events >= min_susp_events > 0:
        return True
    capabilities = trace.get("capability_counts") or {}
    if isinstance(capabilities, Mapping):
        for label in risk_capabilities:
            try:
                if capabilities.get(label, 0) > 0:
                    return True
            except AttributeError:
                break
    return False


def summarize_cap_cluster(counter: Counter) -> str:
    if not counter:
        return "n/a"
    parts = [f"{cluster_id}:{count}" for cluster_id, count in counter.most_common()]
    return ", ".join(parts)


def iter_candidates(
    entries: Mapping[str, Dict[str, object]],
    min_support: int,
    min_ratio: float,
) -> List[Tuple[float, int, int, str, Dict[str, object]]]:
    candidates: List[Tuple[float, int, int, str, Dict[str, object]]] = []
    for name, payload in entries.items():
        total = int(payload.get("total", 0))
        suspicious = int(payload.get("suspicious", 0))
        if not total:
            continue
        ratio = suspicious / total
        if suspicious >= min_support and ratio >= min_ratio:
            candidates.append((ratio, suspicious, total, name, payload))
    candidates.sort(key=lambda item: (item[0], item[1], item[3]), reverse=True)
    return candidates


def build_stats(
    traces: Iterable[Mapping[str, object]],
    min_susp_events: int,
    risk_capabilities: Set[str],
) -> Tuple[
    Dict[int, Dict[str, object]],
    Dict[str, Dict[str, object]],
    Dict[str, Dict[str, object]],
]:
    cluster_stats: Dict[int, Dict[str, object]] = defaultdict(
        lambda: {
            "total": 0,
            "suspicious": 0,
            "plugins": defaultdict(lambda: {"total": 0, "suspicious": 0, "cap_clusters": Counter()}),
            "themes": defaultdict(lambda: {"total": 0, "suspicious": 0, "cap_clusters": Counter()}),
        }
    )
    plugin_totals: Dict[str, Dict[str, object]] = defaultdict(
        lambda: {
            "total": 0,
            "suspicious": 0,
            "clusters": Counter(),
            "cap_clusters": Counter(),
        }
    )
    theme_totals: Dict[str, Dict[str, object]] = defaultdict(
        lambda: {
            "total": 0,
            "suspicious": 0,
            "clusters": Counter(),
            "cap_clusters": Counter(),
        }
    )

    for trace in traces:
        try:
            cluster_id = int(trace.get("cluster", -1))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            cluster_id = -1
        try:
            cap_cluster = int(trace.get("capability_cluster", -1))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            cap_cluster = -1
        suspicious = is_suspicious_trace(trace, min_susp_events, risk_capabilities)
        plugins = unique_asset_names(trace.get("wordpress_plugins") or [])
        themes = unique_asset_names(trace.get("wordpress_themes") or [])

        cluster_entry = cluster_stats[cluster_id]
        cluster_entry["total"] += 1
        if suspicious:
            cluster_entry["suspicious"] += 1

        for name in plugins:
            plugin_entry = cluster_entry["plugins"][name]
            plugin_entry["total"] += 1
            if suspicious:
                plugin_entry["suspicious"] += 1
                plugin_entry["cap_clusters"][cap_cluster] += 1

            global_entry = plugin_totals[name]
            global_entry["total"] += 1
            global_entry["clusters"][cluster_id] += 1
            if suspicious:
                global_entry["suspicious"] += 1
                global_entry["cap_clusters"][cap_cluster] += 1

        for name in themes:
            theme_entry = cluster_entry["themes"][name]
            theme_entry["total"] += 1
            if suspicious:
                theme_entry["suspicious"] += 1
                theme_entry["cap_clusters"][cap_cluster] += 1

            global_entry = theme_totals[name]
            global_entry["total"] += 1
            global_entry["clusters"][cluster_id] += 1
            if suspicious:
                global_entry["suspicious"] += 1
                global_entry["cap_clusters"][cap_cluster] += 1

    return cluster_stats, plugin_totals, theme_totals


def render_cluster_sections(
    cluster_stats: Mapping[int, Dict[str, object]],
    min_support: int,
    min_ratio: float,
    top_n: int,
) -> None:
    for cluster_id in sorted(cluster_stats.keys()):
        stats = cluster_stats[cluster_id]
        total = int(stats["total"])
        suspicious = int(stats["suspicious"])
        if total == 0 or suspicious == 0:
            continue
        ratio = suspicious / total
        print("=" * 100)
        print(f"Cluster {cluster_id} — suspicious traces: {suspicious}/{total} ({ratio:.1%})")
        print("=" * 100)

        plugin_candidates = iter_candidates(stats["plugins"], min_support, min_ratio)[:top_n]
        if plugin_candidates:
            print("Plugins tightly coupled with suspicious traces:")
            for ratio, susp, total_count, name, payload in plugin_candidates:
                caps = summarize_cap_cluster(payload.get("cap_clusters", Counter()))
                print(
                    f"  - {name}: {susp}/{total_count} suspicious ({ratio:.1%}); "
                    f"capability clusters: {caps}"
                )
        else:
            print("Plugins tightly coupled with suspicious traces: None")

        theme_candidates = iter_candidates(stats["themes"], min_support, min_ratio)[:top_n]
        if theme_candidates:
            print("Themes tightly coupled with suspicious traces:")
            for ratio, susp, total_count, name, payload in theme_candidates:
                caps = summarize_cap_cluster(payload.get("cap_clusters", Counter()))
                print(
                    f"  - {name}: {susp}/{total_count} suspicious ({ratio:.1%}); "
                    f"capability clusters: {caps}"
                )
        else:
            print("Themes tightly coupled with suspicious traces: None")
        print()


def render_global_summary(
    title: str,
    totals: Mapping[str, Dict[str, object]],
    min_support: int,
    min_ratio: float,
    top_n: int,
) -> None:
    print("=" * 100)
    print(title)
    print("=" * 100)
    candidates = iter_candidates(totals, min_support, min_ratio)[:top_n]
    if not candidates:
        print("No entries met the thresholds.\n")
        return
    for ratio, susp, total, name, payload in candidates:
        clusters = payload.get("clusters", Counter())
        cluster_preview = ", ".join(
            f"{cluster_id}:{count}" for cluster_id, count in clusters.most_common(5)
        ) or "n/a"
        caps = summarize_cap_cluster(payload.get("cap_clusters", Counter()))
        print(
            f"- {name}: {susp}/{total} suspicious ({ratio:.1%}); "
            f"clusters: {cluster_preview}; capability clusters: {caps}"
        )
    print()


def main() -> None:
    args = parse_args()
    results_path = Path(args.results)
    if not results_path.exists():
        raise SystemExit(f"Results file not found: {results_path}")

    with results_path.open("rb") as fh:
        results = pickle.load(fh)
    traces = results.get("traces")
    if not isinstance(traces, list):
        raise SystemExit("Unexpected results format: 'traces' missing or invalid.")

    risk_capabilities = (
        set(args.risk_capabilities) if args.risk_capabilities else set(DEFAULT_HIGH_RISK_CAPABILITIES)
    )

    cluster_stats, plugin_totals, theme_totals = build_stats(
        traces,
        min_susp_events=args.min_suspicious_events,
        risk_capabilities=risk_capabilities,
    )

    render_cluster_sections(
        cluster_stats,
        min_support=args.min_support,
        min_ratio=args.min_ratio,
        top_n=args.top,
    )

    render_global_summary(
        "Global plugin summary",
        plugin_totals,
        min_support=args.min_support,
        min_ratio=args.min_ratio,
        top_n=args.top,
    )
    render_global_summary(
        "Global theme summary",
        theme_totals,
        min_support=args.min_support,
        min_ratio=args.min_ratio,
        top_n=args.top,
    )


if __name__ == "__main__":
    main()
