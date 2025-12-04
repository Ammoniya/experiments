#!/usr/bin/env python3
"""Stream clustering trace output and run the execution-trace heuristics."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping

from trace_heuristics import evaluate_trace

try:  # pragma: no cover - optional dependency
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run execution-trace heuristics against clustering_results_traces.json."
    )
    parser.add_argument(
        "--cache-root",
        default="cache",
        help="Directory containing cache/<cache-key>/clustering_results_traces.json (default: %(default)s)",
    )
    parser.add_argument(
        "--cluster-key",
        default="all-15",
        help="Cache key to inspect under --cache-root (default: %(default)s)",
    )
    parser.add_argument(
        "--input",
        help="Optional explicit path to a clustering_results_traces.json file.",
    )
    parser.add_argument(
        "--output",
        help="Optional path to write a JSON summary of heuristic hits per cluster.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Stop after processing this many traces (useful for smoke testing).",
    )
    parser.add_argument(
        "--min-hits",
        type=int,
        default=1,
        help="Only print clusters with at least this many heuristic-hit traces (default: %(default)s).",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=3,
        help="Store up to this many sample trace IDs per cluster in the summary (default: %(default)s).",
    )
    parser.add_argument(
        "--log-every",
        type=int,
        default=5000,
        help="Print a progress log every N traces (default: %(default)s). Set to 0 to disable.",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Show a tqdm progress bar (requires tqdm installed).",
    )
    return parser.parse_args()


def iter_traces_from_json(path: Path, progress_callback=None) -> Iterator[Mapping[str, Any]]:
    """Stream objects from a large JSON array without loading it into memory."""
    decoder = json.JSONDecoder()
    buffer = ""
    inside_array = False
    with path.open("r", encoding="utf-8") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                if buffer.strip():
                    # Attempt to parse any trailing object.
                    buffer = buffer.strip()
                    if buffer and buffer not in {"[", "]"}:
                        obj, _ = decoder.raw_decode(buffer)
                        yield obj
                break
            if progress_callback:
                progress_callback(len(chunk))
            buffer += chunk
            idx = 0
            while True:
                while idx < len(buffer) and buffer[idx].isspace():
                    idx += 1
                if not inside_array:
                    if idx < len(buffer) and buffer[idx] == "[":
                        inside_array = True
                        idx += 1
                        continue
                    # Need more data
                    break
                if idx >= len(buffer):
                    break
                char = buffer[idx]
                if char == ",":
                    idx += 1
                    continue
                if char == "]":
                    return
                try:
                    obj, offset = decoder.raw_decode(buffer, idx)
                except json.JSONDecodeError:
                    break
                yield obj
                idx = offset
            buffer = buffer[idx:]


def main() -> None:
    args = parse_args()
    if args.input:
        trace_path = Path(args.input)
    else:
        trace_path = Path(args.cache_root) / args.cluster_key / "clustering_results_traces.json"
    if not trace_path.exists():
        raise SystemExit(f"Trace file not found: {trace_path}")

    progress_bar = None
    if args.progress and tqdm is not None:
        progress_bar = tqdm(
            total=trace_path.stat().st_size,
            unit="B",
            unit_scale=True,
            desc=f"Reading {trace_path.name}",
        )
    elif args.progress and tqdm is None:
        print("tqdm is not installed; falling back to textual logs.")

    progress_callback = progress_bar.update if progress_bar else None

    summary: Dict[int, Dict[str, Any]] = defaultdict(
        lambda: {
            "total_traces": 0,
            "hit_traces": 0,
            "heuristics": Counter(),
            "sample_traces": [],
        }
    )
    processed = 0
    hit_traces = 0

    for trace in iter_traces_from_json(trace_path, progress_callback=progress_callback):
        processed += 1
        try:
            cluster_id = int(trace.get("cluster", -1))
        except (TypeError, ValueError):
            cluster_id = -1
        entry = summary[cluster_id]
        entry["total_traces"] += 1
        matches = evaluate_trace(trace)
        if matches:
            hit_traces += 1
            entry["hit_traces"] += 1
            entry["heuristics"].update(match.name for match in matches)
            if len(entry["sample_traces"]) < args.sample_size:
                entry["sample_traces"].append(
                    {
                        "trace_id": trace.get("trace_id"),
                        "script_url": trace.get("script_url"),
                        "heuristics": [match.name for match in matches],
                    }
                )
        if args.limit and processed >= args.limit:
            break
        if args.log_every and processed % args.log_every == 0:
            print(f"[progress] processed={processed}, hit_traces={hit_traces}", flush=True)

    if progress_bar:
        progress_bar.close()

    print(f"Processed {processed} trace(s); {hit_traces} triggered at least one heuristic.")
    rows = sorted(summary.items(), key=lambda item: item[1]["hit_traces"], reverse=True)
    for cluster_id, entry in rows:
        if entry["hit_traces"] < args.min_hits:
            continue
        total = entry["total_traces"]
        hits = entry["hit_traces"]
        hit_ratio = hits / total if total else 0.0
        print(
            f"\nCluster {cluster_id}: {hits}/{total} traces flagged ({hit_ratio:.1%})"
        )
        top_matches = entry["heuristics"].most_common(5)
        if top_matches:
            print("  Top heuristics:")
            for name, count in top_matches:
                print(f"    - {name}: {count}")
        for sample in entry["sample_traces"]:
            print(
                f"    · {sample['trace_id']} | heuristics={','.join(sample['heuristics'])} | url={sample.get('script_url','n/a')}"
            )

    if args.output:
        serializable_summary: Dict[str, Any] = {}
        for cluster_id, entry in summary.items():
            serializable_summary[str(cluster_id)] = {
                "total_traces": entry["total_traces"],
                "hit_traces": entry["hit_traces"],
                "heuristics": dict(entry["heuristics"]),
                "sample_traces": entry["sample_traces"],
            }
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(serializable_summary, handle, indent=2)
        print(f"\nSummary written to {output_path}")


if __name__ == "__main__":
    main()
