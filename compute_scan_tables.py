#!/usr/bin/env python3
"""
Generate scan/VT coverage tables from both event_data and experiment_data.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

BASE_EVENT = Path("event_data")
BASE_VT = Path("virustotal_reports")
BASE_EXPERIMENT = Path("experiment_data")


def extract_date(name: str) -> str:
    if "-" not in name:
        return ""
    date = name.split("-")[0]
    return date if date.isdigit() else ""


def count_event_traces(base: Path) -> Counter:
    counts: Counter[str] = Counter()
    for queue_entry in os.scandir(base):
        if not queue_entry.is_dir():
            continue
        for ts_entry in os.scandir(queue_entry.path):
            if not ts_entry.is_dir():
                continue
            date = extract_date(ts_entry.name)
            if not date:
                continue
            if (Path(ts_entry.path) / "trace_v2.json").exists():
                counts[date] += 1
    return counts


def count_event_vt_reports(base: Path) -> Counter:
    counts: Counter[str] = Counter()
    for queue_entry in os.scandir(base):
        if not queue_entry.is_dir():
            continue
        for ts_entry in os.scandir(queue_entry.path):
            if not ts_entry.is_dir():
                continue
            date = extract_date(ts_entry.name)
            if not date:
                continue
            if (Path(ts_entry.path) / "virustotal_report.json").exists():
                counts[date] += 1
    return counts


def count_vt_directory_reports(base: Path) -> Counter:
    counts: Counter[str] = Counter()
    for date_entry in os.scandir(base):
        if not date_entry.is_dir():
            continue
        total = sum(
            1
            for file_entry in os.scandir(date_entry.path)
            if (
                file_entry.is_file()
                and file_entry.name.startswith("vt_report")
                and file_entry.name.endswith(".json")
            )
        )
        counts[date_entry.name] = total
    return counts


def count_experiment_data(base: Path) -> tuple[Counter, Counter]:
    trace_counts: Counter[str] = Counter()
    vt_counts: Counter[str] = Counter()
    for hash_entry in os.scandir(base):
        if not hash_entry.is_dir():
            continue
        for ts_entry in os.scandir(hash_entry.path):
            if not ts_entry.is_dir():
                continue
            date = extract_date(ts_entry.name)
            if not date:
                continue
            trace_file = Path(ts_entry.path) / "trace_v2.json"
            vt_file = Path(ts_entry.path) / "virustotal_report.json"
            if trace_file.exists():
                trace_counts[date] += 1
            if vt_file.exists():
                vt_counts[date] += 1
    return trace_counts, vt_counts


def print_table(title: str, vt_counts: Counter, trace_counts: Counter) -> None:
    all_dates = sorted(set(trace_counts) | set(vt_counts))
    total_vt = sum(vt_counts.values())
    total_traces = sum(trace_counts.values())
    print(title)
    print("date      vt_reports  scanned_urls")
    for date in all_dates:
        print(f"{date:>8} {vt_counts.get(date,0):>11} {trace_counts.get(date,0):>13}")
    print(f"\nTOTAL{total_vt:>10}{total_traces:>13}\n")


def main() -> None:
    event_traces = count_event_traces(BASE_EVENT)
    vt_dir_counts = count_vt_directory_reports(BASE_VT)
    print_table("=== Event data vs VirusTotal directories ===", vt_dir_counts, event_traces)

    exp_traces, exp_vt = count_experiment_data(BASE_EXPERIMENT)
    print_table("=== Experiment data trace vs local VT reports ===", exp_vt, exp_traces)


if __name__ == "__main__":
    main()
