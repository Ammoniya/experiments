import os
import json
from pathlib import Path


def analyze_trace_files(root_dir='experiment_data'):

    trace_files = list(Path(root_dir).rglob('trace_v2.json'))

    if not trace_files:
        print("No trace_v2.json files found.")
        return

    print(f"Found {len(trace_files)} trace_v2.json file(s)\n")
    print(f"{'File Path':<120} {'Size (MB)':>12} {'Lines':>15}")
    print("-" * 150)

    total_size = 0

    for file_path in sorted(trace_files):
        size_bytes = file_path.stat().st_size
        size_mb = size_bytes / (1024 * 1024)

        with open(file_path, 'r', encoding='utf-8') as f:
            line_count = sum(1 for _ in f)

        display_path = f"./{file_path}"

        print(f"{str(display_path):<120} {size_mb:>12.2f} {line_count:>15,}")

        total_size += size_mb

    total_size_gb = total_size / 1024
    print("-" * 150)
    print(f"\nTOTAL SIZE: {total_size_gb:.2f} GB")


if __name__ == "__main__":
    analyze_trace_files()
