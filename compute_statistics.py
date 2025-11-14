import os
import json
import shutil
from pathlib import Path
from typing import Dict, Optional
from tqdm import tqdm


def is_file_non_empty(filepath: Path) -> bool:
    try:
        return filepath.stat().st_size > 0
    except (FileNotFoundError, OSError):
        return False


def csv_has_data_rows(csv_path: Path) -> bool:
    try:
        if not is_file_non_empty(csv_path):
            return False

        with open(csv_path, 'r') as f:
            lines = f.readlines()
            return len(lines) > 1
    except (IOError, OSError):
        return False


def check_is_wordpress_fast(fingerprint_path: Path) -> bool:
    try:
        if not is_file_non_empty(fingerprint_path):
            return False

        with open(fingerprint_path, 'r') as f:
            data = json.load(f)
            return data.get('is_wordpress', False) is True
    except (json.JSONDecodeError, IOError, OSError):
        return False


def compute_statistics(event_data_dir: str, copy_to_digest: bool = False) -> Dict[str, int]:
    event_data_path = Path(event_data_dir)

    if not event_data_path.exists():
        raise ValueError(f"Directory does not exist: {event_data_dir}")

    digest_path = None
    if copy_to_digest:
        digest_path = Path('./experiment_data')
        digest_path.mkdir(exist_ok=True)
        print(f"Experiment directory: {digest_path.absolute()}")

    stats = {
        'total_dirs': 0,
        'has_trace_v2': 0,
        'has_fingerprint': 0,
        'has_both_trace_fingerprint': 0,
        'has_both_and_is_wordpress': 0,
        'has_loaded_js_index': 0,
        'has_both_and_loaded_js_index': 0,
        'has_both_wordpress_and_loaded_js_index': 0,
        'copied_to_digest': 0,
        'skipped_already_exists': 0
    }

    print("Scanning directory structure...")
    timestamp_dirs = []

    url_hash_dirs = [d for d in event_data_path.iterdir() if d.is_dir()]

    for url_hash_dir in tqdm(url_hash_dirs, desc="Scanning url_hash dirs", unit="dir"):
        for timestamp_dir in url_hash_dir.iterdir():
            if timestamp_dir.is_dir():
                timestamp_dirs.append(timestamp_dir)

    total_dirs = len(timestamp_dirs)
    print(f"Found {total_dirs} timestamp directories. Processing...")

    for item in tqdm(timestamp_dirs, desc="Processing directories", unit="dir"):
        stats['total_dirs'] += 1

        trace_v2_path = item / 'trace_v2.json'
        fingerprint_path = item / 'fingerprint.json'
        loaded_js_index_path = item / 'loaded_js' / 'index.csv'

        has_trace = is_file_non_empty(trace_v2_path)
        has_fingerprint = is_file_non_empty(fingerprint_path)
        has_loaded_js = csv_has_data_rows(loaded_js_index_path)

        if has_trace:
            stats['has_trace_v2'] += 1

        if has_fingerprint:
            stats['has_fingerprint'] += 1

        has_both = has_trace and has_fingerprint
        if has_both:
            stats['has_both_trace_fingerprint'] += 1

            is_wordpress = check_is_wordpress_fast(fingerprint_path)
            if is_wordpress:
                stats['has_both_and_is_wordpress'] += 1

        if has_loaded_js:
            stats['has_loaded_js_index'] += 1

        if has_both and has_loaded_js:
            stats['has_both_and_loaded_js_index'] += 1

            if check_is_wordpress_fast(fingerprint_path):
                stats['has_both_wordpress_and_loaded_js_index'] += 1

                if copy_to_digest and digest_path:
                    try:
                        url_hash = item.parent.name
                        timestamp = item.name

                        target_url_hash_dir = digest_path / url_hash
                        target_timestamp_dir = target_url_hash_dir / timestamp

                        if target_timestamp_dir.exists():
                            stats['skipped_already_exists'] += 1
                        else:
                            shutil.copytree(item, target_timestamp_dir)
                            stats['copied_to_digest'] += 1

                    except (OSError, IOError) as e:
                        print(f"\nWarning: Failed to copy {item}: {e}")

    return stats


def print_statistics(stats: Dict[str, int], copy_enabled: bool = False) -> None:
    print("=" * 80)
    print("EVENT_DATA DIRECTORY STATISTICS")
    print("=" * 80)
    print()
    print(f"1. Total number of directories: {stats['total_dirs']}")
    print(f"2. Directories with non-empty trace_v2.json: {stats['has_trace_v2']}")
    print(f"3. Directories with non-empty fingerprint.json: {stats['has_fingerprint']}")
    print(f"4. Directories with both non-empty trace_v2.json and fingerprint.json: {stats['has_both_trace_fingerprint']}")
    print(f"5. Directories with both (trace_v2.json + fingerprint.json) where is_wordpress=True: {stats['has_both_and_is_wordpress']}")
    print(f"6. Directories with non-empty loaded_js/index.csv: {stats['has_loaded_js_index']}")
    print(f"7. Directories with both (trace_v2.json + fingerprint.json) and loaded_js/index.csv: {stats['has_both_and_loaded_js_index']}")
    print(f"8. Directories with both (trace_v2.json + fingerprint.json), is_wordpress=True, and loaded_js/index.csv: {stats['has_both_wordpress_and_loaded_js_index']}")

    if copy_enabled:
        print()
        print(f"Copied to experiment_data: {stats['copied_to_digest']}")
        print(f"Skipped (already exists): {stats['skipped_already_exists']}")

    print()
    print("=" * 80)


def main():
    event_data_dir = './event_data'
    copy_to_experiment = True

    try:
        print(f"Analyzing directory: {event_data_dir}")
        if copy_to_experiment:
            print(f"Copy mode enabled: Qualifying directories will be copied to ./experiment_data")
        print()

        stats = compute_statistics(
            event_data_dir,
            copy_to_digest=copy_to_experiment
        )
        print_statistics(stats, copy_enabled=copy_to_experiment)

        return stats

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == '__main__':
    main()
