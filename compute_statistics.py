import os
import json
import shutil
import time
from contextlib import closing
from pathlib import Path
from typing import Dict, Iterator, Optional
from urllib.parse import urlparse
from tqdm import tqdm


BLACKLISTED_DOMAINS = ("wix.com", "weebly.com", "shopify.com", "blogspot.com")


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


def load_fingerprint_data(fingerprint_path: Path) -> Optional[Dict]:
    """Return parsed fingerprint data or None on failure."""
    try:
        if not is_file_non_empty(fingerprint_path):
            return None

        with open(fingerprint_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError, OSError):
        return None


def normalize_host(url: str) -> Optional[str]:
    """Return a normalized hostname for comparisons."""
    if not url:
        return None

    candidate = url
    if "://" not in candidate:
        candidate = f"http://{candidate}"

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None

    host = parsed.netloc or parsed.path
    host = host.split('/')[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host or None


def is_blacklisted_domain(host: Optional[str]) -> bool:
    if not host:
        return False

    host = host.lower()
    return any(host == domain or host.endswith(f".{domain}") for domain in BLACKLISTED_DOMAINS)


def is_url_blacklisted(fingerprint_data: Optional[Dict]) -> bool:
    if not fingerprint_data:
        return False

    url = fingerprint_data.get('url')
    normalized_host = normalize_host(url) if url else None
    return is_blacklisted_domain(normalized_host)

# Codex Addon
def stream_timestamp_directories(event_data_path: Path, log_interval: int = 5000) -> Iterator[Path]:
    """Yield timestamp directories without pre-loading everything into memory."""
    scanned_url_dirs = 0
    yield_count = 0
    next_log_threshold = log_interval
    last_log_time = time.perf_counter()

    tqdm.write("Streaming timestamp directories (may take a while on slow storage)...")

    with closing(os.scandir(event_data_path)) as url_entries:
        for url_entry in url_entries:
            if not url_entry.is_dir(follow_symlinks=False):
                continue

            scanned_url_dirs += 1

            try:
                with closing(os.scandir(url_entry.path)) as timestamp_entries:
                    for timestamp_entry in timestamp_entries:
                        if not timestamp_entry.is_dir(follow_symlinks=False):
                            continue

                        yield_count += 1
                        if yield_count >= next_log_threshold:
                            now = time.perf_counter()
                            elapsed = now - last_log_time
                            dirs_per_sec = (log_interval / elapsed) if elapsed else 0
                            tqdm.write(
                                f"  • Scanned {yield_count:,} timestamp dirs across {scanned_url_dirs:,} url hashes "
                                f"(~{dirs_per_sec:,.0f}/s)"
                            )
                            last_log_time = now
                            next_log_threshold += log_interval

                        yield Path(timestamp_entry.path)
            except (OSError, FileNotFoundError) as err:
                tqdm.write(f"Warning: Unable to access {url_entry.path}: {err}")

    tqdm.write(
        f"Finished scanning {scanned_url_dirs:,} url hash dirs; discovered {yield_count:,} timestamp dirs."
    )


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
        'skipped_already_exists': 0,
        'skipped_blacklisted_domain': 0,
    }

    print("Scanning directory structure...")
    timestamp_dirs_iter = stream_timestamp_directories(event_data_path)

    for item in tqdm(timestamp_dirs_iter, desc="Processing directories", unit="dir"):
        stats['total_dirs'] += 1

        trace_v2_path = item / 'trace_v2.json'
        fingerprint_path = item / 'fingerprint.json'
        loaded_js_index_path = item / 'loaded_js' / 'index.csv'

        has_trace = is_file_non_empty(trace_v2_path)
        has_fingerprint = is_file_non_empty(fingerprint_path)
        has_loaded_js = csv_has_data_rows(loaded_js_index_path)

        fingerprint_data: Optional[Dict] = None
        if has_fingerprint:
            fingerprint_data = load_fingerprint_data(fingerprint_path)

        is_wordpress = bool(fingerprint_data and fingerprint_data.get('is_wordpress', False))

        if has_trace:
            stats['has_trace_v2'] += 1

        if has_fingerprint:
            stats['has_fingerprint'] += 1

        has_both = has_trace and has_fingerprint
        if has_both:
            stats['has_both_trace_fingerprint'] += 1

            if is_wordpress:
                stats['has_both_and_is_wordpress'] += 1

        if has_loaded_js:
            stats['has_loaded_js_index'] += 1

        if has_both and has_loaded_js:
            stats['has_both_and_loaded_js_index'] += 1

            if is_wordpress:
                stats['has_both_wordpress_and_loaded_js_index'] += 1

                if copy_to_digest and digest_path:
                    if is_url_blacklisted(fingerprint_data):
                        stats['skipped_blacklisted_domain'] += 1
                        continue

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
        print(f"Skipped (blacklisted domain): {stats['skipped_blacklisted_domain']}")

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
