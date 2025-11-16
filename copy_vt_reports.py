import json
import os
import shutil
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

BASE_DIR = Path("/home/ravindu/compweb/notebooks/2025-11-11")
EXPERIMENT_DATA_DIR = BASE_DIR / "experiment_data"
VT_REPORTS_DIR = BASE_DIR / "virustotal_reports"

def normalize_url(url):
    url = url.replace("http://", "").replace("https://", "")
    url = url.rstrip("/")
    url_no_www = url.replace("www.", "")
    return url, url_no_www

def find_vt_report_by_url(url, timestamp_str):
    date_part = timestamp_str.split("-")[0]
    url_normalized, url_no_www = normalize_url(url)
    vt_date_dir = VT_REPORTS_DIR / date_part

    if not vt_date_dir.exists():
        print(f"  Warning: VT reports directory not found for date {date_part}")
        return None

    for vt_file in vt_date_dir.glob("vt_report-*.json"):
        try:
            with open(vt_file, 'r') as f:
                vt_data = json.load(f)
                vt_url = vt_data.get("url", "")
                vt_url_normalized, vt_url_no_www = normalize_url(vt_url)

                if (url_normalized == vt_url_normalized or
                    url_no_www == vt_url_no_www or
                    url_normalized == vt_url_no_www or
                    url_no_www == vt_url_normalized):
                    return vt_file
        except Exception as e:
            print(f"  Error reading {vt_file}: {e}")
            continue

    return None

def process_experiment_data():
    stats = {
        "total_experiments": 0,
        "already_exists": 0,
        "matched": 0,
        "not_found": 0,
        "errors": 0
    }

    for hash_dir in sorted(EXPERIMENT_DATA_DIR.iterdir()):
        if not hash_dir.is_dir():
            continue

        for timestamp_dir in sorted(hash_dir.iterdir()):
            if not timestamp_dir.is_dir():
                continue

            stats["total_experiments"] += 1
            fingerprint_file = timestamp_dir / "fingerprint.json"

            if not fingerprint_file.exists():
                print(f"Warning: No fingerprint.json in {timestamp_dir}")
                stats["errors"] += 1
                continue

            try:
                dest_path = timestamp_dir / "virustotal_report.json"
                if dest_path.exists():
                    stats["already_exists"] += 1
                    continue

                with open(fingerprint_file, 'r') as f:
                    fingerprint_data = json.load(f)

                url = fingerprint_data.get("url")
                if not url:
                    print(f"Warning: No URL in {fingerprint_file}")
                    stats["errors"] += 1
                    continue

                timestamp_str = timestamp_dir.name

                print(f"\nProcessing: {hash_dir.name}/{timestamp_str}")
                print(f"  URL: {url}")

                vt_report_path = find_vt_report_by_url(url, timestamp_str)

                if vt_report_path:
                    shutil.copy2(vt_report_path, dest_path)
                    print(f"  [OK] Copied VT report from: {vt_report_path.name}")
                    print(f"  [OK] To: {dest_path}")
                    stats["matched"] += 1
                else:
                    print(f"  ✗ No matching VT report found")
                    stats["not_found"] += 1

            except Exception as e:
                print(f"Error processing {timestamp_dir}: {e}")
                stats["errors"] += 1
                continue

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total experiments processed: {stats['total_experiments']}")
    print(f"VT reports already existed (skipped): {stats['already_exists']}")
    print(f"VT reports newly matched and copied: {stats['matched']}")
    print(f"VT reports not found: {stats['not_found']}")
    print(f"Errors encountered: {stats['errors']}")
    print("="*70)

if __name__ == "__main__":
    print("Starting VT report copy process...")
    print(f"Experiment data directory: {EXPERIMENT_DATA_DIR}")
    print(f"VT reports directory: {VT_REPORTS_DIR}")
    print()

    process_experiment_data()

    print("\nDone!")
