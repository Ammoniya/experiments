#!/usr/bin/env python3

"""Count experiment URLs that belong to specific hosted platforms."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse


TARGET_DOMAINS = ("wix.com", "weebly.com", "shopify.com", "blogspot.com")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Count fingerprinted URLs that belong to Wix, Weebly, Shopify, or Blogspot."
        )
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("experiment_data"),
        help="Root directory that contains <url-hash>/<timestamp>/fingerprint.json",
    )
    return parser.parse_args()


def normalize_host(url: str) -> Optional[str]:
    """Return the hostname for a URL, adding a scheme if necessary."""
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
    host = host.split("/")[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host or None


def match_target_domain(host: str) -> Optional[str]:
    """Return the target domain that the host belongs to, if any."""
    host = host.lower()
    for domain in TARGET_DOMAINS:
        if host == domain or host.endswith(f".{domain}"):
            return domain
    return None


def main() -> None:
    args = parse_args()
    data_dir = args.data_dir.expanduser()
    if not data_dir.exists():
        raise SystemExit(f"Data directory not found: {data_dir}")

    counts: Dict[str, int] = {domain: 0 for domain in TARGET_DOMAINS}
    processed = 0
    missing_url = 0
    parse_errors = 0

    for fingerprint_path in data_dir.rglob("fingerprint.json"):
        processed += 1
        try:
            with fingerprint_path.open("r", encoding="utf-8") as fp:
                fingerprint = json.load(fp)
        except (OSError, json.JSONDecodeError):
            parse_errors += 1
            continue

        url = fingerprint.get("url")
        if not url:
            missing_url += 1
            continue

        host = normalize_host(url)
        if not host:
            continue

        domain = match_target_domain(host)
        if domain:
            counts[domain] += 1

    total_matches = sum(counts.values())

    print(f"Fingerprint files checked: {processed}")
    print(f"Matching platform URLs: {total_matches}")
    for domain in TARGET_DOMAINS:
        print(f"  {domain}: {counts[domain]}")
    if missing_url:
        print(f"Missing 'url' field: {missing_url}")
    if parse_errors:
        print(f"Files failed to parse: {parse_errors}")


if __name__ == "__main__":
    main()
