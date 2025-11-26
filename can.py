#!/usr/bin/env python3
"""
Build cross-linked DTW/AST/Page/Plugin/CVE matrices for downstream analysis.

The script expects an existing clustering run (clustering_results.pkl) and
emits several aligned matrices plus index files under the requested output
directory. Heavy computations (AST cosine distances, CVE lookups) rely on
multi-processing so large datasets finish in a reasonable time.
"""

from __future__ import annotations

import argparse
import json
import logging
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import pickle
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import pairwise_distances

from cluster_scripts import ScriptClusterer
from scan_cluster import (
    convert_wordfence_constraints,
    expand_slug_variations,
    format_vuln_identifier,
    normalize_version,
    slugify_label,
    version_satisfies,
)


LOGGER = logging.getLogger("can")
ASSET_KEY = Tuple[str, str, str]
_DTW_SEQUENCES: Sequence[Sequence[str]] | None = None
_ASSET_VULN_LOOKUP: Mapping[Tuple[str, str], List[Dict[str, object]]] | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Assemble DTW/AST/Page/Plugin/CVE matrices for downstream analysis."
    )
    parser.add_argument(
        "--results",
        default="cache/all-11/clustering_results.pkl",
        help="Path to clustering_results.pkl (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default="for_can",
        help="Directory to write outputs (default: %(default)s)",
    )
    parser.add_argument(
        "--wordfence-db",
        default="wordfence_db.json",
        help="Wordfence vulnerability database JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=max(multiprocessing.cpu_count() - 1, 1),
        help="Worker processes for parallel tasks (default: CPU count - 1)",
    )
    parser.add_argument(
        "--dtw-chunk-size",
        type=int,
        default=256,
        help="Pair chunk size when DTW distances must be recomputed (default: %(default)s)",
    )
    parser.add_argument(
        "--asset-chunk-size",
        type=int,
        default=128,
        help="Asset chunk size for CVE matching (default: %(default)s)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (default: %(default)s)",
    )
    return parser.parse_args()


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s - %(processName)s - %(levelname)s - %(message)s",
    )


def load_results(path: Path) -> Mapping[str, object]:
    LOGGER.info("Loading clustering results from %s", path)
    with path.open("rb") as handle:
        return pickle.load(handle)


def sanitize_page_url(trace: Mapping[str, object]) -> str:
    raw = (trace.get("page_url") or "").strip()
    if raw:
        return raw
    trace_id = trace.get("trace_id") or "unknown-trace"
    return f"unknown://{trace_id}"


def filter_traces(traces: Sequence[Mapping[str, object]]) -> Tuple[List[Mapping[str, object]], List[int]]:
    filtered: List[Mapping[str, object]] = []
    indices: List[int] = []
    for idx, trace in enumerate(traces):
        preview = (trace.get("ast_preview") or "").strip()
        if not preview:
            continue
        filtered.append(trace)
        indices.append(idx)
    return filtered, indices


def _init_dtw_worker(sequences: Sequence[Sequence[str]]) -> None:
    global _DTW_SEQUENCES
    _DTW_SEQUENCES = sequences


def _dtw_worker(chunk: Sequence[Tuple[int, int]]) -> List[Tuple[int, int, float]]:
    results: List[Tuple[int, int, float]] = []
    if _DTW_SEQUENCES is None:
        raise RuntimeError("DTW worker not initialized")
    for i, j in chunk:
        dist = ScriptClusterer.categorical_dtw_distance(_DTW_SEQUENCES[i], _DTW_SEQUENCES[j])
        results.append((i, j, float(dist)))
    return results


def compute_dtw_matrix(
    sequences: Sequence[Sequence[str]],
    workers: int,
    chunk_size: int,
) -> np.ndarray:
    LOGGER.info("Computing DTW matrix from scratch for %d sequences", len(sequences))
    n = len(sequences)
    matrix = np.zeros((n, n), dtype=np.float32)
    if n <= 1:
        return matrix

    pairs: List[Tuple[int, int]] = []
    for i in range(n):
        for j in range(i + 1, n):
            pairs.append((i, j))

    LOGGER.info("Total DTW pairs to compute: %d", len(pairs))
    ctx = multiprocessing.get_context("spawn")
    try:
        with ctx.Pool(
            processes=workers,
            initializer=_init_dtw_worker,
            initargs=(sequences,),
        ) as pool:
            chunk: List[Tuple[int, int]] = []
            pending = []
            for pair in pairs:
                chunk.append(pair)
                if len(chunk) >= chunk_size:
                    pending.append(pool.apply_async(_dtw_worker, (chunk,)))
                    chunk = []
            if chunk:
                pending.append(pool.apply_async(_dtw_worker, (chunk,)))

            completed = 0
            for job in pending:
                for i, j, dist in job.get():
                    matrix[i, j] = dist
                    matrix[j, i] = dist
                completed += 1
                if completed % 100 == 0 or completed == len(pending):
                    LOGGER.info("DTW chunks finished: %d/%d", completed, len(pending))
    except PermissionError:
        LOGGER.warning("Process pool unavailable; falling back to single-process DTW computation.")
        for i, j in pairs:
            dist = ScriptClusterer.categorical_dtw_distance(sequences[i], sequences[j])
            matrix[i, j] = dist
            matrix[j, i] = dist

    return matrix


def prepare_dtw_similarity(
    results: Mapping[str, object],
    filtered_indices: Sequence[int],
    workers: int,
    chunk_size: int,
) -> np.ndarray:
    raw_matrix = np.asarray(results.get("distance_matrix"))
    if raw_matrix.size:
        LOGGER.info("Re-using cached DTW distance matrix.")
        subset = raw_matrix[np.ix_(filtered_indices, filtered_indices)]
    else:
        sequences_full = results.get("sequences") or []
        if not sequences_full:
            sequences_full = [
                trace.get("event_sequence") or [] for trace in results.get("traces")  # type: ignore[assignment]
            ]
        sequences = [sequences_full[idx] for idx in filtered_indices]
        subset = compute_dtw_matrix(sequences, workers, chunk_size)

    finite = np.isfinite(subset)
    if not finite.all():
        LOGGER.warning("Replacing %d non-finite DTW entries with 0.", np.size(subset) - int(finite.sum()))
        subset = subset.copy()
        subset[~finite] = 0.0
    similarity = 1.0 / (1.0 + subset.astype(np.float32, copy=False))
    np.fill_diagonal(similarity, 1.0)
    LOGGER.info("DTW similarity matrix shape: %s", similarity.shape)
    return similarity


def compute_ast_distance_matrix(
    traces: Sequence[Mapping[str, object]],
    workers: int,
) -> np.ndarray:
    LOGGER.info("Vectorizing %d AST unit vectors", len(traces))
    vectorizer = DictVectorizer(sparse=True)
    samples = []
    for trace in traces:
        vec = trace.get("ast_unit_vector") or {}
        samples.append({str(key): float(value) for key, value in (vec or {}).items()})
    ast_matrix = vectorizer.fit_transform(samples)
    LOGGER.info(
        "AST matrix built with %d features; computing cosine distances using %d worker(s)",
        ast_matrix.shape[1],
        workers,
    )
    distances = pairwise_distances(ast_matrix, metric="cosine", n_jobs=workers)
    distances = distances.astype(np.float32, copy=False)
    np.fill_diagonal(distances, 0.0)
    LOGGER.info("AST distance matrix shape: %s", distances.shape)
    return distances


def build_page_data(
    traces: Sequence[Mapping[str, object]],
) -> Tuple[List[str], List[int], np.ndarray, np.ndarray]:
    page_urls: List[str] = []
    page_lookup: Dict[str, int] = {}
    script_to_page: List[int] = []
    for trace in traces:
        url = sanitize_page_url(trace)
        idx = page_lookup.get(url)
        if idx is None:
            idx = len(page_urls)
            page_lookup[url] = idx
            page_urls.append(url)
        script_to_page.append(idx)

    page_script = np.zeros((len(page_urls), len(traces)), dtype=np.uint8)
    for col, page_idx in enumerate(script_to_page):
        page_script[page_idx, col] = 1

    vt_counts = np.full((len(page_urls), 1), -1, dtype=np.int32)
    for trace, page_idx in zip(traces, script_to_page):
        vt = trace.get("virustotal_verdict_count")
        if vt is None:
            vt = (trace.get("virustotal") or {}).get("verdict_count")
        try:
            vt_val = int(vt) if vt is not None else None
        except (TypeError, ValueError):
            vt_val = None
        if vt_val is not None:
            vt_counts[page_idx, 0] = max(vt_counts[page_idx, 0], vt_val)

    return page_urls, script_to_page, page_script, vt_counts


def normalize_asset_entry(item: Mapping[str, object], kind: str) -> Tuple[ASSET_KEY, Dict[str, object]] | None:
    name = (item.get("name") or "").strip()
    if not name:
        return None
    slug = slugify_label(name)
    if not slug:
        return None
    raw_version = item.get("version")
    version_text = str(raw_version).strip() if raw_version not in (None, "") else None
    normalized = normalize_version(version_text)
    version_key = normalized or version_text or "unspecified"
    key: ASSET_KEY = (kind, slug, version_key)
    payload = {
        "type": kind,
        "name": name,
        "slug": slug,
        "version": version_text,
        "normalized_version": normalized,
    }
    return key, payload


def collect_assets(
    traces: Sequence[Mapping[str, object]],
) -> Tuple[List[Dict[str, object]], List[set[ASSET_KEY]], Dict[ASSET_KEY, int]]:
    assets: Dict[ASSET_KEY, Dict[str, object]] = {}
    script_assets: List[set[ASSET_KEY]] = []
    for trace in traces:
        per_trace: set[ASSET_KEY] = set()
        for kind, key_name in (("plugin", "wordpress_plugins"), ("theme", "wordpress_themes")):
            for item in trace.get(key_name) or []:
                normalized = normalize_asset_entry(item, kind)
                if not normalized:
                    continue
                asset_key, payload = normalized
                assets.setdefault(asset_key, payload)
                per_trace.add(asset_key)
        script_assets.append(per_trace)

    asset_items: List[Tuple[ASSET_KEY, Dict[str, object]]] = sorted(
        assets.items(),
        key=lambda entry: (0 if entry[0][0] == "plugin" else 1, entry[0][1], entry[0][2]),
    )
    index_lookup: Dict[ASSET_KEY, int] = {}
    asset_list: List[Dict[str, object]] = []
    for idx, (key, payload) in enumerate(asset_items):
        index_lookup[key] = idx
        asset_list.append(
            {
                "index": idx,
                "type": payload["type"],
                "name": payload["name"],
                "slug": payload["slug"],
                "version": payload.get("version"),
                "normalized_version": payload.get("normalized_version"),
            }
        )

    LOGGER.info("Identified %d unique WordPress assets (plugins + themes)", len(asset_list))
    return asset_list, script_assets, index_lookup


def build_page_asset_matrix(
    page_count: int,
    asset_count: int,
    script_assets: Sequence[set[ASSET_KEY]],
    script_to_page: Sequence[int],
    asset_index: Mapping[ASSET_KEY, int],
) -> np.ndarray:
    matrix = np.zeros((page_count, asset_count), dtype=np.uint8)
    for script_idx, asset_keys in enumerate(script_assets):
        page_idx = script_to_page[script_idx]
        for asset_key in asset_keys:
            col = asset_index[asset_key]
            matrix[page_idx, col] = 1
    LOGGER.info("Page x asset matrix shape: %s", matrix.shape)
    return matrix


def _ingest_wordfence_payload(
    store: Dict[Tuple[str, str], List[Dict[str, object]]],
    entry: Mapping[str, object],
    needed_slugs: Mapping[str, set[str]],
) -> None:
    software_items = entry.get("software") or []
    if not isinstance(software_items, Sequence):
        return

    for software in software_items:
        if not isinstance(software, Mapping):
            continue
        sw_type = (software.get("type") or "plugin").strip().lower()
        if sw_type not in needed_slugs:
            continue
        slug_candidates = {
            slugify_label(str(value))
            for value in (software.get("slug"), software.get("name"))
            if value
        }
        slug_candidates.discard("")
        if not slug_candidates:
            continue
        groups = convert_wordfence_constraints(software.get("affected_versions") or {})
        payload = {
            "cve": entry.get("cve"),
            "wordfence_uuid": entry.get("id"),
            "title": entry.get("title") or "Wordfence advisory",
            "constraint_groups": groups,
            "references": entry.get("references") or [],
        }
        for slug in slug_candidates:
            for alias in expand_slug_variations(slug) or {slug}:
                if alias not in needed_slugs[sw_type]:
                    continue
                store.setdefault((sw_type, alias), []).append(payload)


def load_wordfence_lookup(
    path: Path,
    needed_slugs: Mapping[str, set[str]],
) -> Dict[Tuple[str, str], List[Dict[str, object]]]:
    if not path.exists():
        LOGGER.warning("Wordfence DB %s missing; CVE matrix will remain empty.", path)
        return {}
    LOGGER.info("Loading Wordfence vulnerability data from %s", path)
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    lookup: Dict[Tuple[str, str], List[Dict[str, object]]] = {}
    if isinstance(data, Mapping):
        iterable = data.values()
    else:
        iterable = data
    for entry in iterable:
        if isinstance(entry, Mapping):
            _ingest_wordfence_payload(lookup, entry, needed_slugs)
    LOGGER.info("Loaded Wordfence entries for %d asset slugs", len(lookup))
    return lookup


def chunk_iterable(items: Sequence[Dict[str, object]], size: int) -> Iterable[List[Dict[str, object]]]:
    chunk: List[Dict[str, object]] = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def _init_asset_worker(vuln_lookup: Mapping[Tuple[str, str], List[Dict[str, object]]]) -> None:
    global _ASSET_VULN_LOOKUP
    _ASSET_VULN_LOOKUP = vuln_lookup


def _asset_chunk_worker(chunk: Sequence[Dict[str, object]]) -> List[Tuple[int, List[Dict[str, object]]]]:
    results: List[Tuple[int, List[Dict[str, object]]]] = []
    if _ASSET_VULN_LOOKUP is None:
        raise RuntimeError("Asset CVE worker not initialized")
    for asset in chunk:
        slug = asset["slug"]
        asset_type = asset["type"]
        version = asset.get("normalized_version")
        if not version:
            results.append((asset["index"], []))
            continue
        entries = _ASSET_VULN_LOOKUP.get((asset_type, slug), [])
        matched: List[Dict[str, object]] = []
        for entry in entries:
            if version_satisfies(version, entry.get("constraint_groups") or []):
                identifier = format_vuln_identifier(entry)
                matched.append(
                    {
                        "id": identifier,
                        "title": entry.get("title"),
                        "reference": (entry.get("references") or [None])[0],
                    }
                )
        results.append((asset["index"], matched))
    return results


def build_asset_cve_mapping(
    assets: Sequence[Dict[str, object]],
    vuln_lookup: Mapping[Tuple[str, str], List[Dict[str, object]]],
    workers: int,
    chunk_size: int,
) -> Tuple[np.ndarray, List[Dict[str, object]]]:
    if not assets:
        return np.zeros((0, 0), dtype=np.uint8), []

    if not vuln_lookup:
        LOGGER.warning("No Wordfence data available; CVE matrix will be empty.")
        return np.zeros((len(assets), 0), dtype=np.uint8), []

    LOGGER.info("Matching %d assets against Wordfence CVEs using %d worker(s)", len(assets), workers)
    matches: Dict[int, List[Dict[str, object]]] = {asset["index"]: [] for asset in assets}
    if workers <= 1:
        global _ASSET_VULN_LOOKUP
        _ASSET_VULN_LOOKUP = vuln_lookup
        for chunk in chunk_iterable(list(assets), chunk_size):
            for asset_idx, matched in _asset_chunk_worker(chunk):
                matches[asset_idx] = matched
    else:
        try:
            with ProcessPoolExecutor(
                max_workers=workers,
                initializer=_init_asset_worker,
                initargs=(vuln_lookup,),
            ) as executor:
                futures = [
                    executor.submit(_asset_chunk_worker, chunk)
                    for chunk in chunk_iterable(list(assets), chunk_size)
                ]
                for future in as_completed(futures):
                    for asset_idx, matched in future.result():
                        matches[asset_idx] = matched
        except PermissionError:
            LOGGER.warning("Process pool unavailable; falling back to single-process CVE matching.")
            _ASSET_VULN_LOOKUP = vuln_lookup
            for chunk in chunk_iterable(list(assets), chunk_size):
                for asset_idx, matched in _asset_chunk_worker(chunk):
                    matches[asset_idx] = matched

    cve_index: Dict[str, int] = {}
    cve_records: List[Dict[str, object]] = []
    for matched in matches.values():
        for entry in matched:
            identifier = entry["id"]
            if identifier not in cve_index:
                cve_index[identifier] = len(cve_records)
                cve_records.append(
                    {
                        "index": cve_index[identifier],
                        "id": identifier,
                        "title": entry.get("title"),
                        "reference": entry.get("reference"),
                    }
                )

    matrix = np.zeros((len(assets), len(cve_records)), dtype=np.uint8)
    for asset_idx, matched in matches.items():
        for entry in matched:
            cve_idx = cve_index[entry["id"]]
            matrix[asset_idx, cve_idx] = 1

    LOGGER.info("Asset x CVE matrix shape: %s", matrix.shape)
    return matrix, cve_records


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    LOGGER.info("Wrote %s", path)


def save_matrix(path: Path, array: np.ndarray) -> None:
    np.save(path, array, allow_pickle=False)
    LOGGER.info("Wrote %s with shape %s", path, array.shape)


def main() -> None:
    args = parse_args()
    setup_logging(args.log_level)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        results = load_results(Path(args.results))
        all_traces: Sequence[Mapping[str, object]] = results.get("traces")  # type: ignore[assignment]
        filtered_traces, filtered_indices = filter_traces(all_traces)
        if not filtered_traces:
            raise SystemExit("No traces with AST previews located.")
        LOGGER.info("Using %d/%d traces with AST previews", len(filtered_traces), len(all_traces))

        dtw_similarity = prepare_dtw_similarity(results, filtered_indices, args.max_workers, args.dtw_chunk_size)
        ast_distance = compute_ast_distance_matrix(filtered_traces, args.max_workers)
        page_urls, script_to_page, page_script_matrix, vt_counts = build_page_data(filtered_traces)

        asset_list, script_assets, asset_index = collect_assets(filtered_traces)
        page_asset_matrix = build_page_asset_matrix(
            len(page_urls),
            len(asset_list),
            script_assets,
            script_to_page,
            asset_index,
        )

        needed_slugs: Dict[str, set[str]] = {"plugin": set(), "theme": set()}
        for asset in asset_list:
            needed_slugs.setdefault(asset["type"], set()).add(asset["slug"])
        vuln_lookup = load_wordfence_lookup(Path(args.wordfence_db), needed_slugs)
        asset_cve_matrix, cve_records = build_asset_cve_mapping(
            asset_list,
            vuln_lookup,
            args.max_workers,
            args.asset_chunk_size,
        )

        scripts_index = [
            {
                "index": idx,
                "trace_id": trace.get("trace_id"),
                "page_url": sanitize_page_url(trace),
                "script_url": trace.get("script_url"),
                "script_sha256": trace.get("hash") or trace.get("script_sha256"),
                "cluster": trace.get("cluster"),
            }
            for idx, trace in enumerate(filtered_traces)
        ]

        manifest = {
            "script_count": len(filtered_traces),
            "page_count": len(page_urls),
            "asset_count": len(asset_list),
            "cve_count": len(cve_records),
            "matrices": {
                "dtw_similarity": "dtw_similarity.npy",
                "ast_distance": "ast_distance.npy",
                "page_script": "page_script_matrix.npy",
                "page_asset": "page_asset_matrix.npy",
                "asset_cve": "asset_cve_matrix.npy",
                "page_vt_verdict_counts": "page_vt_verdict_counts.npy",
            },
            "vectors": {
                "page_urls": "page_urls.json",
                "assets": "assets.json",
                "cves": "cves.json",
                "scripts": "scripts.json",
            },
        }

        save_matrix(output_dir / "dtw_similarity.npy", dtw_similarity)
        save_matrix(output_dir / "ast_distance.npy", ast_distance)
        save_matrix(output_dir / "page_script_matrix.npy", page_script_matrix)
        save_matrix(output_dir / "page_asset_matrix.npy", page_asset_matrix)
        save_matrix(output_dir / "asset_cve_matrix.npy", asset_cve_matrix)
        save_matrix(output_dir / "page_vt_verdict_counts.npy", vt_counts)

        write_json(output_dir / "page_urls.json", [{"index": idx, "url": url} for idx, url in enumerate(page_urls)])
        write_json(output_dir / "assets.json", asset_list)
        write_json(output_dir / "cves.json", cve_records)
        write_json(output_dir / "scripts.json", scripts_index)
        write_json(output_dir / "manifest.json", manifest)
        LOGGER.info("All artifacts written to %s", output_dir)
    except Exception:  # noqa: BLE001
        LOGGER.exception("Failed to build matrices")
        raise


if __name__ == "__main__":
    main()

'''
python can.py --results cache/all-11/clustering_results.pkl --output-dir for_can --wordfence-db wordfence_db.json --max-workers 4
''''
