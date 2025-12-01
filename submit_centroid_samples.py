#!/usr/bin/env python3
"""
Identify JavaScript traces closest to each cluster centroid and optionally
submit them to VirusTotal while respecting the free-tier rate limits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from tqdm import tqdm

try:
    import requests
except ImportError:  # pragma: no cover - graceful fallback when requests is missing
    requests = None  # type: ignore


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_RATE_LIMIT = 4          # requests per minute (VirusTotal free tier)
DEFAULT_DAILY_CAP = 500         # maximum requests per day
VT_GUI_BASE = "https://www.virustotal.com/gui/file"
HARDCODED_VT_API_KEY = "d41c5c9cbbe2fdcad140c9fae60c2bf7cdf99304db49daee8f69ff1379250d27"
# HARDCODED_VT_API_KEY = "d63a5a61329f7274c975839c99db74bff6052a045dcbbbf0d97731c5f16ade34"
DEFAULT_EXPERIMENT_ROOT = BASE_DIR / "experiment_data"
ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[92m"
ANSI_RED = "\033[91m"
ENABLE_COLOR = sys.stdout.isatty()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def as_float(value: Any, default: float = float("-inf")) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def ensure_requests_available() -> None:
    if requests is None:
        raise RuntimeError(
            "The 'requests' package is required. Install it with 'pip install requests'."
        )


class RateLimiter:
    """Slide a fixed-size window to enforce the 4 lookups / minute quota."""

    def __init__(self, max_calls: int, period: float) -> None:
        self.max_calls = max_calls
        self.period = period
        self.calls: deque[float] = deque()

    def wait_for_slot(self) -> None:
        now = time.monotonic()
        while True:
            while self.calls and now - self.calls[0] >= self.period:
                self.calls.popleft()
            if len(self.calls) < self.max_calls:
                self.calls.append(now)
                return
            sleep_for = self.period - (now - self.calls[0]) + 0.05
            time.sleep(max(sleep_for, 0.05))
            now = time.monotonic()


class VirusTotalError(RuntimeError):
    """Raised when the VirusTotal client encounters an error."""


@dataclass
class VTResult:
    sha256: str
    stats: Dict[str, int]
    source: str
    status: str
    analysis_link: Optional[str]
    permalink: Optional[str]
    analysis_id: Optional[str]
    fetched_at: str
    raw: Dict[str, Any]
    message: Optional[str] = None

    def detection_ratio(self) -> str:
        total = sum(self.stats.values())
        hits = self.stats.get("malicious", 0) + self.stats.get("suspicious", 0)
        return f"{hits}/{total}" if total else "n/a"

    def verdict_label(self) -> str:
        if self.stats.get("malicious"):
            return "malicious"
        if self.stats.get("suspicious"):
            return "suspicious"
        if self.stats.get("harmless"):
            return "harmless"
        if self.stats.get("undetected"):
            return "undetected"
        return "unknown"


def summarize_verdict(vt_result: Optional[VTResult], vt_error: Optional[str]) -> str:
    if vt_result:
        label = vt_result.verdict_label().lower()
        if label in {"harmless", "undetected"}:
            return "benign"
        return label
    if vt_error:
        return f"error: {vt_error}"
    return "pending"


def colorize_label(label: str) -> str:
    normalized = label.lower()
    if ENABLE_COLOR and normalized.startswith("benign"):
        return f"{ANSI_GREEN}{label}{ANSI_RESET}"
    if ENABLE_COLOR and normalized.startswith("malicious"):
        return f"{ANSI_RED}{label}{ANSI_RESET}"
    return label


def build_manifest_data(
    cluster_key: str,
    cache_root: Path,
    experiment_data_root: Path,
    samples_root: Path,
    vt_output_root: Path,
    entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "cluster_key": cluster_key,
        "generated_at": now_utc(),
        "cache_root": str(cache_root),
        "experiment_data_root": str(experiment_data_root),
        "samples_root": str(samples_root),
        "vt_output_root": str(vt_output_root),
        "entries": entries,
    }


def write_manifest(manifest_path: Path, manifest: Dict[str, Any]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)


def load_existing_manifest(manifest_path: Path, cluster_key: str) -> List[Dict[str, Any]]:
    if not manifest_path.exists():
        return []
    try:
        with manifest_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    if data.get("cluster_key") and data.get("cluster_key") != cluster_key:
        return []
    entries = data.get("entries")
    if isinstance(entries, list):
        return entries
    return []


def manifest_entry_has_error(entry: Dict[str, Any]) -> bool:
    """
    Return True when the manifest entry recorded a VirusTotal error or is missing a summary.
    """
    vt_summary = entry.get("vt_summary")
    if not isinstance(vt_summary, dict):
        return True
    error_value = vt_summary.get("error")
    if isinstance(error_value, str):
        return bool(error_value.strip())
    return bool(error_value)


def entry_to_table_row(entry: Dict[str, Any]) -> Dict[str, str]:
    vt_summary = entry.get("vt_summary") or {}
    verdict = vt_summary.get("verdict") or vt_summary.get("error") or "n/a"
    detections = vt_summary.get("detections") or "n/a"
    sha = (entry.get("script_sha256") or "")[:12]
    ast_sim = entry.get("ast_similarity")
    ast_text = f"{float(ast_sim):.4f}" if isinstance(ast_sim, (int, float)) else "n/a"
    vt_link = entry.get("vt_result_file") or vt_summary.get("error") or "n/a"
    return {
        "cluster": str(entry.get("cluster_id")),
        "sha": sha,
        "ast": ast_text,
        "verdict": str(verdict),
        "detections": str(detections),
        "link": str(vt_link),
    }


class VirusTotalClient:
    """Thin wrapper around the VirusTotal v3 API with built-in throttling."""

    API_BASE = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: str,
        per_minute: int = DEFAULT_RATE_LIMIT,
        daily_cap: int = DEFAULT_DAILY_CAP,
        poll_interval: int = 20,
        max_polls: int = 6,
    ) -> None:
        ensure_requests_available()
        self.api_key = api_key
        self.rate_limiter = RateLimiter(per_minute, 60.0)
        self.daily_cap = daily_cap
        self.poll_interval = max(poll_interval, 5)
        self.max_polls = max(max_polls, 1)
        self.requests_made = 0
        self.session = requests.Session()

    def _request(self, method: str, path: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
        if self.requests_made >= self.daily_cap:
            raise VirusTotalError(
                f"Daily VirusTotal quota exhausted ({self.requests_made}/{self.daily_cap})."
            )
        self.rate_limiter.wait_for_slot()
        headers = kwargs.pop("headers", {})
        headers["x-apikey"] = self.api_key
        kwargs["headers"] = headers
        kwargs.setdefault("timeout", 60)
        url = f"{self.API_BASE}{path}"
        try:
            response = self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:  # pragma: no cover - network errors
            raise VirusTotalError(f"VirusTotal request failed: {exc}") from exc
        self.requests_made += 1
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise VirusTotalError(
                f"VirusTotal API error {response.status_code}: {response.text.strip()}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise VirusTotalError("VirusTotal returned an invalid JSON payload") from exc

    def lookup_hash(self, sha256: str) -> Optional[VTResult]:
        payload = self._request("GET", f"/files/{sha256}")
        if not payload:
            return None
        return self._build_result_from_file(payload, source="hash-lookup")

    def upload_and_scan(self, path: Path) -> VTResult:
        with path.open("rb") as handle:
            payload = self._request("POST", "/files", files={"file": (path.name, handle)})
        if not payload:
            raise VirusTotalError("Upload succeeded but no analysis id was returned.")
        analysis_id = payload.get("data", {}).get("id")
        if not analysis_id:
            raise VirusTotalError("Response missing analysis identifier.")
        for attempt in range(self.max_polls):
            if attempt:
                time.sleep(self.poll_interval)
            analysis = self._request("GET", f"/analyses/{analysis_id}")
            if not analysis:
                continue
            status = (analysis.get("data", {}).get("attributes") or {}).get("status")
            if status == "completed":
                result = self._build_result_from_analysis(analysis, source="upload")
                result.analysis_id = analysis_id
                return result
        raise VirusTotalError(
            f"Analysis {analysis_id} did not finish after {self.max_polls} polls."
        )

    def scan_file(
        self,
        path: Path,
        sha256: Optional[str],
        force_upload: bool = False,
    ) -> VTResult:
        if sha256 and not force_upload:
            existing = self.lookup_hash(sha256)
            if existing:
                return existing
        return self.upload_and_scan(path)

    def _build_result_from_file(self, payload: Dict[str, Any], source: str) -> VTResult:
        data = payload.get("data") or {}
        attributes = data.get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
        stats = {k: int(v) for k, v in stats.items()}
        sha256 = attributes.get("sha256") or data.get("id") or ""
        link = f"{VT_GUI_BASE}/{sha256}/detection" if sha256 else None
        return VTResult(
            sha256=sha256,
            stats=stats,
            source=source,
            status="completed" if stats else attributes.get("status", "unknown"),
            analysis_link=link,
            permalink=(data.get("links") or {}).get("self"),
            analysis_id=data.get("id"),
            fetched_at=now_utc(),
            raw=payload,
        )

    def _build_result_from_analysis(self, payload: Dict[str, Any], source: str) -> VTResult:
        attributes = (payload.get("data") or {}).get("attributes") or {}
        stats = attributes.get("stats") or attributes.get("results") or {}
        stats = {k: int(v) for k, v in stats.items()}
        sha256 = (
            (payload.get("meta") or {}).get("file_info") or {}
        ).get("sha256") or attributes.get("sha256") or ""
        link = f"{VT_GUI_BASE}/{sha256}/detection" if sha256 else None
        return VTResult(
            sha256=sha256,
            stats=stats,
            source=source,
            status=attributes.get("status", "completed"),
            analysis_link=link,
            permalink=(payload.get("data", {}).get("links") or {}).get("self"),
            analysis_id=payload.get("data", {}).get("id"),
            fetched_at=now_utc(),
            raw=payload,
        )


def parse_cluster_list(values: Optional[Sequence[str]]) -> Optional[List[int]]:
    if not values:
        return None
    tokens: List[str] = []
    for value in values:
        tokens.extend(token.strip() for token in value.split(","))
    clusters: List[int] = []
    for token in tokens:
        if not token:
            continue
        try:
            clusters.append(int(token))
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid cluster id: {token!r}")
    return clusters


def load_traces(cache_root: Path, cluster_key: str) -> List[Dict[str, Any]]:
    traces_path = cache_root / cluster_key / "clustering_results_traces.json"
    if not traces_path.exists():
        raise FileNotFoundError(f"Trace file not found: {traces_path}")
    with traces_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict) and "traces" in data:
        return data["traces"]  # type: ignore[return-value]
    if isinstance(data, list):
        return data
    raise ValueError(f"Unexpected JSON structure in {traces_path}")


def select_representatives(
    traces: Iterable[Dict[str, Any]],
    allowed_clusters: Optional[Sequence[int]],
    max_per_cluster: int,
    max_total: Optional[int],
) -> List[Tuple[int, Dict[str, Any]]]:
    allowed = set(allowed_clusters or [])
    grouped: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for trace in traces:
        cluster_id = trace.get("cluster")
        if cluster_id in (None, -1):
            continue
        cluster_id = int(cluster_id)
        if allowed and cluster_id not in allowed:
            continue
        grouped[cluster_id].append(trace)

    representatives: List[Tuple[int, Dict[str, Any]]] = []
    for cluster_id in sorted(grouped):
        samples = grouped[cluster_id]
        samples.sort(
            key=lambda item: (
                as_float(item.get("ast_similarity")),
                as_float(item.get("silhouette_score")),
                as_float(item.get("suspicious_event_count")),
                as_float(item.get("virustotal_verdict_count")),
            ),
            reverse=True,
        )
        for trace in samples[: max_per_cluster or 1]:
            representatives.append((cluster_id, trace))
        if max_total and len(representatives) >= max_total:
            break
    return representatives


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_script_path(trace: Dict[str, Any], experiment_root: Path) -> Optional[Path]:
    ast_info = trace.get("ast_fingerprint") or {}
    candidate = ast_info.get("script_path")
    if isinstance(candidate, str) and candidate:
        path = Path(candidate)
        if path.exists():
            return path
    url_hash = trace.get("url_hash")
    timestamp = trace.get("timestamp")
    script_id = trace.get("script_id")
    script_hash = trace.get("hash")
    if url_hash and timestamp and script_id and script_hash:
        guess = experiment_root / str(url_hash) / str(timestamp) / "loaded_js" / f"{script_id}_{script_hash}.js"
        if guess.exists():
            return guess
    return None


def save_vt_result(
    vt_root: Path,
    cluster_key: str,
    cluster_id: int,
    trace_id: str,
    vt_result: VTResult,
) -> Path:
    vt_dir = vt_root / cluster_key
    vt_dir.mkdir(parents=True, exist_ok=True)
    filename = f"cluster-{cluster_id}_{vt_result.sha256 or trace_id}.json"
    path = vt_dir / filename
    payload = {
        "cluster_key": cluster_key,
        "cluster_id": cluster_id,
        "trace_id": trace_id,
        "fetched_at": vt_result.fetched_at,
        "result": {
            "sha256": vt_result.sha256,
            "source": vt_result.source,
            "status": vt_result.status,
            "stats": vt_result.stats,
            "analysis_link": vt_result.analysis_link,
            "permalink": vt_result.permalink,
            "analysis_id": vt_result.analysis_id,
            "message": vt_result.message,
        },
        "raw": vt_result.raw,
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return path


def render_table(rows: List[Dict[str, str]]) -> None:
    if not rows:
        print("No samples selected.")
        return
    headers = ["Cluster", "SHA256", "AST Sim", "VT Verdict", "Detections", "VT Link / Notes"]
    widths = [len(h) for h in headers]
    for row in rows:
        widths[0] = max(widths[0], len(row["cluster"]))
        widths[1] = max(widths[1], len(row["sha"]))
        widths[2] = max(widths[2], len(row["ast"]))
        widths[3] = max(widths[3], len(row["verdict"]))
        widths[4] = max(widths[4], len(row["detections"]))
        widths[5] = max(widths[5], len(row["link"]))
    fmt = "  ".join(f"{{:{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        print(
            fmt.format(
                row["cluster"],
                row["sha"],
                row["ast"],
                row["verdict"],
                row["detections"],
                row["link"],
            )
        )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Submit centroid-adjacent JS samples to VirusTotal with rate-limiting."
    )
    parser.add_argument("cluster_key", help="Cache/sample key (e.g., all-13)")
    parser.add_argument(
        "--cache-root",
        default=str(BASE_DIR / "cache"),
        help="Path to the cache directory (default: %(default)s)",
    )
    parser.add_argument(
        "--experiment-data-root",
        default=str(DEFAULT_EXPERIMENT_ROOT),
        help="Location of the experiment_data directory (default: %(default)s)",
    )
    parser.add_argument(
        "--samples-root",
        default=str(BASE_DIR / "samples"),
        help="Directory to copy representative scripts into (default: %(default)s)",
    )
    parser.add_argument(
        "--vt-output-root",
        default=str(BASE_DIR / "vt_submissions"),
        help="Directory used to store VirusTotal responses (default: %(default)s)",
    )
    parser.add_argument(
        "--clusters",
        nargs="*",
        help="Optional cluster id filters (comma or space separated).",
    )
    parser.add_argument(
        "--max-per-cluster",
        type=int,
        default=1,
        help="Number of samples to pull per cluster (default: %(default)s)",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        help="Hard limit on total samples processed (default: unlimited)",
    )
    parser.add_argument(
        "--vt-api-key",
        help="VirusTotal API key (defaults to VT_API_KEY environment variable).",
    )
    parser.add_argument(
        "--force-upload",
        action="store_true",
        help="Always upload files even if an existing report is found.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip all VirusTotal calls; useful for verifying selection/copying.",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=20,
        help="Seconds to wait between VT analysis polls (default: %(default)s).",
    )
    parser.add_argument(
        "--max-polls",
        type=int,
        default=6,
        help="Maximum analysis polls before giving up (default: %(default)s).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    cache_root = Path(args.cache_root)
    experiment_data_root = Path(args.experiment_data_root)
    samples_root = Path(args.samples_root)
    vt_output_root = Path(args.vt_output_root)
    clusters = parse_cluster_list(args.clusters)

    traces = load_traces(cache_root, args.cluster_key)
    selected = select_representatives(
        traces,
        clusters,
        max(args.max_per_cluster, 1),
        args.max_samples,
    )

    if not selected:
        print("No candidate traces found for the provided filters.")
        return 0

    vt_client: Optional[VirusTotalClient] = None
    api_key = args.vt_api_key or os.environ.get("VT_API_KEY") or HARDCODED_VT_API_KEY
    if not args.dry_run:
        if not api_key:
            parser.error("VirusTotal API key missing (set --vt-api-key or VT_API_KEY).")
        vt_client = VirusTotalClient(
            api_key=api_key,
            per_minute=DEFAULT_RATE_LIMIT,
            daily_cap=DEFAULT_DAILY_CAP,
            poll_interval=args.poll_interval,
            max_polls=args.max_polls,
        )

    manifest_path = samples_root / args.cluster_key / "vt_centroid_manifest.json"
    manifest_entries: List[Dict[str, Any]] = load_existing_manifest(
        manifest_path, args.cluster_key
    )
    entry_index_lookup: Dict[Tuple[int, Optional[str]], int] = {}
    retry_pairs: set[Tuple[int, Optional[str]]] = set()
    for idx, entry in enumerate(manifest_entries):
        if entry.get("cluster_id") is None:
            continue
        cluster_id = int(entry["cluster_id"])
        trace_id = entry.get("trace_id")
        trace_key = str(trace_id) if trace_id is not None else None
        pair = (cluster_id, trace_key)
        entry_index_lookup[pair] = idx
        if manifest_entry_has_error(entry):
            retry_pairs.add(pair)

    if retry_pairs:
        suffix = "y" if len(retry_pairs) == 1 else "ies"
        print(
            f"Detected {len(retry_pairs)} manifest entr{suffix} with VirusTotal errors; "
            "they will be retried when included in the current selection."
        )

    processed_pairs = set(entry_index_lookup.keys()) - retry_pairs
    processed_counts = Counter(pair[0] for pair in processed_pairs)
    per_cluster_counter: Dict[int, int] = defaultdict(int, processed_counts)

    selected_pairs: set[Tuple[int, Optional[str]]] = set()
    pending: List[Tuple[int, Dict[str, Any]]] = []
    for item in selected:
        cluster_id, trace = item
        trace_id_value = trace.get("trace_id")
        trace_key = str(trace_id_value) if trace_id_value is not None else None
        pair = (cluster_id, trace_key)
        selected_pairs.add(pair)
        if pair in processed_pairs:
            continue
        pending.append(item)

    if retry_pairs:
        missing_retries = retry_pairs - selected_pairs
        if missing_retries:
            suffix = "y was" if len(missing_retries) == 1 else "ies were"
            print(
                f"Warning: {len(missing_retries)} manifest entr{suffix} flagged for retry but "
                "filtered out of the current run; adjust cluster filters or max-per-cluster "
                "to process them."
            )

    if not pending:
        if retry_pairs and manifest_entries:
            print(
                "No pending submissions match the requested filters, so existing manifest errors "
                "remain until their traces are selected again."
            )
        elif manifest_entries:
            print("All selected samples already processed; manifest is up to date.")
        else:
            print("No candidate traces found for the provided filters.")
        return 0

    def dump_manifest() -> None:
        manifest = build_manifest_data(
            args.cluster_key,
            cache_root,
            experiment_data_root,
            samples_root,
            vt_output_root,
            manifest_entries,
        )
        write_manifest(manifest_path, manifest)

    progress = tqdm(
        pending,
        total=len(pending),
        unit="script",
        desc="Processing samples",
        disable=len(pending) == 0,
    )

    try:
        for index, (cluster_id, trace) in enumerate(progress, start=1):
            trace_id_value = trace.get("trace_id")
            trace_key = str(trace_id_value) if trace_id_value is not None else None
            pair = (cluster_id, trace_key)
            if pair in processed_pairs:
                continue
            per_cluster_counter[cluster_id] += 1
            progress.write(
                f"[{index}/{len(pending)}] Cluster {cluster_id}: "
                f"{trace_id_value} ({trace.get('script_url')})"
            )

            source_path = resolve_script_path(trace, experiment_data_root)
            if not source_path:
                progress.write("    [WARN] Unable to locate script on disk; skipping.")
                continue

            sample_path = source_path

            computed_sha = compute_sha256(sample_path)
            declared_sha = str(trace.get("script_sha256") or "")
            if declared_sha and declared_sha.lower() != computed_sha.lower():
                progress.write(
                    "    [WARN] Script SHA mismatch; using computed hash "
                    f"{computed_sha} instead of declared {declared_sha}"
                )

            vt_result: Optional[VTResult] = None
            vt_error: Optional[str] = None
            if vt_client:
                try:
                    vt_result = vt_client.scan_file(
                        sample_path,
                        sha256=declared_sha or computed_sha,
                        force_upload=args.force_upload,
                    )
                except VirusTotalError as exc:
                    vt_error = str(exc)
                    progress.write(f"    [ERROR] {vt_error}")
            else:
                vt_error = "dry-run (VirusTotal submission skipped)"

            vt_result_path: Optional[Path] = None
            if vt_result:
                vt_result_path = save_vt_result(
                    vt_output_root,
                    args.cluster_key,
                    cluster_id,
                    str(trace.get("trace_id")),
                    vt_result,
                )
                progress.write(
                    "    VirusTotal verdict: "
                    f"{vt_result.verdict_label()} ({vt_result.detection_ratio()})"
                )
                if vt_result.analysis_link:
                    progress.write(f"    GUI link: {vt_result.analysis_link}")
                if vt_result.permalink:
                    progress.write(f"    API link: {vt_result.permalink}")

            new_entry = {
                "cluster_id": cluster_id,
                "trace_id": trace_id_value,
                "script_url": trace.get("script_url"),
                "page_url": trace.get("page_url"),
                "script_sha256": declared_sha or computed_sha,
                "ast_similarity": trace.get("ast_similarity"),
                "silhouette_score": trace.get("silhouette_score"),
                "suspicious_event_count": trace.get("suspicious_event_count"),
                "source_script_path": str(source_path),
                "sample_path": str(sample_path),
                "vt_result_file": str(vt_result_path) if vt_result_path else None,
                "vt_summary": {
                    "verdict": vt_result.verdict_label() if vt_result else None,
                    "detections": vt_result.detection_ratio() if vt_result else None,
                    "error": vt_error,
                },
            }
            existing_index = entry_index_lookup.get(pair)
            if existing_index is not None:
                manifest_entries[existing_index] = new_entry
            else:
                entry_index_lookup[pair] = len(manifest_entries)
                manifest_entries.append(new_entry)

            summary_label = summarize_verdict(vt_result, vt_error)
            colored_summary = colorize_label(summary_label)
            progress.write(
                f"    Summary: Cluster {cluster_id}: {colored_summary} "
                f"based on {per_cluster_counter[cluster_id]} submitted file(s)."
            )

            if vt_error and not args.dry_run:
                dump_manifest()
                progress.write(f"    Partial manifest saved to {manifest_path}")
                break
            processed_pairs.add(pair)
    finally:
        progress.close()
        dump_manifest()

    print(f"\nManifest written to {manifest_path}")

    print("\nVirusTotal verdict summary:")
    render_table([entry_to_table_row(entry) for entry in manifest_entries])
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
