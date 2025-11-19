# Clustering Pipeline Quick Reference

This repository centers around `run_clustering.sh`, which orchestrates the full JavaScript clustering pipeline (trace extraction, DTW, clustering, reporting, and visualization). The script wraps several Python entry points, so invoking it is the easiest way to run end-to-end workflows.

## Basic usage

```bash
./run_clustering.sh [OPTIONS] [MAX_SCRIPTS] [MIN_CLUSTER_SIZE]
```

- `MAX_SCRIPTS` (default `100`) limits how many scripts are ingested.
- `MIN_CLUSTER_SIZE` (default `5`) is forwarded to HDBSCAN.

Example: process at most 250 scripts, require clusters of size ≥10, and only keep traces with cached AST previews:

```bash
./run_clustering.sh --require-ast-preview 250 10
```

## Flags and options

| Option | Description |
| --- | --- |
| `--use-cache` | Reuse a cached run located under `cache/<cache-key>/`. Requires `--cache-key` (see below). |
| `--no-cache` | Force a full recompute even when cached artifacts are present. |
| `--dtw-max-distance <value>` | Cap DTW distances (default `${DEFAULT_DTW_MAX_DISTANCE}` = 200) to activate LB_Keogh pruning. |
| `--dtw-lb-ratio <value>` | Window ratio for LB_Keogh pruning (default `${DEFAULT_DTW_LB_RATIO}` = 0.05). Set ≤0 to disable via ratio. |
| `--disable-dtw-pruning` | Skip LB_Keogh pruning entirely (legacy behavior). |
| `--require-ast-preview` | Filter traces so only scripts with cached AST previews are clustered. |
| `--min-suspicious-events <value>` | Drop traces that contain fewer than this many suspicious events (default `0`, which keeps everything). |
| `--timestamp <values>` | Restrict processing to timestamp directories. Accepts space/comma separated values (use quotes or `--` before positional args) and can be repeated. Multiple timestamps are concatenated with `-` to form the timestamp key. |
| `--max-scripts <value>` | Limit how many scripts are processed (equivalent to the first positional arg, use `0` for “all”). |
| `--min-cluster-size <value>` | Set HDBSCAN’s minimum cluster size (equivalent to the second positional arg). |
| `--cache-key <value>` | Explicit cache directory name (e.g., `20251112-2`). Required with `--use-cache` and useful to label a run manually. |
| `-h`, `--help` | Show the built-in usage text. |
| `--` | Stop option parsing (pass following args through as positionals). |

**Timestamp filtering tips**

- Provide a single timestamp: `--timestamp 20251112`.
- Provide many via spaces/commas: `--timestamp "20251112 20251113"` or `--timestamp 20251112 20251113 -- 250 10` (use `--` before positional arguments).
- Repeat the flag if you prefer: `--timestamp 20251112 --timestamp 20251113`.
- The exact sequence supplied becomes the timestamp key (e.g., `20251112-20251113`), and new runs auto-generate cache directories such as `20251112-20251113-1`, `20251112-20251113-2`, etc.
- You can pass either full directory names (e.g., `20251112-125136`) or just the `YYYYMMDD` prefix; prefix filters include every directory that starts with that date.
- To reuse an existing cache (or to override the auto-generated name), pass `--cache-key <cache-directory>` alongside the timestamp filter(s). This is required with `--use-cache`.

## Environment variables

These mirror the CLI switches and can be exported inline for a single invocation:

| Variable | Effect |
| --- | --- |
| `USE_CACHE=1` | Same as `--use-cache`. |
| `DTW_MAX_DISTANCE=<value>` | Default for `--dtw-max-distance`. |
| `DTW_LB_RATIO=<value>` | Default for `--dtw-lb-ratio`. |
| `DTW_PRUNING_ENABLED=0` | Equivalent to `--disable-dtw-pruning`. |
| `REQUIRE_AST_PREVIEW=1` | Enables the AST-preview filter without editing the script. |
| `MIN_SUSPICIOUS_EVENTS=<value>` | Default minimum suspicious event count passed to `--min-suspicious-events`. |
| `TSNE_FORCE=1` | Forces recomputation of t-SNE embeddings even if cached data exists. |
| `SKIP_VIZ=1` | Prepare the Dash app without launching a server. |
| `TIMESTAMP_FILTER="ts1,ts2"` | Comma/space separated timestamps (equivalent to repeating `--timestamp`, also defines the base timestamp key). |
| `CACHE_KEY=<value>` | Override/select the cache directory name (required with `--use-cache`). |
| `JOBLIB_TEMP_FOLDER=<path>` | Override the temp directory joblib uses (defaults to `.joblib_tmp`). |

Examples:

```bash
# Reuse cached clustering results, only run AST-ready traces, and skip the Dash UI.
USE_CACHE=1 REQUIRE_AST_PREVIEW=1 TIMESTAMP_FILTER="20251112" SKIP_VIZ=1 ./run_clustering.sh

# Customize DTW pruning without CLI flags.
DTW_MAX_DISTANCE=150 DTW_LB_RATIO=0.08 ./run_clustering.sh --require-ast-preview

# Cluster a single crawl timestamp.
./run_clustering.sh --require-ast-preview --timestamp 20251112

# Same run with explicit flags (no positional args needed) and unlimited scripts.
./run_clustering.sh --require-ast-preview --timestamp 20251112 --max-scripts 0 --min-cluster-size 10

# Cluster two timestamps, then pass the same pair to reuse the cache.
./run_clustering.sh --timestamp 20251112 20251113 --require-ast-preview
./run_clustering.sh --use-cache --timestamp 20251112 20251113 --cache-key 20251112-20251113-1 --require-ast-preview

# Reuse a specific cache directory explicitly.
./run_clustering.sh --use-cache --timestamp 20251112 --cache-key 20251112-2 --require-ast-preview

# Process multiple days in sequence without launching the Dash UI.
SKIP_VIZ=1 for ts in 20251111 20251112 20251113; do \
  ./run_clustering.sh --no-cache --require-ast-preview --disable-dtw-pruning \
    --timestamp "$ts" --max-scripts 0 --min-cluster-size 10; \
done
```

## Cache layout

All artifacts now live under `cache/<cache-key>/`, where the cache key defaults to `<timestamp-key>-N` (`N` is an auto-incrementing counter per timestamp combination). When you pass `--cache-key`, that value is used verbatim. Reusing a cache requires supplying the matching `--cache-key` (and the same timestamp filter so downstream scripts stay consistent).

Example structure for `--timestamp 20251112 20251113` (first run auto-creates `20251112-20251113-1`):

```
cache/
└── 20251112-20251113-1/
    ├── clustering_results.pkl
    ├── clustering_results_traces.json
    ├── cluster_report.json
    └── cache_config.json
```

## Output artifacts

A successful run writes:

- `cache/<cache-key>/clustering_results.pkl` – serialized clustering state consumed by downstream scripts.
- `cache/<cache-key>/clustering_results_traces.json` – trace-only JSON for quick inspection.
- `cache/<cache-key>/cluster_report.json` – structured cluster metadata (counts, AST summaries, alignments, WP artifacts, etc.).
- `cache/<cache-key>/cache_config.json` – snapshot of the options used to create that cache (command string, timestamps, DTW settings, AST filter, etc.).

Running `./run_clustering.sh --require-ast-preview` ensures every trace in these artifacts already has an AST preview, which simplifies AST-centric reviews. Feel free to mix and match the options above to match your analysis goals.

## Building a consolidated dashboard

After you compute clusters for different days/timestamp groups, summarize the most interesting clusters per run with:

```bash
./aggregate_cluster_reports.py --cache-root cache --output cache_summary.html --top-n 5
```

The script scans every `cache/<cache-key>/cluster_report.json`, computes a simple “interesting score” (mix of suspicious events, silhouette, and size), and writes an HTML dashboard highlighting the top `N` clusters for each timestamp key. Each entry includes:

- A link to the raw `cluster_report.json` for deeper inspection.
- A ready-to-run reuse command (e.g., `./run_clustering.sh --use-cache --cache-key 20251112-2 --timestamp 20251112`) so you can relaunch the Dash visualization for that cache.

Open `cache_summary.html` in a browser to explore daily highlights and jump directly into the corresponding cache directories.
