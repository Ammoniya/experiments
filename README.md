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
| `--use-cache` | Reuse the cached `.pkl`/JSON stored under `cache/<timestamp-key>/`. Requires specifying the timestamp key (see below). |
| `--no-cache` | Force a full recompute even when cached artifacts are present. |
| `--dtw-max-distance <value>` | Cap DTW distances (default `${DEFAULT_DTW_MAX_DISTANCE}` = 200) to activate LB_Keogh pruning. |
| `--dtw-lb-ratio <value>` | Window ratio for LB_Keogh pruning (default `${DEFAULT_DTW_LB_RATIO}` = 0.05). Set ≤0 to disable via ratio. |
| `--disable-dtw-pruning` | Skip LB_Keogh pruning entirely (legacy behavior). |
| `--require-ast-preview` | Filter traces so only scripts with cached AST previews are clustered. |
| `--timestamp <values>` | Restrict processing to timestamp directories. Accepts space/comma separated values (use quotes or `--` before positional args) and can be repeated. Multiple timestamps are concatenated with `-` to form the cache key. |
| `--max-scripts <value>` | Limit how many scripts are processed (equivalent to the first positional arg, use `0` for “all”). |
| `--min-cluster-size <value>` | Set HDBSCAN’s minimum cluster size (equivalent to the second positional arg). |
| `-h`, `--help` | Show the built-in usage text. |
| `--` | Stop option parsing (pass following args through as positionals). |

**Timestamp filtering tips**

- Provide a single timestamp: `--timestamp 20251112`.
- Provide many via spaces/commas: `--timestamp "20251112 20251113"` or `--timestamp 20251112 20251113 -- 250 10` (use `--` before positional arguments).
- Repeat the flag if you prefer: `--timestamp 20251112 --timestamp 20251113`.
- The exact sequence supplied becomes the cache key (e.g., `20251112-20251113`), so reuse the same ordering when calling `--use-cache`.
- You can pass either full directory names (e.g., `20251112-125136`) or just the `YYYYMMDD` prefix; prefix filters include every directory that starts with that date.

## Environment variables

These mirror the CLI switches and can be exported inline for a single invocation:

| Variable | Effect |
| --- | --- |
| `USE_CACHE=1` | Same as `--use-cache`. |
| `DTW_MAX_DISTANCE=<value>` | Default for `--dtw-max-distance`. |
| `DTW_LB_RATIO=<value>` | Default for `--dtw-lb-ratio`. |
| `DTW_PRUNING_ENABLED=0` | Equivalent to `--disable-dtw-pruning`. |
| `REQUIRE_AST_PREVIEW=1` | Enables the AST-preview filter without editing the script. |
| `TSNE_FORCE=1` | Forces recomputation of t-SNE embeddings even if cached data exists. |
| `SKIP_VIZ=1` | Prepare the Dash app without launching a server. |
| `TIMESTAMP_FILTER="ts1,ts2"` | Comma/space separated timestamps (equivalent to repeating `--timestamp`, also defines the cache key). |
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
./run_clustering.sh --use-cache --timestamp 20251112 20251113 --require-ast-preview
```

## Cache layout

All artifacts now live under `cache/<timestamp-key>/`, where `<timestamp-key>` is `all` (no filter) or the concatenation of every timestamp you supplied, in order, separated by `-`. Reusing a cache requires specifying the same key via `--timestamp`/`TIMESTAMP_FILTER`.

Example structure for `--timestamp 20251112 20251113`:

```
cache/
└── 20251112-20251113/
    ├── clustering_results.pkl
    ├── clustering_results_traces.json
    └── cluster_report.json
```

## Output artifacts

A successful run writes:

- `cache/<timestamp-key>/clustering_results.pkl` – serialized clustering state consumed by downstream scripts.
- `cache/<timestamp-key>/clustering_results_traces.json` – trace-only JSON for quick inspection.
- `cache/<timestamp-key>/cluster_report.json` – structured cluster metadata (counts, AST summaries, alignments, WP artifacts, etc.).

Running `./run_clustering.sh --require-ast-preview` ensures every trace in these artifacts already has an AST preview, which simplifies AST-centric reviews. Feel free to mix and match the options above to match your analysis goals.
