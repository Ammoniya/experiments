#!/bin/bash
# Quick start script for clustering JavaScript scripts

set -e

ORIGINAL_COMMAND="$0 $*"

DEFAULT_OUTPUT="clustering_results.pkl"
DEFAULT_DTW_MAX_DISTANCE="${DEFAULT_DTW_MAX_DISTANCE:-200}"
DEFAULT_DTW_LB_RATIO="${DEFAULT_DTW_LB_RATIO:-0.05}"

# Ensure joblib has a writable temp directory (shared memory is not available here)
if [ -z "${JOBLIB_TEMP_FOLDER:-}" ]; then
    JOBLIB_TEMP_FOLDER="$PWD/.joblib_tmp"
fi
if [ ! -d "$JOBLIB_TEMP_FOLDER" ]; then
    mkdir -p "$JOBLIB_TEMP_FOLDER"
fi
export JOBLIB_TEMP_FOLDER

show_help() {
    cat <<'EOF'
Usage: ./run_clustering.sh [OPTIONS] [MAX_SCRIPTS] [MIN_CLUSTER_SIZE]

Options:
  --use-cache          Skip recomputing clusters and reuse the last results file.
  --no-cache           Force recomputing clusters even if a cache file exists.
  --dtw-max-distance   Cap DTW distances (enables LB_Keogh pruning in cluster_scripts.py).
  --dtw-lb-ratio       Override the LB_Keogh window ratio passed to cluster_scripts.py.
  --disable-dtw-pruning
                        Skip DTW lower-bound pruning (restores legacy behavior).
  --require-ast-preview
                        Filter to scripts that already have cached AST previews.
  --timestamp VALUE    Restrict processing to one or more timestamp directories (repeatable).
  --max-scripts VALUE  Limit how many scripts are processed (use 0 for no limit).
  --min-cluster-size VALUE
                        Override the minimum HDBSCAN cluster size.
  --cache-key VALUE    Explicit cache directory key (e.g., 20251112-1) for reuse or custom labeling.
  -h, --help           Show this help message and exit.

Environment:
  USE_CACHE=1          Equivalent to providing --use-cache.
  DTW_MAX_DISTANCE     Default value for --dtw-max-distance.
  DTW_LB_RATIO         Default value for --dtw-lb-ratio.
  DTW_PRUNING_ENABLED  Set to 0 to disable pruning without editing the script.
  TSNE_FORCE=1         Recompute t-SNE embeddings even if cached ones exist.
  TIMESTAMP_FILTER     Comma/space separated list of timestamps (equivalent to repeating --timestamp).
  CACHE_KEY            Override cache directory name (needed with --use-cache).
  JOBLIB_TEMP_FOLDER   Writable directory for joblib's temp storage (defaults to .joblib_tmp).

Examples:
  ./run_clustering.sh 250 10
  USE_CACHE=1 ./run_clustering.sh --use-cache
EOF
}

add_timestamp_filter() {
    local value="$1"
    if [ -z "$value" ]; then
        return
    fi
    for existing in "${TIMESTAMP_FILTERS[@]}"; do
        if [ "$existing" = "$value" ]; then
            return
        fi
    done
    TIMESTAMP_FILTERS+=("$value")
}

parse_timestamp_values() {
    local raw="$1"
    if [ -z "$raw" ]; then
        return
    fi
    raw="${raw//,/ }"
    for token in $raw; do
        add_timestamp_filter "$token"
    done
}

write_cache_metadata() {
    if [ "$USE_CACHE" -ne 0 ]; then
        return
    fi
    local config_path="$RUN_CACHE_DIR/cache_config.json"
    local timestamp_serialized=""
    if [ ${#TIMESTAMP_FILTERS[@]} -gt 0 ]; then
        timestamp_serialized=$(printf "%s\n" "${TIMESTAMP_FILTERS[@]}")
    fi

    RUN_COMMAND="$ORIGINAL_COMMAND" \
    TIMESTAMP_FILTERS_ENV="$timestamp_serialized" \
    CACHE_CONFIG_PATH="$config_path" \
    CACHE_KEY_NAME_ENV="$CACHE_DIR_KEY" \
    TIMESTAMP_KEY_ENV="$TIMESTAMP_KEY" \
    MAX_SCRIPTS_ENV="$MAX_SCRIPTS" \
    MIN_CLUSTER_ENV="$MIN_CLUSTER_SIZE" \
    REQUIRE_AST_ENV="$REQUIRE_AST_PREVIEW" \
    DTW_MAX_ENV="$DTW_MAX_DISTANCE" \
    DTW_LB_ENV="$DTW_LB_RATIO" \
    DTW_PRUNING_ENV="$DTW_PRUNING_ENABLED" \
    DATA_DIR_ENV="$DATA_DIR" \
    python3 <<'PY'
import json
import os
import time

def parse_int(name):
    value = os.environ.get(name)
    if value in (None, "", "None"):
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value

def parse_float(name):
    value = os.environ.get(name)
    if value in (None, "", "None"):
        return None
    try:
        return float(value)
    except ValueError:
        return value

config = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "command": os.environ.get("RUN_COMMAND"),
    "timestamp_filters": [
        line for line in os.environ.get("TIMESTAMP_FILTERS_ENV", "").splitlines() if line
    ],
    "timestamp_key": os.environ.get("TIMESTAMP_KEY_ENV"),
    "cache_key": os.environ.get("CACHE_KEY_NAME_ENV"),
    "data_dir": os.environ.get("DATA_DIR_ENV"),
    "max_scripts": parse_int("MAX_SCRIPTS_ENV"),
    "min_cluster_size": parse_int("MIN_CLUSTER_ENV"),
    "require_ast_preview": os.environ.get("REQUIRE_AST_ENV") == "1",
    "dtw": {
        "max_distance": parse_float("DTW_MAX_ENV"),
        "lb_ratio": parse_float("DTW_LB_ENV"),
        "pruning_enabled": os.environ.get("DTW_PRUNING_ENV") != "0"
    },
}

with open(os.environ["CACHE_CONFIG_PATH"], "w", encoding="utf-8") as fh:
    json.dump(config, fh, indent=2)
    fh.write("\n")
PY

    if [ $? -eq 0 ]; then
        echo "[INFO] Cache metadata saved to: $config_path"
    else
        echo "[WARN] Failed to write cache metadata at $config_path"
    fi
}

USE_CACHE="${USE_CACHE:-0}"
DTW_PRUNING_ENABLED="${DTW_PRUNING_ENABLED:-1}"
DTW_MAX_DISTANCE="${DTW_MAX_DISTANCE:-$DEFAULT_DTW_MAX_DISTANCE}"
DTW_LB_RATIO="${DTW_LB_RATIO:-$DEFAULT_DTW_LB_RATIO}"
REQUIRE_AST_PREVIEW="${REQUIRE_AST_PREVIEW:-0}"
TIMESTAMP_FILTER="${TIMESTAMP_FILTER:-}"
CACHE_KEY_OVERRIDE="${CACHE_KEY:-}"
MAX_SCRIPTS_OVERRIDE=""
MIN_CLUSTER_OVERRIDE=""
TIMESTAMP_FILTERS=()
if [ -n "$TIMESTAMP_FILTER" ]; then
    parse_timestamp_values "$TIMESTAMP_FILTER"
fi
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --use-cache)
            USE_CACHE=1
            shift
            ;;
        --no-cache)
            USE_CACHE=0
            shift
            ;;
        --dtw-max-distance)
            if [ -z "${2:-}" ]; then
                echo "--dtw-max-distance requires a numeric value"
                exit 1
            fi
            DTW_MAX_DISTANCE="$2"
            shift 2
            ;;
        --dtw-lb-ratio)
            if [ -z "${2:-}" ]; then
                echo "--dtw-lb-ratio requires a numeric value"
                exit 1
            fi
            DTW_LB_RATIO="$2"
            shift 2
            ;;
        --disable-dtw-pruning)
            DTW_PRUNING_ENABLED=0
            shift
            ;;
        --require-ast-preview)
            REQUIRE_AST_PREVIEW=1
            shift
            ;;
        --max-scripts)
            if [ -z "${2:-}" ]; then
                echo "--max-scripts requires a numeric value (use 0 for no limit)"
                exit 1
            fi
            MAX_SCRIPTS_OVERRIDE="$2"
            shift 2
            ;;
        --min-cluster-size)
            if [ -z "${2:-}" ]; then
                echo "--min-cluster-size requires a numeric value"
                exit 1
            fi
            MIN_CLUSTER_OVERRIDE="$2"
            shift 2
            ;;
        --cache-key)
            if [ -z "${2:-}" ]; then
                echo "--cache-key requires a value (e.g., 20251112-1)"
                exit 1
            fi
            CACHE_KEY_OVERRIDE="$2"
            shift 2
            ;;
        --timestamp)
            shift
            consumed_any=0
            if [ $# -eq 0 ]; then
                echo "--timestamp requires at least one value (e.g., 20251112 20251113)"
                exit 1
            fi
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --|--*)
                        break
                        ;;
                    -*)
                        break
                        ;;
                    *)
                        parse_timestamp_values "$1"
                        consumed_any=1
                        shift
                        ;;
                esac
            done
            if [ "$consumed_any" -eq 0 ]; then
                echo "--timestamp requires at least one value (e.g., 20251112)"
                exit 1
            fi
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Use --help to see available options."
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

if [ "$#" -gt 0 ]; then
    POSITIONAL_ARGS+=("$@")
fi

if [ "$#" -gt 0 ]; then
    POSITIONAL_ARGS+=("$@")
fi

if [ "$USE_CACHE" -eq 1 ] && [ ${#TIMESTAMP_FILTERS[@]} -eq 0 ]; then
    echo "--use-cache requires at least one timestamp via --timestamp or TIMESTAMP_FILTER."
    exit 1
fi

if [ -n "$MAX_SCRIPTS_OVERRIDE" ]; then
    MAX_SCRIPTS="$MAX_SCRIPTS_OVERRIDE"
elif [ ${#POSITIONAL_ARGS[@]} -ge 1 ]; then
    MAX_SCRIPTS="${POSITIONAL_ARGS[0]}"
else
    MAX_SCRIPTS=100
fi

if [ -n "$MIN_CLUSTER_OVERRIDE" ]; then
    MIN_CLUSTER_SIZE="$MIN_CLUSTER_OVERRIDE"
elif [ ${#POSITIONAL_ARGS[@]} -ge 2 ]; then
    MIN_CLUSTER_SIZE="${POSITIONAL_ARGS[1]}"
else
    MIN_CLUSTER_SIZE=5
fi

echo "========================================"
echo "JavaScript Script Clustering Pipeline"
echo "========================================"
echo ""

# Configuration
DATA_DIR="experiment_data"

if [ ${#TIMESTAMP_FILTERS[@]} -gt 0 ]; then
    TIMESTAMP_KEY="${TIMESTAMP_FILTERS[0]}"
    if [ ${#TIMESTAMP_FILTERS[@]} -gt 1 ]; then
        for ts in "${TIMESTAMP_FILTERS[@]:1}"; do
            TIMESTAMP_KEY="$TIMESTAMP_KEY-$ts"
        done
    fi
else
    TIMESTAMP_KEY="all"
fi

CACHE_ROOT="cache"
mkdir -p "$CACHE_ROOT"

if [ -z "$CACHE_KEY_OVERRIDE" ]; then
    if [ "$USE_CACHE" -eq 1 ]; then
        echo "--use-cache requires --cache-key (e.g., --cache-key ${TIMESTAMP_KEY}-1)."
        exit 1
    fi
    suffix=1
    while true; do
        candidate="${TIMESTAMP_KEY}-${suffix}"
        if [ ! -e "$CACHE_ROOT/$candidate" ]; then
            CACHE_DIR_KEY="$candidate"
            break
        fi
        suffix=$((suffix + 1))
    done
else
    CACHE_DIR_KEY="$CACHE_KEY_OVERRIDE"
fi

RUN_CACHE_DIR="$CACHE_ROOT/$CACHE_DIR_KEY"
OUTPUT="$RUN_CACHE_DIR/$DEFAULT_OUTPUT"
REPORT_FILE="$RUN_CACHE_DIR/cluster_report.json"

if [ "$USE_CACHE" -eq 1 ]; then
    if [ ! -d "$RUN_CACHE_DIR" ]; then
        echo "Cache directory $RUN_CACHE_DIR not found (use --cache-key to pick an existing run)."
        exit 1
    fi
else
    if [ -e "$RUN_CACHE_DIR" ] && [ -z "$CACHE_KEY_OVERRIDE" ]; then
        # Should not happen because we auto-selected unused suffix, but guard anyway.
        echo "Cache directory $RUN_CACHE_DIR already exists. Choose a different --cache-key."
        exit 1
    fi
    if [ -n "$CACHE_KEY_OVERRIDE" ] && [ -e "$RUN_CACHE_DIR" ]; then
        echo "Cache directory $RUN_CACHE_DIR already exists. Choose a new --cache-key or remove it."
        exit 1
    fi
    mkdir -p "$RUN_CACHE_DIR"
fi

echo "Configuration:"
echo "  Data directory: $DATA_DIR"
echo "  Max scripts: $MAX_SCRIPTS"
echo "  Min cluster size: $MIN_CLUSTER_SIZE"
if [ "$DTW_PRUNING_ENABLED" -eq 1 ]; then
    echo "  DTW max distance: $DTW_MAX_DISTANCE"
    echo "  DTW LB ratio: $DTW_LB_RATIO"
else
    echo "  DTW pruning: disabled"
fi
if [ "$USE_CACHE" -eq 1 ]; then
    echo "  Cache mode: enabled (expecting $OUTPUT)"
else
    echo "  Cache mode: disabled"
fi
if [ "$REQUIRE_AST_PREVIEW" -eq 1 ]; then
    echo "  AST preview filter: enabled (scripts missing previews will be skipped)"
else
    echo "  AST preview filter: disabled"
fi
if [ ${#TIMESTAMP_FILTERS[@]} -gt 0 ]; then
    echo "  Timestamp filter: ${TIMESTAMP_FILTERS[*]}"
else
    echo "  Timestamp filter: none"
fi
echo "  Timestamp key: $TIMESTAMP_KEY"
echo "  Cache key: $CACHE_DIR_KEY"
echo "  Cache directory: $RUN_CACHE_DIR"
echo "  JOBLIB_TEMP_FOLDER: $JOBLIB_TEMP_FOLDER"
echo ""

# Step 1: Check dependencies
echo "[1/7] Checking dependencies..."
python3 << 'EOF'
import importlib.util as ilu
import sys

missing = []

def has_module(module_name):
    return ilu.find_spec(module_name) is not None

required = [
    ("numpy", "numpy"),
    ("pandas", "pandas"),
    ("scipy", "scipy"),
    ("sklearn", "scikit-learn"),
    ("hdbscan", "hdbscan"),
    ("dash", "dash"),
    ("plotly", "plotly"),
]

for module_name, pip_name in required:
    if not has_module(module_name):
        missing.append(pip_name)

if has_module("dtaidistance"):
    print("[OK] dtaidistance (fast DTW)")
else:
    print("[WARN] dtaidistance not found, will use fastdtw (slower)")
    if has_module("fastdtw"):
        print("[OK] fastdtw (fallback)")
    else:
        missing.append("dtaidistance OR fastdtw")

if has_module("umap"):
    print("[OK] umap-learn (recommended)")
else:
    print("[WARN] umap-learn not found, will use t-SNE (slower)")

if missing:
    print(f"\n Missing dependencies: {', '.join(missing)}")
    print("Install with: pip install -r requirements.txt")
    sys.exit(1)
else:
    print("\n[OK] All required dependencies installed")
EOF

if [ $? -ne 0 ]; then
    echo ""
    echo "Please install missing dependencies first:"
    echo "  pip install -r requirements.txt"
    exit 1
fi

# Step 2: Run clustering or reuse cache
echo ""
if [ "$USE_CACHE" -eq 1 ]; then
    if [ -f "$OUTPUT" ]; then
        echo "[2/7] Reusing cached clustering results..."
        echo "  Cache file: $OUTPUT"
    else
        echo "[2/7] Cache requested but $OUTPUT was not found."
        echo "       Falling back to full clustering run..."
        USE_CACHE=0
    fi
fi

if [ "$USE_CACHE" -eq 0 ]; then
    echo "[2/7] Running clustering pipeline..."
    echo "  Data directory: $DATA_DIR"
    echo "  Max scripts: $MAX_SCRIPTS"
    echo "  Min cluster size: $MIN_CLUSTER_SIZE"
    echo ""

    DTW_ARGS=()
    if [ "$DTW_PRUNING_ENABLED" -eq 1 ]; then
        DTW_ARGS+=(--dtw-max-distance "$DTW_MAX_DISTANCE" --dtw-lb-ratio "$DTW_LB_RATIO")
    fi
    FILTER_ARGS=()
    if [ "$REQUIRE_AST_PREVIEW" -eq 1 ]; then
        FILTER_ARGS+=(--require-ast-preview)
    fi
    if [ ${#TIMESTAMP_FILTERS[@]} -gt 0 ]; then
        for ts in "${TIMESTAMP_FILTERS[@]}"; do
            FILTER_ARGS+=(--timestamp "$ts")
        done
    fi

    python3 cluster_scripts.py \
        --data-dir "$DATA_DIR" \
        --max-scripts "$MAX_SCRIPTS" \
        --min-cluster-size "$MIN_CLUSTER_SIZE" \
        --output "$OUTPUT" \
        "${DTW_ARGS[@]}" \
        "${FILTER_ARGS[@]}"

    if [ $? -ne 0 ]; then
        echo "Clustering failed!"
        exit 1
    fi
else
    echo "  Skipping clustering step."
fi

# Step 3: Verify output
echo ""
echo "[3/7] Verifying output..."
if [ -f "$OUTPUT" ]; then
    echo "[OK] Results saved to: $OUTPUT"
    SIZE=$(du -h "$OUTPUT" | cut -f1)
    echo "  File size: $SIZE"
else
    echo "Output file not found!"
    exit 1
fi

# Step 4: Compute and cache t-SNE embeddings
echo ""
echo "[4/7] Computing t-SNE embeddings..."
TSNE_ARGS=(--results "$OUTPUT")
if [ "${TSNE_FORCE:-0}" -eq 1 ]; then
    TSNE_ARGS+=(--force)
fi
if python3 compute_tsne_embeddings.py "${TSNE_ARGS[@]}"; then
    echo "[OK] t-SNE embeddings cached."
else
    echo "[WARN] Failed to compute t-SNE embeddings. Visualization will recompute them on demand."
fi

# Step 5: Precompute subsequence alignments
echo ""
echo "[5/7] Precomputing subsequence alignment cache..."
if python3 precompute_subsequence_alignments.py --results "$OUTPUT"; then
    echo "[OK] Subsequence DTW cache ready."
else
    echo "Failed to build subsequence alignment cache. Visualization will fall back to error messages."
fi

# Step 6: Generate JSON report
echo ""
echo "[6/7] Generating cluster report (JSON)..."
python3 generate_cluster_report.py \
    --results "$OUTPUT" \
    --data-dir "$DATA_DIR" \
    --output "$REPORT_FILE"
if [ $? -ne 0 ]; then
    echo "Failed to generate cluster report!"
    exit 1
fi
echo "[OK] Cluster report saved to: $REPORT_FILE"

if [ "$USE_CACHE" -eq 0 ]; then
    write_cache_metadata
fi

# Step 7: Launch visualization
echo ""
echo "[7/7] Launching interactive visualization..."
echo ""

VIZ_ARGS=()
if [ "${SKIP_VIZ:-0}" = "1" ]; then
    echo "SKIP_VIZ=1 detected - initializing Dash without starting the server."
    VIZ_ARGS+=(--no-server)
fi

echo "========================================"
if [ "${#VIZ_ARGS[@]}" -eq 0 ]; then
    echo "Opening Dash app at http://127.0.0.1:8050"
    echo "Press Ctrl+C to stop the server"
else
    echo "Dash app will be prepared without launching a server (headless mode)"
fi
echo "========================================"
echo ""

python3 visualize_clusters.py \
    --results "$OUTPUT" \
    --data-dir "$DATA_DIR" \
    "${VIZ_ARGS[@]}"
