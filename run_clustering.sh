#!/bin/bash
# Quick start script for clustering JavaScript scripts

set -e

DEFAULT_OUTPUT="clustering_results.pkl"

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
  -h, --help           Show this help message and exit.

Environment:
  USE_CACHE=1          Equivalent to providing --use-cache.
  TSNE_FORCE=1         Recompute t-SNE embeddings even if cached ones exist.
  JOBLIB_TEMP_FOLDER   Writable directory for joblib's temp storage (defaults to .joblib_tmp).

Examples:
  ./run_clustering.sh 250 10
  USE_CACHE=1 ./run_clustering.sh --use-cache
EOF
}

USE_CACHE="${USE_CACHE:-0}"
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

if [ ${#POSITIONAL_ARGS[@]} -ge 1 ]; then
    MAX_SCRIPTS="${POSITIONAL_ARGS[0]}"
else
    MAX_SCRIPTS=100
fi

if [ ${#POSITIONAL_ARGS[@]} -ge 2 ]; then
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
OUTPUT="$DEFAULT_OUTPUT"

echo "Configuration:"
echo "  Data directory: $DATA_DIR"
echo "  Max scripts: $MAX_SCRIPTS"
echo "  Min cluster size: $MIN_CLUSTER_SIZE"
if [ "$USE_CACHE" -eq 1 ]; then
    echo "  Cache mode: enabled (expecting $OUTPUT)"
else
    echo "  Cache mode: disabled"
fi
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

    python3 cluster_scripts.py \
        --data-dir "$DATA_DIR" \
        --max-scripts "$MAX_SCRIPTS" \
        --min-cluster-size "$MIN_CLUSTER_SIZE" \
        --output "$OUTPUT"

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

# Step 6: Generate text report
echo ""
echo "[6/7] Generating cluster report..."
REPORT_FILE="cluster_report.txt"
python3 generate_cluster_report.py \
    --results "$OUTPUT" \
    --data-dir "$DATA_DIR" \
    --output "$REPORT_FILE"
if [ $? -ne 0 ]; then
    echo "Failed to generate cluster report!"
    exit 1
fi
echo "[OK] Cluster report saved to: $REPORT_FILE"

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
