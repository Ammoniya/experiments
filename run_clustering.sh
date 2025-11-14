#!/bin/bash
# Quick start script for clustering JavaScript scripts

set -e

echo "========================================"
echo "JavaScript Script Clustering Pipeline"
echo "========================================"
echo ""

# Configuration
DATA_DIR="experiment_data"
MAX_SCRIPTS=${1:-100}  # Default to 100 scripts for quick test
MIN_CLUSTER_SIZE=${2:-5}   # Default to 5 as the minimum cluster size
OUTPUT="clustering_results.pkl"

# Step 1: Check dependencies
echo "[1/4] Checking dependencies..."
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
    print("✓ dtaidistance (fast DTW)")
else:
    print("⚠ dtaidistance not found, will use fastdtw (slower)")
    if has_module("fastdtw"):
        print("✓ fastdtw (fallback)")
    else:
        missing.append("dtaidistance OR fastdtw")

if has_module("umap"):
    print("✓ umap-learn (recommended)")
else:
    print("⚠ umap-learn not found, will use t-SNE (slower)")

if missing:
    print(f"\n❌ Missing dependencies: {', '.join(missing)}")
    print("Install with: pip install -r requirements.txt")
    sys.exit(1)
else:
    print("\n✓ All required dependencies installed")
EOF

if [ $? -ne 0 ]; then
    echo ""
    echo "Please install missing dependencies first:"
    echo "  pip install -r requirements.txt"
    exit 1
fi

# Step 2: Run clustering
echo ""
echo "[2/5] Running clustering pipeline..."
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
    echo "❌ Clustering failed!"
    exit 1
fi

# Step 3: Verify output
echo ""
echo "[3/5] Verifying output..."
if [ -f "$OUTPUT" ]; then
    echo "✓ Results saved to: $OUTPUT"
    SIZE=$(du -h "$OUTPUT" | cut -f1)
    echo "  File size: $SIZE"
else
    echo "❌ Output file not found!"
    exit 1
fi

# Step 4: Generate text report
echo ""
echo "[4/5] Generating cluster report..."
REPORT_FILE="cluster_report.txt"
python3 generate_cluster_report.py --results "$OUTPUT" --data-dir "$DATA_DIR" > "$REPORT_FILE"
if [ $? -ne 0 ]; then
    echo "❌ Failed to generate cluster report!"
    exit 1
fi
echo "✓ Cluster report saved to: $REPORT_FILE"

# Step 5: Launch visualization
echo ""
echo "[5/5] Launching interactive visualization..."
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
