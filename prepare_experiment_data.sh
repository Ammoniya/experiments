#!/bin/bash
# Helper script to prepare experiment_data artifacts before clustering.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

STEPS=(
    "compute_statistics.py"
    "copy_vt_reports.py"
    "process_traces.py"
    "analyze_traces.py"
    "compute_ast_fingerprints.py"
)

echo "========================================"
echo "Experiment Data Preparation Pipeline"
echo "========================================"
echo ""

TOTAL=${#STEPS[@]}

for idx in "${!STEPS[@]}"; do
    STEP_NUM=$((idx + 1))
    SCRIPT_NAME="${STEPS[$idx]}"

    echo "[${STEP_NUM}/${TOTAL}] Running ${SCRIPT_NAME}..."
    if python3 "$SCRIPT_NAME"; then
        echo "[OK] ${SCRIPT_NAME} completed."
    else
        echo "[ERROR] ${SCRIPT_NAME} failed. Aborting preparation."
        exit 1
    fi
    echo ""
done

echo "All experiment data preparation steps completed successfully."
