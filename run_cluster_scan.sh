#!/usr/bin/env bash
#
# Run scan_cluster.py for a cache key and emit the vulnerability report
# into samples/<cluster-key>/.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <cluster-key> [additional scan_cluster.py args...]" >&2
  exit 1
fi

cluster_key="$1"
shift

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${repo_root}"

sample_dir="samples/${cluster_key}"
mkdir -p "${sample_dir}"

csv_path="${sample_dir}/${cluster_key}_summary.csv"
text_report="${sample_dir}/cluster_summary_report.txt"
vuln_report="${sample_dir}/cluster_vulnerabilities.txt"

echo "Running scan_cluster.py for ${cluster_key}..."
python3 scan_cluster.py "${cluster_key}" \
  --output "${csv_path}" \
  --text-report "${text_report}" \
  "$@"

echo "Generating vulnerability summary..."
python3 generate_vulnerability_report.py \
  --csv "${csv_path}" \
  --output "${vuln_report}"

echo "Saved reports under ${sample_dir}"
