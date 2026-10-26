#!/usr/bin/env bash
# Optional side-output generator.
# NOTE: This script is completely separate from the core pipeline (run.sh).
# Run this on-demand when you want visual executive artifacts:
#   ./scripts/generate_extra_artifacts.sh

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "=== GENERATING OPTIONAL SIDE-OUTPUT ARTIFACTS ==="

# 1. Interactive HTML Dashboard
echo "1. Generating Interactive HTML Dashboard..."
python3 src/generate_dashboard.py

# 2. Comparative Benchmark Plots
echo "2. Generating Comparative Benchmark Plot..."
python3 src/plot_benchmark.py

# 3. Auto-Remediation Example
echo "3. Generating Remediation Patch Example..."
python3 src/auto_remediate.py manifests/insecure/weak-deployment.yaml \
  --output data/processed/remediated-weak-deployment.yaml > /dev/null
echo "Remediated manifest saved to: data/processed/remediated-weak-deployment.yaml"

echo
echo "✓ All side-output artifacts generated successfully:"
echo "  - HTML Dashboard   : reports/dashboard.html"
echo "  - Benchmark Plot   : reports/model_benchmark_comparison.svg"
echo "  - Remediated Patch : data/processed/remediated-weak-deployment.yaml"
