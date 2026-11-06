#!/usr/bin/env bash
# Optional side-output generator.
# NOTE: This script is completely separate from the core pipeline (run.sh).
# Run this on-demand when you want visual executive artifacts:
#   ./scripts/generate_extra_artifacts.sh

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "=== GENERATING OPTIONAL SIDE-OUTPUT ARTIFACTS ==="

# 1. Standard Text Security Report
echo "1. Generating Standard Assessment Report..."
python3 src/reporting/generate_report.py > /dev/null
echo "Assessment report saved to: reports/security_report.txt"

# 2. Interactive HTML Dashboard
echo "2. Generating Interactive HTML Dashboard..."
python3 src/reporting/generate_dashboard.py

# 3. Comparative Benchmark Plots
echo "3. Generating Comparative Benchmark Plot..."
python3 src/reporting/plot_benchmark.py

# 4. Auto-Remediation Example
echo "4. Generating Remediation Patch Example..."
python3 src/scanners/auto_remediate.py manifests/insecure/weak-deployment.yaml \
  --output data/processed/remediated-weak-deployment.yaml > /dev/null
echo "Remediated manifest saved to: data/processed/remediated-weak-deployment.yaml"

echo
echo "✓ All artifacts generated successfully at once:"
echo "  - Text Report      : reports/security_report.txt"
echo "  - HTML Dashboard   : reports/dashboard.html"
echo "  - Benchmark Plot   : reports/model_benchmark_comparison.svg"
echo "  - Remediated Patch : data/processed/remediated-weak-deployment.yaml"
