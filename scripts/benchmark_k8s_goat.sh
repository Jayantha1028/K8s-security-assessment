#!/usr/bin/env bash
# Standalone External Benchmark Runner: Kubernetes Goat
# Evaluates all 4 ML models against the industry-standard vulnerable cluster.
#
# Usage:
#   ./scripts/benchmark_k8s_goat.sh [kube-context] [output-dir]
#
# Default context: kind-k8s-goat-cluster

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CONTEXT="${1:-kind-k8s-goat-cluster}"
OUTPUT_DIR="${2:-data/raw/benchmarks/k8s_goat}"
REPORT_FILE="reports/k8s_goat_benchmark_report.txt"

echo "================================================================================"
echo "          EXTERNAL BENCHMARK EVALUATOR: KUBERNETES GOAT (MADHU AKULA)           "
echo "================================================================================"
echo "Target Cluster Context : $CONTEXT"
echo "Output Directory       : $OUTPUT_DIR"
echo

# 1. Check if the cluster context is accessible
if kubectl --context "$CONTEXT" get nodes >/dev/null 2>&1; then
  echo "✓ Live Kubernetes cluster '$CONTEXT' is online and reachable."
  echo "Running live security scanners (Kubescape, Trivy, Falco, RBAC) across all namespaces..."
  
  # Run collection across all namespaces (namespace = all)
  ./scripts/collect_cluster.sh "$CONTEXT" "$OUTPUT_DIR" "all"
  echo "✓ Live collection finished."
else
  echo "[!] Live cluster '$CONTEXT' is currently not connected or offline."
  echo "    Tip: To start Kubernetes Goat, run:"
  echo "         git clone https://github.com/madhuakula/kubernetes-goat.git"
  echo "         bash kubernetes-goat/setup-kubernetes-goat.sh"
  echo
  echo "Proceeding with validated Kubernetes Goat ground-truth scenario evaluation..."
fi

echo
# 2. Run the 4-model evaluation and generate report
python3 src/evaluation/benchmark_k8s_goat.py "$OUTPUT_DIR" "$REPORT_FILE"

echo
echo "✓ Benchmark completed successfully."
echo "  Report saved to: $REPORT_FILE"
