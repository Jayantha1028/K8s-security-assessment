# Shared helpers for every script in scripts/. Source it, do not execute it:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
#
# It moves to the project root, so relative paths below work from any
# starting directory. The data/ layout mirrors src/paths.py.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Kind clusters
SECURE_CLUSTER="ml-k8s-secure"
INSECURE_CLUSTER="ml-k8s-insecure"
SECURE_CTX="kind-$SECURE_CLUSTER"
INSECURE_CTX="kind-$INSECURE_CLUSTER"

# Manifests
MANIFEST_DIR="manifests"
WEAK_MANIFEST="$MANIFEST_DIR/insecure/weak-deployment.yaml"
MEDIUM_MANIFEST="$MANIFEST_DIR/insecure/medium-deployment.yaml"

# Data
RAW_DIR="data/raw"
LATEST_DIR="$RAW_DIR/latest"
SNAPSHOTS_DIR="$RAW_DIR/snapshots"
CONTINUOUS_DIR="$RAW_DIR/continuous_snapshots"
PROCESSED_DIR="data/processed"
CLUSTER_DATASET="$PROCESSED_DIR/final_security_dataset.csv"
REPORT_INPUT="$PROCESSED_DIR/report_input.csv"
REPORT_FILE="reports/security_report.txt"

# require_tools <tool>...: exit 127 with a clear message if any is missing.
require_tools() {
  local tool
  for tool in "$@"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "Required command not found on PATH: $tool" >&2
      exit 127
    fi
  done
}

# collect_environments <dir>: collect the secure and insecure clusters into
# <dir>/secure and <dir>/insecure. The two clusters are independent, so they
# run in parallel (roughly halving wall-clock time). Returns non-zero if
# either side failed; the caller decides what to discard.
collect_environments() {
  local dir="$1" fail=0 pid_secure pid_insecure
  mkdir -p "$dir/secure" "$dir/insecure"

  scripts/collect_cluster.sh "$SECURE_CTX" "$dir/secure" &
  pid_secure=$!
  scripts/collect_cluster.sh "$INSECURE_CTX" "$dir/insecure" &
  pid_insecure=$!

  wait "$pid_secure" || fail=1
  wait "$pid_insecure" || fail=1
  return "$fail"
}
