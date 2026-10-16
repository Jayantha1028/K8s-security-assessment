#!/usr/bin/env bash
# Collect everything for ONE cluster into <output-directory>:
#   kubescape.json, trivy.json, cluster_features.json, falco.log
#
# Usage: scripts/collect_cluster.sh <kube-context> <output-directory>
#
# The four collectors are independent, so they run concurrently. The script
# fails if any of them fails; the caller then discards the whole directory.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <kube-context> <output-directory>" >&2
  exit 2
fi
CONTEXT="$1"
OUTPUT="$2"
case "$OUTPUT" in /*) ;; *) OUTPUT="$PWD/$OUTPUT" ;; esac  # before lib.sh changes directory

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_tools kubectl kubescape trivy python3

mkdir -p "$OUTPUT"
pids=()

# The context is passed explicitly with --kube-context instead of mutating
# the shared kubeconfig current-context via `kubectl config use-context`, so
# several scans can safely run at the same time.
echo "Kubescape -> $CONTEXT"
kubescape scan framework nsa \
  --kube-context "$CONTEXT" \
  --include-namespaces security-demo \
  --format json \
  --format-version v2 \
  --output "$OUTPUT/kubescape.json" &
pids+=($!)

echo "Trivy -> $CONTEXT"
trivy k8s \
  --scanners vuln,misconfig,secret \
  --disable-node-collector \
  --include-namespaces security-demo \
  --report all \
  --format json \
  --output "$OUTPUT/trivy.json" \
  "$CONTEXT" &
pids+=($!)

python3 src/collect_cluster_features.py "$CONTEXT" > "$OUTPUT/cluster_features.json" &
pids+=($!)

python3 src/collect_falco.py "$CONTEXT" "$OUTPUT/falco.log" &
pids+=($!)

fail=0
for pid in "${pids[@]}"; do
  wait "$pid" || fail=1
done

if [ "$fail" -ne 0 ]; then
  echo "Collection failed for $CONTEXT" >&2
  exit 1
fi
echo "Collected $CONTEXT -> $OUTPUT"
