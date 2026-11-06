#!/usr/bin/env bash
# Collect everything for ONE cluster into <output-directory>:
#   kubescape.json, trivy.json, cluster_features.json, falco.log
#
# Usage: scripts/collect_cluster.sh <kube-context> <output-directory>
#
# The four collectors are independent, so they run concurrently. The script
# fails if any of them fails; the caller then discards the whole directory.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <kube-context> <output-directory> [namespace]" >&2
  exit 2
fi
CONTEXT="$1"
OUTPUT="$2"
NAMESPACE="${3:-security-demo}"
case "$OUTPUT" in /*) ;; *) OUTPUT="$PWD/$OUTPUT" ;; esac  # before lib.sh changes directory

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
require_tools kubectl kubescape trivy python3

mkdir -p "$OUTPUT"
pids=()

ns_arg_ks=()
ns_arg_trivy=()
if [ "$NAMESPACE" != "all" ] && [ -n "$NAMESPACE" ]; then
  ns_arg_ks=(--include-namespaces "$NAMESPACE")
  ns_arg_trivy=(--include-namespaces "$NAMESPACE")
fi

# The context is passed explicitly with --kube-context instead of mutating
# the shared kubeconfig current-context via `kubectl config use-context`, so
# several scans can safely run at the same time.
echo "Kubescape -> $CONTEXT (${NAMESPACE:-all})"
kubescape scan framework nsa \
  --kube-context "$CONTEXT" \
  --host-scan=false \
  ${ns_arg_ks[@]+"${ns_arg_ks[@]}"} \
  --format json \
  --format-version v2 \
  --output "$OUTPUT/kubescape.json" &
pids+=($!)

echo "Trivy -> $CONTEXT (${NAMESPACE:-all})"
trivy k8s \
  --timeout 15m \
  --skip-version-check \
  --scanners vuln,misconfig,secret \
  --disable-node-collector \
  ${ns_arg_trivy[@]+"${ns_arg_trivy[@]}"} \
  --report all \
  --format json \
  --output "$OUTPUT/trivy.json" \
  "$CONTEXT" &
pids+=($!)

python3 src/data/collect_cluster_features.py "$CONTEXT" > "$OUTPUT/cluster_features.json" &
pids+=($!)

python3 src/data/collect_falco.py "$CONTEXT" "$OUTPUT/falco.log" &
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
