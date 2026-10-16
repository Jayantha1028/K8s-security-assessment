#!/usr/bin/env bash
# Switch the insecure cluster from the weak workload to the medium-risk one.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

echo "Applying medium-risk workload to $INSECURE_CTX"

kubectl --context "$INSECURE_CTX" delete deployment vulnerable-app \
  --ignore-not-found

kubectl --context "$INSECURE_CTX" apply -f "$MEDIUM_MANIFEST"

echo
echo "Take a new snapshot:"
echo "  scripts/take_snapshot.sh medium_01"
echo
echo "Restore the weak workload later with:"
echo "  kubectl --context $INSECURE_CTX apply -f $WEAK_MANIFEST"
