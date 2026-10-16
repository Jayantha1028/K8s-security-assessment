#!/usr/bin/env bash
# Take a snapshot every INTERVAL seconds until Ctrl+C.
#
# Usage: INTERVAL=300 scripts/continuous_assessment.sh
#
# Each round is a normal take_snapshot.sh run stored under
# data/raw/continuous_snapshots/<timestamp>; a failed round is skipped.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

INTERVAL="${INTERVAL:-300}"

if [[ ! "$INTERVAL" =~ ^[1-9][0-9]*$ ]]; then
  echo "INTERVAL must be a positive integer number of seconds (got '$INTERVAL')." >&2
  exit 2
fi

require_tools kubectl kubescape trivy python3

export SNAPSHOT_ROOT="$CONTINUOUS_DIR"
trap 'echo; echo "Stopped."; exit 130' INT TERM

echo "Continuous assessment interval: ${INTERVAL} seconds"
echo "Press Ctrl+C to stop"

while true; do
  TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
  if scripts/take_snapshot.sh "$TIMESTAMP"; then
    echo "Snapshot saved: $TIMESTAMP"
  else
    echo "Round $TIMESTAMP failed - skipping." >&2
  fi
  sleep "$INTERVAL"
done
