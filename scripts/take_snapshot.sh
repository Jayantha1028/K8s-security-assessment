#!/usr/bin/env bash
# Take one named assessment snapshot of both clusters.
#
# Usage: scripts/take_snapshot.sh [name]
#
# Environment:
#   BUILD_DATASET=0   do not rebuild the dataset afterwards (./run.sh --all uses
#                     this and rebuilds once at the end instead of after every
#                     snapshot - each rebuild re-reads every snapshot).
#   SNAPSHOT_ROOT     where to store snapshots (default data/raw/snapshots;
#                     continuous_assessment.sh points it elsewhere).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

NAME="${1:-snapshot_$(date +%Y%m%d_%H%M%S)}"

# The name becomes a directory and a dataset key, so keep it simple and
# safe. "latest" is reserved for the one-off ./run.sh --final collection.
if [[ ! "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "Invalid snapshot name: '$NAME'" >&2
  echo "Use letters, digits, '.', '_' or '-', starting with a letter/digit." >&2
  exit 2
fi
if [[ "$NAME" == "latest" ]]; then
  echo "'latest' is reserved for ./run.sh --final; choose another name." >&2
  exit 2
fi

require_tools kubectl kubescape trivy python3

SNAPSHOT_ROOT="${SNAPSHOT_ROOT:-$SNAPSHOTS_DIR}"
BUILD_DATASET="${BUILD_DATASET:-1}"
BASE="$SNAPSHOT_ROOT/$NAME"
TMP="$SNAPSHOT_ROOT/.tmp-$NAME"

# Collect into a hidden temp folder and move it into place only when BOTH
# clusters succeeded. A failed scan must never leave a half-written snapshot
# behind, because it would be read as "no findings" later.
rm -rf "$TMP"
mkdir -p "$SNAPSHOT_ROOT"
trap 'rm -rf "$TMP"' EXIT

if ! collect_environments "$TMP"; then
  echo "One or more cluster scans failed - snapshot '$NAME' was NOT saved." >&2
  exit 1
fi

if [ -d "$BASE" ]; then
  echo "Replacing existing snapshot: $NAME"
  rm -rf "$BASE"
fi
mv "$TMP" "$BASE"
echo
echo "Snapshot saved under $BASE"

if [ "$BUILD_DATASET" = "1" ]; then
  if ! python3 src/build_cluster_dataset.py; then
    echo "Dataset rebuild failed; snapshot kept under $BASE." >&2
    exit 1
  fi
  echo "Dataset updated: $CLUSTER_DATASET"
fi
