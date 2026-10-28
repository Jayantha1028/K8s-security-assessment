#!/usr/bin/env bash
# Single entry point for the whole project.
#
#   ./run.sh --manifests [--fresh]   manifest pipeline (needs only Kubescape)
#   ./run.sh --fleet [--count 100]   parallel fleet pipeline (100 YAMLs: Kubescape + Trivy + Kind/Falco)
#   ./run.sh --compare-11            train and benchmark all 11 models (Real, Synth, Consolidated, Master)
#   ./run.sh --final                 Kind clusters + latest assessment (+ training if enough data)
#   ./run.sh --all                   everything: clusters, snapshots, medium scenario, training, report
#
# Settings for --all (environment variables):
#   SNAPSHOTS  snapshots per scenario, minimum 5   (default 6)
#   PAUSE      seconds between snapshots           (default 30)
# Example: SNAPSHOTS=8 PAUSE=60 ./run.sh --all
#
# Every run is also saved to logs/<timestamp>_<mode>.log (command, start time,
# full output, exit status). The newest 30 logs are kept.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/scripts/lib.sh"

usage() { sed -n '2,11p' "$ROOT/run.sh" | sed 's/^# \{0,1\}//'; }

# State cleaned up on any exit (success, failure, Ctrl+C); the trap is set in
# main(), which runs inside the logged subshell below.
TMP_COLLECT=""
MEDIUM_APPLIED=0

restore_weak() {
  echo "Restoring the weak workload on $INSECURE_CTX"
  kubectl --context "$INSECURE_CTX" delete deployment medium-app \
    -n security-demo --ignore-not-found >/dev/null 2>&1 || true
  kubectl --context "$INSECURE_CTX" apply -f "$WEAK_MANIFEST" >/dev/null 2>&1 || true
}

cleanup() {
  if [ -n "$TMP_COLLECT" ]; then rm -rf "$TMP_COLLECT"; fi
  if [ "$MEDIUM_APPLIED" -eq 1 ]; then restore_weak; fi
}

# ---------------------------------------------------------------- manifests
# Generate manifests -> scan with Kubescape -> build kubernetes_security_dataset.csv
cmd_manifests() {
  local fresh=0
  [[ "${1:-}" == "--fresh" ]] && fresh=1
  local count="${MANIFEST_COUNT:-${COUNT:-}}"
  local count_args=()
  [ -n "$count" ] && count_args=(--count "$count")

  # Fail before generating anything if the scanner is missing.
  require_tools python3 kubescape

  echo "=== MANIFEST PIPELINE ==="

  if [ "$fresh" -eq 1 ]; then
    echo "Fresh run: clearing samples, scans and the existing dataset."
    rm -rf "$RAW_DIR/samples" "$RAW_DIR/manifest_scans"
    rm -f "$PROCESSED_DIR/kubernetes_security_dataset.csv"
    python3 src/generate_samples.py --fresh ${count_args[@]+"${count_args[@]}"}
  else
    echo "Incremental run: adding new samples on top of what's already on disk."
    echo "(use './run.sh --manifests --fresh' to start over instead)"
    python3 src/generate_samples.py ${count_args[@]+"${count_args[@]}"}
  fi

  python3 src/scan_manifests.py

  if [ "$fresh" -eq 1 ]; then
    python3 src/create_dataset.py --fresh
  else
    python3 src/create_dataset.py
  fi

  echo
  echo "Manifest pipeline completed."
  echo "Main output: $PROCESSED_DIR/kubernetes_security_dataset.csv"
}

# -------------------------------------------------------------------- final
# cmd_final [train]: set up both clusters, collect the "latest" assessment,
# build the dataset; with "train" (default) also train + report when >= 20 rows.
cmd_final() {
  local train="${1:-train}"

  echo "=== FINAL ML-BASED KUBERNETES SECURITY PIPELINE ==="
  echo "Prerequisites: Docker, kind, kubectl, Helm, Kubescape and Trivy."
  require_tools python3 docker kind kubectl helm kubescape trivy

  # Collected in a hidden temp folder and swapped into data/raw/latest only
  # after everything succeeded, so a failure never destroys the previous good
  # collection or leaves a partial one behind.
  TMP_COLLECT="$RAW_DIR/.latest.tmp"
  rm -rf "$TMP_COLLECT"

  scripts/setup-kind-clusters.sh

  if ! collect_environments "$TMP_COLLECT"; then
    echo "Collection failed - the previous 'latest' collection was kept." >&2
    exit 1
  fi

  rm -rf "$LATEST_DIR"
  mv "$TMP_COLLECT" "$LATEST_DIR"
  TMP_COLLECT=""
  rm -f "$REPORT_INPUT" "$REPORT_FILE"

  # Also writes the 'latest' rows (both environments) to $REPORT_INPUT, so the
  # report covers the assessment this run just collected.
  python3 src/build_cluster_dataset.py --report-input "$REPORT_INPUT"

  local rows=$(( $(wc -l < "$CLUSTER_DATASET") - 1 ))
  echo
  echo "Assessment rows collected: $rows"

  [ "$train" = "train" ] || return 0

  if [ "$rows" -lt 20 ]; then
    echo
    echo "ML training is intentionally not started yet."
    echo "The two clusters provide controlled validation data."
    echo "Collect diverse snapshots before training, for example:"
    echo
    echo "  scripts/take_snapshot.sh snapshot_01"
    echo "  scripts/take_snapshot.sh snapshot_02"
    echo "  ..."
    echo
    echo "At least 20 diverse assessment rows are recommended."
    echo "Once trained, generate the report with:"
    echo "  python3 src/generate_report.py"
    return 0
  fi

  python3 src/train_security_models.py
  python3 src/generate_report.py "$REPORT_INPUT"
  echo
  echo "╔════════════════════════════════════════════════════════════════════════════╗"
  echo "║                   LIVE CLUSTER SECURITY ASSESSMENT COMPLETE                ║"
  echo "╠════════════════════════════════════════════════════════════════════════════╣"
  echo "║  Trained Model : models/security_models.joblib                             ║"
  echo "║  Cluster Data  : $CLUSTER_DATASET                                          ║"
  echo "║  Audit Report  : $REPORT_FILE                                              ║"
  echo "║                                                                            ║"
  echo "║  View Report   : cat $REPORT_FILE                                          ║"
  echo "╚════════════════════════════════════════════════════════════════════════════╝"
  echo "Final pipeline completed."
}

# ---------------------------------------------------------------------- all
cmd_all() {
  local snapshots="${SNAPSHOTS:-6}" pause="${PAUSE:-30}" value

  for value in "$snapshots" "$pause"; do
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
      echo "SNAPSHOTS and PAUSE must be whole numbers (got '$value')." >&2
      exit 2
    fi
  done
  # Training needs 5 distinct snapshots in every risk class, and the medium
  # scenario only produces SNAPSHOTS of them - fewer would collect for tens of
  # minutes and then refuse to train.
  if [ "$snapshots" -lt 5 ]; then
    echo "SNAPSHOTS must be at least 5: training needs 5 distinct snapshots per risk class." >&2
    exit 2
  fi

  require_tools python3 docker kind kubectl helm kubescape trivy

  # Snapshots are taken without rebuilding the dataset each time (a rebuild
  # re-reads every snapshot, so doing it after each one is quadratic); it is
  # rebuilt once in step 5. A snapshot left by an interrupted run is picked
  # up by the next rebuild.
  take_series() {
    local prefix="$1" i name
    for i in $(seq 1 "$snapshots"); do
      name="$(printf '%s_%02d' "$prefix" "$i")"
      echo
      echo "=== Snapshot $name ($i/$snapshots) ==="
      BUILD_DATASET=0 scripts/take_snapshot.sh "$name"
      if [ "$i" -lt "$snapshots" ] && [ "$pause" -gt 0 ]; then sleep "$pause"; fi
    done
  }

  echo "=== Step 1/5: clusters + latest assessment ==="
  cmd_final no-train

  echo
  echo "=== Step 2/5: baseline snapshots ==="
  take_series auto_base

  echo
  echo "=== Step 3/5: security scenario snapshots ==="
  local scenarios_to_run="${SCENARIOS:-medium}"
  MEDIUM_APPLIED=1
  if [ "$scenarios_to_run" = "all" ]; then
    echo "Applying all 3 essential scenarios: medium, host_secrets, runtime_attack..."
    scripts/apply_medium_scenario.sh medium
    kubectl --context "$INSECURE_CTX" rollout status deployment/medium-app \
      -n security-demo --timeout=180s
    take_series auto_medium

    scripts/apply_medium_scenario.sh host_secrets
    kubectl --context "$INSECURE_CTX" rollout status deployment/medium-app \
      -n security-demo --timeout=180s
    take_series auto_secrets

    scripts/apply_medium_scenario.sh runtime_attack
    take_series auto_attack
  else
    scripts/apply_medium_scenario.sh "$scenarios_to_run"
    kubectl --context "$INSECURE_CTX" rollout status deployment/medium-app \
      -n security-demo --timeout=180s
    take_series "auto_${scenarios_to_run}"
  fi

  echo
  echo "=== Step 4/5: restoring weak workload ==="
  MEDIUM_APPLIED=0
  restore_weak

  echo
  echo "=== Step 5/5: dataset, training, report ==="
  python3 src/build_cluster_dataset.py --report-input "$REPORT_INPUT"

  # The trainer prints distinct snapshots per risk class before checking them.
  if ! python3 src/train_security_models.py; then
    echo >&2
    echo "Training did not run. The table above shows which risk class has too" >&2
    echo "few snapshots. Re-run with a larger SNAPSHOTS value, e.g.:" >&2
    echo "  SNAPSHOTS=10 ./run.sh --all" >&2
    exit 1
  fi

  python3 src/generate_report.py "$REPORT_INPUT"

  echo
  echo "╔════════════════════════════════════════════════════════════════════════════╗"
  echo "║                   LIVE CLUSTER SECURITY ASSESSMENT COMPLETE                ║"
  echo "╠════════════════════════════════════════════════════════════════════════════╣"
  echo "║  Evaluated     : Kind Clusters (Secure & Insecure Postures)                ║"
  echo "║  Telemetry     : Kubescape, Trivy, RBAC Graph & Falco eBPF                 ║"
  echo "║  Trained Model : models/security_models.joblib                             ║"
  echo "║  Dataset       : $CLUSTER_DATASET                                          ║"
  echo "║  Audit Report  : $REPORT_FILE                                              ║"
  echo "║                                                                            ║"
  echo "║  View Report   : cat $REPORT_FILE                                          ║"
  echo "╚════════════════════════════════════════════════════════════════════════════╝"
  echo "All done. Outputs: $CLUSTER_DATASET, models/security_models.joblib, $REPORT_FILE"
}

cmd_fleet() {
  echo "=== 100-CLUSTER PARALLEL FLEET PIPELINE ==="
  require_tools python3 kubectl kubescape trivy
  python3 src/run_cluster_fleet.py "$@"
}

cmd_test_cluster() {
  local ctx="${1:-${CONTEXT:-kind-ml-k8s-insecure}}"
  echo "=== Live Cluster Assessment: $ctx ==="
  require_tools python3 kubectl kubescape trivy
  local out_dir="$RAW_DIR/latest/$ctx"
  mkdir -p "$out_dir"
  scripts/collect_cluster.sh "$ctx" "$out_dir"
  python3 src/build_cluster_dataset.py --report-input "$REPORT_INPUT"
  python3 src/generate_report.py "$REPORT_INPUT" "$REPORT_FILE"
}

cmd_train_11() {
  echo "=== 11-MODEL TRAINING & BENCHMARK MATRIX ==="
  require_tools python3
  python3 "$ROOT/src/build_real_world_dataset.py"
  python3 "$ROOT/src/train_11_models.py"
}

main() {
  trap cleanup EXIT
  case "$MODE" in
    --manifests|--midsem)          shift || true; cmd_manifests "$@" ;;
    --fleet|--pipeline)            shift || true; cmd_fleet "$@" ;;
    --compare-11|--train-11)       cmd_train_11 ;;
    --final)                       cmd_final ;;
    --all)                         cmd_all ;;
    --test-cluster|--test_cluster) shift || true; cmd_test_cluster "$@" ;;
  esac
}

MODE="${1:---manifests}"
case "$MODE" in
  --manifests|--midsem|--fleet|--pipeline|--compare-11|--train-11|--final|--all|--test-cluster|--test_cluster) ;;
  -h|--help) usage; exit 0 ;;
  *)
    echo "Unknown option: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac

# ------------------------------------------------------------------ logging
# Output goes to the terminal AND logs/<timestamp>_<mode>.log. `tee -i` keeps
# the log complete when you press Ctrl+C; the exit status is recorded last.
LOG_DIR="logs"
LOG_FILE="$LOG_DIR/$(date +%Y%m%d_%H%M%S)_${MODE#--}.log"
mkdir -p "$LOG_DIR"

# A failing run must still reach the log-saved/pruning steps below.
set +e

# stdout and stderr each go through their own tee, so errors still reach the
# terminal's stderr while both streams are captured in the log.
{
  {
    echo "# ./run.sh $* | started $(date '+%Y-%m-%d %H:%M:%S')"
    set +e
    ( set -e; main "$@" )
    rc=$?
    echo
    echo "# finished $(date '+%Y-%m-%d %H:%M:%S') | exit status $rc"
    exit "$rc"
  } 2>&1 1>&3 | tee -a -i "$LOG_FILE" >&2
} 3>&1 | tee -a -i "$LOG_FILE"
status=${PIPESTATUS[0]}

# Keep only the newest 30 logs.
ls -1t "$LOG_DIR"/*.log 2>/dev/null | tail -n +31 | xargs rm -f
echo "Log saved: $LOG_FILE"
exit "$status"
