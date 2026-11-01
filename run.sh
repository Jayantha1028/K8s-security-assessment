#!/usr/bin/env bash
# Single entry point for the Kubernetes ML Security Assessment project.
#
#   ./run.sh --manifests   manifest pipeline & model training (needs Kubescape)
#   ./run.sh --real        200 real-world manifests & 11-model master matrix
#   ./run.sh --live        live cluster telemetry collection & model training
#   ./run.sh --test        execute test suite (48 unit tests)
#   ./run.sh --report      generate & display security assessment & benchmark reports
#   ./run.sh --run-all     execute every feature in the project at once (18 stages)
#   ./run.sh --all         run live-cluster Kind snapshots pipeline
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
  local count="${MANIFEST_COUNT:-${COUNT:-}}"
  local count_args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --fresh) fresh=1; shift ;;
      --count) count="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
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

cmd_real() {
  echo "=== REAL-WORLD WORKLOAD PIPELINE & 11-MODEL MATRIX ==="
  require_tools python3
  python3 "$ROOT/src/build_real_world_dataset.py"
  python3 "$ROOT/src/train_11_models.py"
}

cmd_live() {
  local count="${COUNT:-}"
  local batch_size="${BATCH_SIZE:-}"
  local skip_live="${SKIP_LIVE:-}"
  local fleet_mode=0
  local fleet_args=()

  local args=("$@")
  local i=0
  while [ $i -lt ${#args[@]} ]; do
    case "${args[$i]}" in
      --count)
        fleet_mode=1
        count="${args[$((i+1))]}"
        i=$((i+2))
        ;;
      --batch-size)
        fleet_mode=1
        batch_size="${args[$((i+1))]}"
        i=$((i+2))
        ;;
      --skip-live)
        fleet_mode=1
        skip_live=1
        i=$((i+1))
        ;;
      *)
        i=$((i+1))
        ;;
    esac
  done

  if [ -n "$count" ] || [ -n "$batch_size" ] || [ -n "$skip_live" ] || [ "$fleet_mode" -eq 1 ]; then
    echo "=== LIVE CLUSTER FLEET PIPELINE ==="
    require_tools python3 kubectl kubescape trivy
    [ -n "$count" ] && fleet_args+=(--count "$count")
    [ -n "$batch_size" ] && fleet_args+=(--batch-size "$batch_size")
    if [ "$skip_live" = "1" ] || [ "$skip_live" = "true" ]; then
      fleet_args+=(--skip-live)
    fi
    python3 "$ROOT/src/run_cluster_fleet.py" ${fleet_args[@]+"${fleet_args[@]}"}
    python3 "$ROOT/src/train_security_models.py"
  else
    cmd_final "$@"
  fi
}

cmd_report() {
  echo "=== SECURITY & ML BENCHMARK REPORTS ==="
  require_tools python3
  if [ -f "$ROOT/reports/11_model_comparison_report.txt" ]; then
    cat "$ROOT/reports/11_model_comparison_report.txt"
    echo ""
  fi
  if [ -f "$REPORT_INPUT" ] && [ -f "$MODEL_FILE" ]; then
    python3 "$ROOT/src/generate_report.py" "$REPORT_INPUT" "$REPORT_FILE"
  elif [ -f "$REPORT_FILE" ]; then
    cat "$REPORT_FILE"
  else
    echo "No cluster assessment report found. Run 'make live' or 'make all' first."
  fi
}

cmd_clean() {
  echo "Cleaning cache files and temporary logs..."
  find "$ROOT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  find "$ROOT" -type f -name "*.py[cod]" -delete 2>/dev/null || true
  find "$ROOT" -name ".DS_Store" -delete 2>/dev/null || true
  rm -rf "$ROOT/.pytest_cache" "$ROOT/.coverage" "$ROOT/htmlcov"
  rm -rf "$ROOT/logs"/*.log
  rm -rf "$ROOT/data/raw/.latest.tmp"
  echo "Clean completed."
}

cmd_clean_deep() {
  cmd_clean
  echo "Deep cleaning previous run data, scans, snapshots, and runtime models..."
  rm -rf "$ROOT/data/raw/manifest_scans"
  rm -rf "$ROOT/data/raw/samples/synthetic"
  rm -rf "$ROOT/data/raw/latest" "$ROOT/data/raw/snapshots" "$ROOT/data/raw/continuous_snapshots"
  rm -rf "$ROOT/models/security_models.joblib" "$ROOT/models/random_forest_model.joblib" "$ROOT/models/svm_model.joblib" "$ROOT/models/xgboost_model.joblib" "$ROOT/models/isolation_forest_model.joblib"
  rm -rf "$ROOT/logs"/*
  echo "Deep clean completed. Repository reset to clean baseline."
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
  cmd_real
}

main() {
  trap cleanup EXIT
  case "$MODE" in
    --manifests|--midsem)          shift || true; cmd_manifests "$@" ;;
    --real)                        cmd_real ;;
    --live|--final)                shift || true; cmd_live "$@" ;;
    --test)                        python3 -m unittest discover -s tests -v ;;
    --report)                      cmd_report ;;
    --all)                         cmd_all ;;
    --clean)                       cmd_clean ;;
    --clean-deep)                  cmd_clean_deep ;;
    --fleet|--pipeline)            shift || true; cmd_fleet "$@" ;;
    --compare-11|--train-11)       cmd_train_11 ;;
    --test-cluster|--test_cluster) shift || true; cmd_test_cluster "$@" ;;
    --run-all|--features)          shift || true; exec "$ROOT/run_all.sh" "$@" ;;
  esac
}

MODE="${1:---manifests}"
case "$MODE" in
  manifests|real|live|final|all|test|report|fleet|pipeline|clean|clean-deep|clean_deep|deep-clean|deep|run-all|features)
    case "$MODE" in
      clean_deep|deep-clean|deep) MODE="--clean-deep" ;;
      run-all|features) MODE="--run-all" ;;
      *) MODE="--$MODE" ;;
    esac
    ;;
esac

case "$MODE" in
  --manifests|--midsem|--real|--live|--final|--all|--test|--report|--clean|--clean-deep|--fleet|--pipeline|--compare-11|--train-11|--test-cluster|--test_cluster|--run-all|--features) ;;
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
