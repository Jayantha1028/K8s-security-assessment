#!/usr/bin/env bash
# ==============================================================================
# run_all.sh - Execute Every Feature in the Kubernetes Security Assessment Project
# ==============================================================================
# Runs the complete end-to-end security pipeline, machine learning matrix,
# Bayesian engines, XAI explainability, auto-remediation, chaos engineering,
# executive PDF generation, and regression test suites with zero omissions.
#
# Usage:
#   ./run_all.sh                 Run all 18 features end-to-end
#   ./run_all.sh --skip-tests    Run all features except the 48-unit-test suite
#   ./run_all.sh --skip-snowflake Skip Snowflake cloud warehouse sync
#   ./run_all.sh --list          List all individual features
#   ./run_all.sh --only <step>   Run only a specific feature step
#   ./run_all.sh --help          Display this help message
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# ANSI Colors
BOLD="\033[1m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
MAGENTA="\033[1;35m"
DIM="\033[2m"
RESET="\033[0m"

# Options
SKIP_TESTS=0
SKIP_SNOWFLAKE=0
ONLY_FEATURE=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --skip-tests|--no-tests)
        SKIP_TESTS=1
        shift
        ;;
      --skip-snowflake|--no-snowflake)
        SKIP_SNOWFLAKE=1
        shift
        ;;
      --only)
        if [ -z "${2:-}" ]; then
          echo -e "${RED}Error: --only requires a feature name.${RESET}" >&2
          exit 1
        fi
        ONLY_FEATURE="$2"
        shift 2
        ;;
      --list)
        list_features
        exit 0
        ;;
      -h|--help)
        show_help
        exit 0
        ;;
      *)
        echo -e "${RED}Unknown option: $1${RESET}" >&2
        show_help
        exit 1
        ;;
    esac
  done
}

show_help() {
  echo -e "${BOLD}Kubernetes ML Security Assessment - Full Feature Runner${RESET}"
  echo ""
  echo "Usage: ./run_all.sh [options]"
  echo ""
  echo "Options:"
  echo "  --skip-tests       Skip Stage 17 (48-test unit & integration suite)"
  echo "  --skip-snowflake   Skip Stage 18 (Snowflake cloud data warehouse sync)"
  echo "  --only <feature>   Execute only a specific stage by ID or name"
  echo "  --list             List all 18 available features with descriptions"
  echo "  -h, --help         Show this help guide"
  echo ""
  echo "Examples:"
  echo "  ./run_all.sh                   # Complete end-to-end execution"
  echo "  ./run_all.sh --skip-tests      # Fast feature validation (~30s)"
  echo "  ./run_all.sh --only chaos      # Run Security Chaos Engineering only"
}

list_features() {
  echo -e "${BOLD}Available Features in Kubernetes Security Assessment Platform:${RESET}"
  echo "  1. audit-taxonomy       : 56-Vulnerability Taxonomy & 7-Plane Master Traceability Matrix"
  echo "  2. build-dataset        : 500-Workload Multi-Source Dataset Aggregation Pipeline"
  echo "  3. data-cleaning        : Dataset Integrity, Range Clamping & Duplicate Sanitization"
  echo "  4. train-11-models      : 11-Model Machine Learning Matrix & Dynamic Meta-Stacking"
  echo "  5. evaluate-model-rigor : 12-Gate Statistical & Clinical Accuracy Rigor Benchmark"
  echo "  6. bayesian-scoring     : Hierarchical Bayesian Engine & AHP Multi-Criteria Consistency"
  echo "  7. dual-mode-gmm        : Dual-Mode Gaussian Mixture Model Zero-Day Anomaly Detector"
  echo "  8. xai-threat-attribution: Explainable AI (TreeSHAP) Marginal Risk Waterfall Drivers"
  echo "  9. auto-remediation     : Automated Security Hardening Engine & Unified Patch Diff"
  echo " 10. ci-security-gate     : Shift-Left CI/CD Admission Gate & PR Markdown Linter"
  echo " 11. benchmark-k8s-goat   : External Ground-Truth Validation on Madhu Akula's K8s Goat"
  echo " 12. plot-benchmarks      : Publication-Grade Model Comparison Vector Charts (SVG & PNG)"
  echo " 13. generate-report      : Executive Multi-Cluster Security Report & ASCII Posture Meter"
  echo " 14. interactive-dashboard: Responsive Single-Page HTML Operations Dashboard"
  echo " 15. security-chaos-testing: Security Chaos Engineering (SCE 1-6 Resilience Suite)"
  echo " 16. executive-audit      : Enterprise Compliance Audit HTML & 9-Page High-Res Vector PDF"
  echo " 17. scanner-comparison   : Native Independent Scanner vs Kubescape vs Trivy Benchmark"
  echo " 18. prometheus-metrics   : Prometheus Telemetry, Model 12 Unsupervised Anomaly Inference & Exporter"
  echo " 19. test-suite           : Full 83-Test Verification, Rigor & Chaos Assertion Suite"
  echo " 20. snowflake-sync       : Enterprise Snowflake Cloud Data Warehouse Delta Export"
}

# Scorecard Tracker
declare -a STEP_NAMES=()
declare -a STEP_STATUS=()
declare -a STEP_DURATIONS=()

run_step() {
  local id="$1"
  local name="$2"
  local cmd="$3"
  local is_optional="${4:-0}"

  if [ -n "$ONLY_FEATURE" ]; then
    local id_l
    local name_l
    local only_l
    id_l="$(echo "$id" | tr '[:upper:]' '[:lower:]')"
    name_l="$(echo "$name" | tr '[:upper:]' '[:lower:]')"
    only_l="$(echo "$ONLY_FEATURE" | tr '[:upper:]' '[:lower:]')"
    if [[ "$id_l" != *"$only_l"* && "$name_l" != *"$only_l"* ]]; then
      return 0
    fi
  fi

  echo ""
  echo -e "${CYAN}================================================================================${RESET}"
  echo -e "${BOLD}${BLUE}▶ [STAGE: $id]${RESET} ${BOLD}$name${RESET}"
  echo -e "${DIM}  Command: $cmd${RESET}"
  echo -e "${CYAN}================================================================================${RESET}"

  local start_time
  start_time=$(python3 -c 'import time; print(time.time())')

  local exit_code=0
  eval "$cmd" || exit_code=$?

  local end_time
  end_time=$(python3 -c 'import time; print(time.time())')
  local duration
  duration=$(python3 -c "print(f'{$end_time - $start_time:.2f}s')")

  STEP_NAMES+=("$name")
  STEP_DURATIONS+=("$duration")

  if [ $exit_code -eq 0 ]; then
    echo -e "${GREEN}✓ [PASS] Stage completed successfully in $duration${RESET}"
    STEP_STATUS+=("PASS")
  else
    if [ "$is_optional" -eq 1 ]; then
      echo -e "${YELLOW}⚠ [SKIPPED / OPTIONAL] Stage bypassed cleanly (exit code $exit_code) in $duration${RESET}"
      STEP_STATUS+=("SKIPPED")
    else
      echo -e "${RED}✗ [FAIL] Stage failed with exit code $exit_code in $duration${RESET}"
      STEP_STATUS+=("FAIL")
      print_summary
      exit $exit_code
    fi
  fi
}

print_summary() {
  echo ""
  echo -e "${BOLD}${MAGENTA}================================================================================${RESET}"
  echo -e "${BOLD}${MAGENTA}             KUBERNETES SECURITY ASSESSMENT - FULL RUN SCORECARD                ${RESET}"
  echo -e "${BOLD}${MAGENTA}================================================================================${RESET}"
  printf "${BOLD}%-4s | %-52s | %-10s | %-8s${RESET}\n" "Step" "Feature Pipeline Stage" "Status" "Time"
  echo "--------------------------------------------------------------------------------"

  local total_pass=0
  local total_fail=0
  local total_skip=0

  for i in "${!STEP_NAMES[@]}"; do
    local s_num=$((i + 1))
    local s_name="${STEP_NAMES[$i]}"
    local s_stat="${STEP_STATUS[$i]}"
    local s_dur="${STEP_DURATIONS[$i]}"

    case "$s_stat" in
      PASS)
        printf "%-4s | %-52s | ${GREEN}%-10s${RESET} | %-8s\n" "$s_num" "$s_name" "✓ PASS" "$s_dur"
        total_pass=$((total_pass + 1))
        ;;
      FAIL)
        printf "%-4s | %-52s | ${RED}%-10s${RESET} | %-8s\n" "$s_num" "$s_name" "✗ FAIL" "$s_dur"
        total_fail=$((total_fail + 1))
        ;;
      SKIPPED)
        printf "%-4s | %-52s | ${YELLOW}%-10s${RESET} | %-8s\n" "$s_num" "$s_name" "⚠ SKIP" "$s_dur"
        total_skip=$((total_skip + 1))
        ;;
    esac
  done

  echo "--------------------------------------------------------------------------------"
  echo -e "Summary: ${GREEN}$total_pass Passed${RESET} | ${RED}$total_fail Failed${RESET} | ${YELLOW}$total_skip Skipped${RESET} across ${#STEP_NAMES[@]} evaluated stages."
  echo -e "${BOLD}${MAGENTA}================================================================================${RESET}"
}

main() {
  parse_args "$@"

  echo -e "${BOLD}${BLUE}"
  echo "██████╗ ██╗   ██╗███╗   ██╗     █████╗ ██╗     ██╗     "
  echo "██╔══██╗██║   ██║████╗  ██║    ██╔══██╗██║     ██║     "
  echo "██████╔╝██║   ██║██╔██╗ ██║    ███████║██║     ██║     "
  echo "██╔══██╗██║   ██║██║╚██╗██║    ██╔══██║██║     ██║     "
  echo "██║  ██║╚██████╔╝██║ ╚████║    ██║  ██║███████╗███████╗"
  echo "╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝╚══════╝╚══════╝"
  echo -e "${RESET}"
  echo -e "${BOLD}Kubernetes ML Security Assessment - Full Feature Orchestrator${RESET}"
  echo -e "${DIM}Working Directory: $ROOT_DIR${RESET}"
  echo -e "${DIM}Timestamp: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"

  local overall_start
  overall_start=$(python3 -c 'import time; print(time.time())')

  # 1. 56-Vulnerability Taxonomy & Audit
  run_step "01" "56-Vulnerability Taxonomy Audit" \
    "python3 src/scanners/audit_56_vulnerabilities.py"

  # 2. Build 500-Workload Dataset
  run_step "02" "500-Workload Dataset Aggregation" \
    "python3 src/data/build_real_world_dataset.py"

  # 3. Data Cleaning & Integrity Check
  run_step "03" "Dataset Cleaning & Schema Validation" \
    "python3 src/data/data_cleaning.py"

  # 4. Train 11 Models Matrix & Dynamic Stacker
  run_step "04" "11-Model Machine Learning Matrix" \
    "python3 src/models/train_11_models.py"

  # 5. 12-Gate Statistical & Clinical Accuracy Rigor Benchmark
  run_step "05" "12-Gate Statistical & Clinical Rigor Benchmark" \
    "python3 src/evaluation/evaluate_model_rigor.py"

  # 6. Bayesian Multi-Plane Threat Scoring Engine
  run_step "06" "Bayesian Threat Scoring & AHP Prior Engine" \
    "python3 src/models/bayesian_scoring_engine.py"

  # 7. Dual-Mode GMM Zero-Day Outlier Detector
  run_step "07" "Dual-Mode GMM Zero-Day Anomaly Detector" \
    "python3 src/models/dual_mode_gmm.py"

  # 8. Explainable AI (TreeSHAP) Threat Attribution
  run_step "08" "Explainable AI (TreeSHAP) Feature Attribution" \
    "python3 src/models/xai_threat_attribution.py"

  # 9. Automated Security Remediation Generator
  run_step "09" "Automated Security Remediation Engine" \
    "python3 src/scanners/auto_remediate.py manifests/insecure/weak-deployment.yaml --output manifests/remediated/weak-deployment-hardened.yaml"

  # 10. Shift-Left CI/CD Admission Gate
  run_step "10" "Shift-Left CI/CD Gate & PR Linter" \
    "python3 src/evaluation/ci_security_gate.py 'manifests/secure/*.yaml'"

  # 11. External Ground Truth (Kubernetes Goat Benchmark)
  run_step "11" "Kubernetes Goat Benchmark Validation" \
    "python3 src/evaluation/benchmark_k8s_goat.py"

  # 12. Publication-Grade Model Comparison Charts
  run_step "12" "Benchmark Charts Generator (SVG & PNG)" \
    "python3 src/reporting/plot_benchmark.py"

  # 13. Executive Multi-Cluster Security Report
  run_step "13" "Security Assessment Report & Posture Meter" \
    "python3 src/reporting/generate_report.py"

  # 14. Responsive Single-Page HTML Dashboard
  run_step "14" "Interactive Single-Page HTML Dashboard" \
    "python3 src/reporting/generate_dashboard.py"

  # 15. Security Chaos Engineering (SCE 1-6 Resilience Suite)
  run_step "15" "Security Chaos Engineering Resilience Suite" \
    "python3 src/evaluation/security_chaos_testing.py"

  # 16. Executive Compliance Audit & 9-Page Vector PDF Exporter
  run_step "16" "Executive Compliance Audit HTML & 9-Page PDF" \
    "python3 src/reporting/generate_executive_audit.py"

  # 17. Native Scanner vs Kubescape vs Trivy Benchmark
  run_step "17" "Native Security Scanner & Industry Comparator" \
    "python3 comparator/comparator_cli.py"

  # 18. Prometheus Runtime Telemetry, Model 12 Anomaly Inference & OpenMetrics Exporter
  run_step "18" "Prometheus Telemetry & Model 12 Anomaly Detector" \
    "python3 src/data/collect_prometheus.py --timeout 0.5 && python3 src/evaluation/evaluate_prometheus_anomalies.py && python3 src/integrations/prometheus_exporter.py --export-file"

  # 19. Full 83-Test Verification & Regression Suite
  if [ "$SKIP_TESTS" -eq 1 ]; then
    STEP_NAMES+=("Full 83-Test Verification Suite")
    STEP_DURATIONS+=("0.00s")
    STEP_STATUS+=("SKIPPED")
    echo -e "\n${YELLOW}ℹ [INFO] Skipping Stage 19 (--skip-tests specified).${RESET}"
  else
    run_step "19" "Full 73-Test Verification Suite" \
      "python3 -m unittest discover -s tests"
  fi

  # 20. Enterprise Snowflake Cloud Data Warehouse Sync
  if [ "$SKIP_SNOWFLAKE" -eq 1 ]; then
    STEP_NAMES+=("Snowflake Data Warehouse Delta Export")
    STEP_DURATIONS+=("0.00s")
    STEP_STATUS+=("SKIPPED")
    echo -e "\n${YELLOW}ℹ [INFO] Skipping Stage 20 (--skip-snowflake specified).${RESET}"
  else
    run_step "20" "Snowflake Data Warehouse Delta Export" \
      "python3 src/integrations/export_to_snowflake.py --incremental" 1
  fi

  local overall_end
  overall_end=$(python3 -c 'import time; print(time.time())')
  local total_elapsed
  total_elapsed=$(python3 -c "print(f'{$overall_end - $overall_start:.2f}s')")

  print_summary
  echo -e "\n${BOLD}${GREEN}🎉 ALL EVALUATED FEATURES EXECUTED SUCCESSFULLY IN $total_elapsed!${RESET}\n"
}

main "$@"
