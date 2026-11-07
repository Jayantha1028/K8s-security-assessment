.PHONY: help manifests Manifests real Real live Live test Test report Report gate Gate chaos Chaos audit Audit pdf Pdf snowflake-full snowflake-update prometheus-collect prometheus-export prometheus-serve train-prometheus-model eval-prometheus-model prometheus-daemon ebpf-monitor gitops-remediate Gitops-Remediate scan-native scan-cluster Scan-Cluster scan-layers admission-webhook admission-certs all All clean Clean clean-deep clean_deep deep-clean deep run-all run_all all-features finetune Finetune rigor Rigor Compare-Scanners

COUNT ?=
BATCH_SIZE ?=
SNAPSHOTS ?=
PAUSE ?=
SKIP_LIVE ?=
FRESH ?=
TREES ?= 20
LR ?= 0.02
SCAN_PATH ?= manifests/

help:
	@echo "=========================================================================="
	@echo "          Kubernetes ML Security Assessment - Primary Commands            "
	@echo "=========================================================================="
	@echo "  make manifests [COUNT=N] [FRESH=1]        Generate & scan manifests and train"
	@echo "  make real                                 Process 200 real manifests & train 11 models"
	@echo "  make live [COUNT=N] [BATCH_SIZE=N]        Collect live telemetry & train models"
	@echo "  make scan-native [SCAN_PATH=path]         Execute pure-Python zero-dependency AST security scanner"
	@echo "  make scan-cluster [NS=name]               Live in-cluster CSPM audit of active workloads"
	@echo "  make scan-layers [IMAGE=name] [TAR=path]  Deep container layer & OS package SBOM scan"
	@echo "  make compare-scanners                     Execute empirical side-by-side benchmark: Native vs Kubescape vs Trivy"
	@echo "  make finetune [TREES=N] [LR=N]            Incremental warm-start fine-tuning of Model 11"
	@echo "  make rigor                                Execute 12-Gate Statistical & Clinical Accuracy Rigor Benchmark"
	@echo "  make test                                 Execute full test suite (67 unit, rigor, scanner & benchmark tests)"
	@echo "  make report                               Display security & benchmark reports"
	@echo "  make gate                                 Execute Shift-Left CI/CD Security Gate"
	@echo "  make chaos                                Execute Security Chaos Engineering Resilience Suite"
	@echo "  make audit (or make pdf)                  Generate Executive Compliance Audit HTML & 9-Page PDF"
	@echo "  make prometheus-collect                   Collect runtime telemetry from Prometheus (or mock fallback)"
	@echo "  make train-prometheus-model               Train Model 12 Unsupervised Prometheus Anomaly Detector"
	@echo "  make eval-prometheus-model                Evaluate live Prometheus telemetry with Model 12"
	@echo "  make prometheus-daemon [INTERVAL=15]      Run continuous Prometheus anomaly daemon with online learning"
	@echo "  make ebpf-monitor                         Sub-second kernel syscall defense & auto-quarantine"
	@echo "  make prometheus-export                    Export security assessment scores to OpenMetrics format"
	@echo "  make prometheus-serve [PORT=9108]         Serve live /metrics Prometheus endpoint"
	@echo "  make snowflake-full                       Push all baseline tables & views to Snowflake once"
	@echo "  make snowflake-update                     Update only necessary dynamic data (Assessment & SHAP)"
	@echo "  make run-all (or make all-features)       Execute EVERY feature in the project at once (20 stages)"
	@echo "  make all [SNAPSHOTS=N] [PAUSE=N]          Run live-cluster Kind snapshots pipeline"
	@echo "  make clean                                Remove cache, bytecode, and temp logs"
	@echo "  make clean-deep (or make clean deep)      Remove all previous run scans, snapshots & models"
	@echo "=========================================================================="

manifests:
	@COUNT=$(COUNT) MANIFEST_COUNT=$(COUNT) ./run.sh --manifests $(if $(filter 1 true,$(FRESH)),--fresh,)
	@python3 src/models/train_11_models.py

Manifests: manifests

real:
	@./run.sh --real

Real: real

live:
	@COUNT=$(COUNT) BATCH_SIZE=$(BATCH_SIZE) SKIP_LIVE=$(SKIP_LIVE) ./run.sh --live $(if $(COUNT),--count $(COUNT),) $(if $(BATCH_SIZE),--batch-size $(BATCH_SIZE),) $(if $(filter 1 true,$(SKIP_LIVE)),--skip-live,)

Live: live

finetune:
	@python3 src/models/finetune_models.py --incremental-trees $(TREES) --finetune-lr $(LR)

Finetune: finetune

test:
	@./run.sh --test

Test: test

report:
	@./run.sh --report

Report: report

gate:
	@python3 src/evaluation/ci_security_gate.py "manifests/**/*.yaml"

Gate: gate

scan-native:
	@python3 src/scanners/native_security_scanner.py $(SCAN_PATH)

Scan-Native: scan-native

scan-cluster:
	@python3 src/scanners/cluster_scanner.py $(if $(NS),-n $(NS),) $(if $(REMEDIATE_OUT),--remediate-out $(REMEDIATE_OUT),)

Scan-Cluster: scan-cluster

OVERLAY_DIR ?=
PR_MD ?=

gitops-remediate:
	@python3 src/integrations/gitops_remediator.py $(if $(SCAN_PATH),$(SCAN_PATH),manifests/) $(if $(OVERLAY_DIR),--output-overlay $(OVERLAY_DIR),) $(if $(PR_MD),--output-pr-markdown $(PR_MD),)

Gitops-Remediate: gitops-remediate

IMAGE ?= nginx:1.14.2
TAR ?=

scan-layers:
	@python3 src/scanners/container_layer_scanner.py $(if $(TAR),--tarball $(TAR),--image $(IMAGE))

Scan-Layers: scan-layers

compare-scanners:
	@python3 comparator/comparator_cli.py

Compare-Scanners: compare-scanners

rigor:
	@python3 src/evaluation/evaluate_model_rigor.py

Rigor: rigor

chaos:
	@python3 src/evaluation/security_chaos_testing.py

Chaos: chaos

audit:
	@python3 src/reporting/generate_executive_audit.py

Audit: audit
pdf: audit
Pdf: audit

PORT ?= 9108
PROMETHEUS_URL ?= http://localhost:9090

prometheus-collect:
	@python3 src/data/collect_prometheus.py --url $(PROMETHEUS_URL)

train-prometheus-model:
	@python3 src/models/train_prometheus_anomaly_model.py

eval-prometheus-model:
	@python3 src/evaluation/evaluate_prometheus_anomalies.py

prometheus-export:
	@python3 src/integrations/prometheus_exporter.py --export-file

prometheus-serve:
	@python3 src/integrations/prometheus_exporter.py --serve --port $(PORT)

INTERVAL ?= 15

prometheus-daemon:
	@python3 src/integrations/run_prometheus_daemon.py --interval $(INTERVAL) --port $(PORT) --url $(PROMETHEUS_URL)

ebpf-monitor:
	@python3 src/integrations/ebpf_runtime_monitor.py

admission-webhook:
	@python3 src/integrations/admission_webhook.py --port $(PORT)

admission-certs:
	@./deploy/admission-controller/generate_certs.sh

snowflake-full:
	@python3 src/integrations/export_to_snowflake.py --full

snowflake-update:
	@python3 src/integrations/export_to_snowflake.py --incremental

run-all:
	@./run_all.sh

run_all: run-all
all-features: run-all

all:
	@SNAPSHOTS=$(SNAPSHOTS) PAUSE=$(PAUSE) ./run.sh --all

All: all

clean:
	@./run.sh --clean

Clean: clean

clean-deep:
	@./run.sh --clean-deep

clean_deep: clean-deep
deep-clean: clean-deep
deep: clean-deep
