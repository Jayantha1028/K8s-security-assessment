.PHONY: help manifests Manifests real Real live Live test Test report Report gate Gate chaos Chaos audit Audit pdf Pdf snowflake-full snowflake-update all All clean Clean clean-deep clean_deep deep-clean deep run-all run_all all-features

COUNT ?=
BATCH_SIZE ?=
SNAPSHOTS ?=
PAUSE ?=
SKIP_LIVE ?=
FRESH ?=

help:
	@echo "=========================================================================="
	@echo "          Kubernetes ML Security Assessment - Primary Commands            "
	@echo "=========================================================================="
	@echo "  make manifests [COUNT=N] [FRESH=1]        Generate & scan manifests and train"
	@echo "  make real                                 Process 200 real manifests & train 11 models"
	@echo "  make live [COUNT=N] [BATCH_SIZE=N]        Collect live telemetry & train models"
	@echo "  make test                                 Execute full test suite (48 unit tests)"
	@echo "  make report                               Display security & benchmark reports"
	@echo "  make gate                                 Execute Shift-Left CI/CD Security Gate"
	@echo "  make chaos                                Execute Security Chaos Engineering Resilience Suite"
	@echo "  make audit (or make pdf)                  Generate Executive Compliance Audit HTML & 9-Page PDF"
	@echo "  make snowflake-full                       Push all baseline tables & views to Snowflake once"
	@echo "  make snowflake-update                     Update only necessary dynamic data (Assessment & SHAP)"
	@echo "  make run-all (or make all-features)       Execute EVERY feature in the project at once (18 stages)"
	@echo "  make all [SNAPSHOTS=N] [PAUSE=N]          Run live-cluster Kind snapshots pipeline"
	@echo "  make clean                                Remove cache, bytecode, and temp logs"
	@echo "  make clean-deep (or make clean deep)      Remove all previous run scans, snapshots & models"
	@echo "=========================================================================="

manifests:
	@COUNT=$(COUNT) MANIFEST_COUNT=$(COUNT) ./run.sh --manifests $(if $(filter 1 true,$(FRESH)),--fresh,)
	@python3 src/train_security_models.py

Manifests: manifests

real:
	@./run.sh --real

Real: real

live:
	@COUNT=$(COUNT) BATCH_SIZE=$(BATCH_SIZE) SKIP_LIVE=$(SKIP_LIVE) ./run.sh --live $(if $(COUNT),--count $(COUNT),) $(if $(BATCH_SIZE),--batch-size $(BATCH_SIZE),) $(if $(filter 1 true,$(SKIP_LIVE)),--skip-live,)

Live: live

test:
	@./run.sh --test

Test: test

report:
	@./run.sh --report

Report: report

gate:
	@python3 src/ci_security_gate.py "manifests/**/*.yaml"

Gate: gate

chaos:
	@python3 src/security_chaos_testing.py

Chaos: chaos

audit:
	@python3 src/generate_executive_audit.py

Audit: audit
pdf: audit
Pdf: audit

snowflake-full:
	@python3 src/export_to_snowflake.py --full

snowflake-update:
	@python3 src/export_to_snowflake.py --incremental

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
