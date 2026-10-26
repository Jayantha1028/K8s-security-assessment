.PHONY: help test-cluster test_cluster report manifests train all test clean

CONTEXT ?= kind-ml-k8s-insecure
REPORT_INPUT ?= data/processed/report_input.csv
REPORT_FILE ?= reports/security_report.txt

help:
	@echo "Kubernetes ML Security Assessment - Makefile targets:"
	@echo "  make test-cluster [CONTEXT=<ctx>]  Scan a live cluster context and generate ML report"
	@echo "  make report                        Display the latest generated security report"
	@echo "  make train                         Train the Random Forest security models"
	@echo "  make manifests [COUNT=100]         Generate and scan sample manifests"
	@echo "  make final                         Run Kind clusters + latest assessment"
	@echo "  make all                           Run complete multi-scenario assessment pipeline"
	@echo "  make test                          Run all Python unit tests"

test-cluster:
	@echo "=== Scanning Live Cluster Context: $(CONTEXT) ==="
	@mkdir -p data/raw/latest/$(CONTEXT)
	@scripts/collect_cluster.sh $(CONTEXT) data/raw/latest/$(CONTEXT)
	@python3 src/build_cluster_dataset.py --report-input $(REPORT_INPUT)
	@python3 src/generate_report.py $(REPORT_INPUT) $(REPORT_FILE)
	@echo ""
	@echo "Report saved to: $(REPORT_FILE)"

test_cluster: test-cluster

report:
	@cat $(REPORT_FILE)

train:
	@python3 src/train_security_models.py

manifests:
	@MANIFEST_COUNT=$(COUNT) ./run.sh --manifests

final:
	@./run.sh --final

all:
	@./run.sh --all

test:
	@python3 -m unittest discover -s tests -v
