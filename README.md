# CDC-5: ML‑Based Kubernetes Security Assessment

**Purpose** – An end-to-end Kubernetes security assessment and machine-learning benchmarking platform. Generates 100 synthetic Kubernetes manifests, provisions Kind clusters, runs **Trivy**, **Falco**, and **Kubescape** scans with RBAC inspection, merges telemetry into unified datasets (34 columns: 32 core security indicators + 2 vulnerability categorizations), and trains & benchmarks **four independent machine learning models** (**Random Forest**, **Support Vector Machine**, **XGBoost**, and **Isolation Forest**).

---

## Architecture & Pipeline Flow

```mermaid
%%{init: {
  'theme': 'base',
  'themeVariables': {
    'background': '#FFFFFF',
    'primaryColor': '#FFFFFF',
    'primaryBorderColor': '#0F172A',
    'primaryTextColor': '#0F172A',
    'lineColor': '#2563EB',
    'fontFamily': 'Inter, system-ui, sans-serif',
    'fontSize': '14px'
  }
}}%%
flowchart LR
    A["100 Manifest Samples"] --> B["Static Scans<br/>(Kubescape & Trivy)"]
    B --> C["Kind Deployment<br/>(Batches of 5)"]
    C --> D["Runtime Telemetry<br/>(Falco & kubectl)"]
    D --> E["Data Cleaning<br/>(32 Indicators)"]
    E --> F["ML Models<br/>(RF, SVM, XGB, iForest)"]
    F --> G["Validation<br/>(K8s Goat)"]
    G --> H["Final Security Report"]

    style A fill:#FFFFFF,stroke:#0F172A,stroke-width:2px,color:#0F172A
    style B fill:#FFFFFF,stroke:#0F172A,stroke-width:2px,color:#0F172A
    style C fill:#FFFFFF,stroke:#0F172A,stroke-width:2px,color:#0F172A
    style D fill:#FFFFFF,stroke:#0F172A,stroke-width:2px,color:#0F172A
    style E fill:#FFFFFF,stroke:#0F172A,stroke-width:2px,color:#0F172A
    style F fill:#FFFFFF,stroke:#0F172A,stroke-width:2px,color:#0F172A
    style G fill:#FFFFFF,stroke:#0F172A,stroke-width:2px,color:#0F172A
    style H fill:#FFFFFF,stroke:#0F172A,stroke-width:2px,color:#0F172A
```

---

## Quick‑Start
```bash
# 1️⃣ Set up the Python environment
chmod +x run.sh scripts/*.sh
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2️⃣ Verify required tools (Docker, Kind, kubectl, Helm, Kubescape, Trivy)
for t in docker kind kubectl helm kubescape trivy; do command -v $t >/dev/null && echo "ok: $t" || echo "MISSING: $t"; done

# 3️⃣ Run the full pipeline
./run.sh --fleet --count 100 --batch-size 5   # Full 100-cluster assessment with live Kind & Falco probes
./run.sh --fleet --count 100 --skip-live       # Fast offline: 100 manifests + Kubescape/Trivy + ML training
./run.sh --manifests                          # Manifests only + Kubescape + dataset
./run.sh --all                                # Classic suite: dual clusters, snapshots, training, report
```

---

## Project Layout
```
.
├── run.sh                          # Master CLI entry point (--fleet | --manifests | --final | --all)
├── requirements.txt                # Pinned Python dependencies
├── src/                            # Pipeline source code
│   ├── paths.py                    # Centralized I/O paths
│   ├── run_cluster_fleet.py        # 100-cluster fleet orchestration & bounded batch deployment
│   ├── generate_samples.py         # Synthetic manifest generator (100 manifests across 3 profiles)
│   ├── scan_manifests.py           # Parallel Kubescape scanner for manifests (NSA/CISA framework)
│   ├── data_cleaning.py            # Robust cleaning (inf handling, outlier cap, case normalization)
│   ├── create_dataset.py           # Builds kubernetes_security_dataset.csv
│   ├── collect_cluster_features.py # Live cluster RBAC & workload configuration extractor
│   ├── collect_falco.py            # Runtime Falco alert collector
│   ├── build_cluster_dataset.py    # Merges scanner outputs into final_security_dataset.csv
│   ├── train_security_models.py    # Trains & benchmarks 4 models independently with zero leakage
│   ├── generate_report.py          # Executive multi-model CLI security report
│   ├── generate_dashboard.py       # (Side-output) Standalone interactive HTML dashboard
│   ├── plot_benchmark.py           # (Side-output) 4-panel SVG benchmark chart generator
│   └── auto_remediate.py           # (Side-output) Automated YAML manifest security hardening
├── scripts/                        # Automation & cluster scripts
│   ├── setup-kind-clusters.sh      # Provisions secure and insecure Kind clusters
│   ├── collect_cluster.sh          # Parallel Kubescape, Trivy, Falco, kubectl collector
│   ├── deploy_k8s_goat.sh          # Provisions Kubernetes Goat benchmark scenario cluster
│   ├── generate_extra_artifacts.sh # All-in-one runner for optional side outputs
│   └── lib.sh                      # Common shell library and paths
├── manifests/                      # Workload deployment templates
│   ├── secure/                     # Hardened workloads, default-deny network policy, RBAC
│   └── insecure/                   # Vulnerable and medium-risk workloads
├── models/                         # 4 Individually trained model files
│   ├── random_forest_model.joblib  # Supervised baseline classifier & regressor
│   ├── svm_model.joblib            # Support Vector Machine (kernel margin)
│   ├── xgboost_model.joblib        # Gradient boosted trees (lowest error)
│   ├── isolation_forest_model.joblib # Unsupervised zero-day anomaly detector
│   └── security_models.joblib      # Consolidated bundle for backward compatibility
├── reports/                        # Output reports and visual artifacts
│   ├── security_report.txt         # Terminal assessment report & comparison table
│   ├── dashboard.html              # Interactive HTML executive dashboard
│   └── model_benchmark_comparison.svg # Scalable vector benchmark graphic
├── docs/                           # Documentation
│   ├── SETUP.md                    # Environment installation guide
│   └── DETAILED_PROJECT_REPORT.md  # Comprehensive project report & benchmarks
└── tests/                          # 42 Unit & integration tests (no cluster required)
```

---

## Supported Machine Learning Models

Rather than ensembling into an opaque black-box, all 4 models are **trained and evaluated independently** to benchmark their distinct advantages:

| Model | Paradigm | Role & Benchmark Finding | Best For |
|---|---|---|---|
| **Random Forest** | Supervised Bagging | **Top Classifier:** 90.5% Accuracy, 0.883 Macro F1 | Robust baseline, stable feature importances |
| **SVM** | Kernel Margin | **Competitive Regression:** $R^2 = 0.952$, RMSE = 4.684 | High-dimensional decision boundaries |
| **XGBoost** | Gradient Boosting | **Top Regressor:** $R^2 = 0.959$, RMSE = 4.376 (Lowest Error) | Precise continuous security score prediction |
| **Isolation Forest** | Unsupervised Ensembling | **Anomaly Detection:** ROC-AUC = 0.975, 100% Outlier Recall | Catching novel/zero-day cluster drifts without labels |

---

## Data Cleaning & Feature Engineering

The pipeline processes **34 total columns** (32 core security indicators + 2 vulnerability breakdown columns) with strict production cleaning:
- **Infinite Value Replacement:** Bidirectional replacement of $\pm \infty$ with `np.nan` prior to numerical imputation.
- **String Sanitization:** Leading/trailing whitespace stripping and rejection of empty/whitespace-only keys.
- **Categorical Normalization:** Case standardization (`risk_level`: `Low`, `Medium`, `High`; `environment`: lowercase).
- **Outlier Protection:** Cap extreme spikes via `max_count_cap=100000`.
- **Zero-Variance Diagnostics:** Real-time logging of static features without dropping indicators unexpectedly.
- **Zero Data Leakage:** Numerical and categorical imputation statistics are fitted strictly on training folds.

---

## Optional Side-Output Artifacts (Visual & Remediation)

The core pipeline in `./run.sh` remains lightweight, fast, and terminal-friendly. If you want executive visual deliverables, run the dedicated side-output generator:

```bash
# Generate all visual & actionable side artifacts at once
./scripts/generate_extra_artifacts.sh
```

### What this produces:
1. **Interactive HTML Dashboard** (`reports/dashboard.html`): Open in any browser (`open reports/dashboard.html`) for interactive charts, posture gauges, and findings breakdown.
2. **Benchmark Graphic** (`reports/model_benchmark_comparison.svg`): 4-panel publication-ready comparison plot.
3. **Automated YAML Hardening** (`src/auto_remediate.py`):
   ```bash
   python3 src/auto_remediate.py manifests/insecure/weak-deployment.yaml
   ```
   Inspects insecure manifests, revokes container privileges, removes host namespaces, enforces `runAsNonRoot` & `RuntimeDefault` seccomp, drops all Linux capabilities, and outputs a colorized unified diff.

---

## Testing & Verification

All 42 unit and integration tests run entirely with mocks—**no live Kubernetes cluster is needed**:

```bash
# Run full test suite
python3 -m unittest discover -s tests -v

# Verify bash script syntax
for s in run.sh scripts/*.sh; do bash -n "$s" || exit 1; done
```

---

## Documentation
* [**SETUP.md**](docs/SETUP.md) – Detailed tool setup (Docker, Kind, Kubescape, Trivy, Falco).
* [**DETAILED_PROJECT_REPORT.md**](docs/DETAILED_PROJECT_REPORT.md) – Comprehensive architecture and mathematical formulation report.
* [**PRESENTATION_MASTER_GUIDE.md**](docs/PRESENTATION_MASTER_GUIDE.md) – Complete presentation guide, codebase walkthrough, slide-by-slide script, and defense Q&A.
