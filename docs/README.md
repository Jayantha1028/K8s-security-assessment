# CDC-5: ML‑Based Kubernetes Security Assessment

**Purpose** – Generate 100 synthetic Kubernetes manifests, spin up up‑to‑100 Kind clusters in parallel, run **Trivy**, **Falco**, and **Kubescape** scans, merge the three reports into a unified CSV, and train four machine‑learning models (Random Forest, SVM, XGBoost, Isolation Forest).  The trained models are then applied to fresh test clusters and a comparative performance report is generated.

## Quick‑Start
```bash
# 1️⃣ Set up the Python environment (once)
chmod +x run.sh scripts/*.sh
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2️⃣ Install external scanners (see SETUP.md)
#    Kubescape, Trivy, Docker, Kind, kubectl, Helm

# 3️⃣ Run the full pipeline (creates 100 clusters in bounded parallel batches)
./run.sh --all   # equivalent to the steps below
```
*You can also run the steps individually (see **Step‑by‑step** section).*

## Project layout
```
.
├── run.sh                      # entry point (–manifests | –final | –all)
├── src/                        # Python code
│   ├── paths.py                # all I/O locations (single source of truth)
│   ├── k8s_features.py
│   ├── scan_parser.py
│   ├── data_cleaning.py
│   ├── generate_samples.py     # synthetic manifest generator (100 manifests)
│   ├── scan_manifests.py       # Kubescape on manifests
│   ├── collect_cluster_features.py
│   ├── collect_falco.py
│   ├── build_cluster_dataset.py
│   ├── train_security_models.py
│   └── generate_report.py
├── scripts/                    # Bash helpers
│   ├── setup-kind-clusters.sh
│   ├── apply_medium_scenario.sh
│   ├── collect_cluster.sh
│   ├── take_snapshot.sh
│   └── lib.sh
├── manifests/                  # example secure / insecure workloads
├── data/                       # generated data (git‑ignored)
│   ├── raw/                    # manifests, scanner JSON, Falco logs
│   └── processed/              # CSVs used for ML
├── models/                     # trained model file (joblib)
├── reports/                    # final human‑readable report
├── docs/                       # README.md, SETUP.md, PROJECT_REPORT.md
└── tests/                      # unit + integration tests (no cluster needed)
```

## Core pipeline (what `./run.sh --all` does)
1. **Manifest generation** – `src/generate_samples.py` creates 100 YAML files in `data/raw/samples/`.
2. **Parallel cluster creation** – `src/run_cluster_fleet.py` launches up to `--batch-size` clusters concurrently (default 5, configurable via `MAX_PARALLEL` env var).  The total target is 100 clusters (`--count`).
3. **Live scans** – for each cluster we run:
   * **Trivy** (image CVEs & misconfigurations)
   * **Falco** (runtime alerts, 5‑minute window)
   * **Kubescape** (policy compliance on the live cluster)
4. **Manifest‑only scan** – `src/scan_manifests.py` runs Kubescape on the generated manifests.
5. **Data merging** – `src/build_cluster_dataset.py` combines the three scanner outputs into a single row per cluster, adding the evidence score and the target label (high/medium/low risk).
6. **Feature extraction & cleaning** – `src/data_cleaning.py` removes NaNs, normalises numeric columns, and derives additional features (e.g., total CVEs, Falco alert count).
7. **Model training** – `src/train_security_models.py` fits four models:
   * Random Forest (`sklearn.ensemble.RandomForestClassifier`)
   * Support Vector Machine (`sklearn.svm.SVC`)
   * XGBoost (`xgboost.XGBClassifier`)
   * Isolation Forest (`sklearn.ensemble.IsolationForest` – unsupervised anomaly detector)
   Models are saved to `models/security_models.joblib`.
8. **Live‑test evaluation** – The same pipeline is executed on a fresh set of clusters; the trained models predict risk and a comparative table (accuracy, ROC‑AUC, precision, recall) is written to `reports/security_report.txt`.
9. **Report generation** – `src/generate_report.py` produces a human‑readable markdown report (`PROJECT_REPORT.md`).

## Supported models
| Model               | Type                | Primary use case |
|---------------------|---------------------|------------------|
| Random Forest       | Supervised classifier | Baseline, robust to noisy features |
| SVM                 | Supervised classifier | High‑dimensional feature spaces |
| XGBoost             | Gradient‑boosted tree | Often best predictive performance |
| Isolation Forest    | Unsupervised anomaly detector | Detect out‑of‑distribution clusters |

*All four models are trained together and benchmarked in the final report.*

## How to adjust parallelism
- The default parallel batch size is **5** (see `--batch-size` in `run_cluster_fleet.py`).
- Override with an environment variable, e.g.:
```bash
export MAX_PARALLEL=12
./run.sh --all
```
- **Caution** – increasing parallelism may exhaust CPU or memory on a modest laptop.  Monitor `top`/`htop` and adjust accordingly.

## Running only the manifest pipeline
If you want to skip the heavyweight cluster step, execute:
```bash
./run.sh --manifests   # generates manifests and runs Kubescape on them
```
The resulting CSV can still be used for model training (the cluster‑derived columns will be missing).

## Testing & verification
```bash
# Unit + integration tests (no real clusters needed)
python3 -m unittest discover -s tests -v

# Verify bash scripts syntax
for s in run.sh scripts/*.sh; do bash -n "$s" || exit 1; done
```
All tests must pass before committing changes.

## Documentation
- **SETUP.md** – detailed environment installation.
- **PROJECT_REPORT.md** – full end‑to‑end description, benchmark tables, and future work.

---
*For a deeper dive into the architecture, see the **Project Report** (`docs/PROJECT_REPORT.md`).*
