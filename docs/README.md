# CDC-5: ML-Based Kubernetes Security Assessment

CDC-5 evaluates Kubernetes workload security using manifest analysis and,
optionally, two local Kind clusters. The lightweight pipeline builds a CSV from
generated YAML manifests. The cluster-backed pipeline collects Kubescape, Trivy,
Falco and Kubernetes configuration evidence, creates an evidence score and (only
when enough diverse observations exist) trains ML models.

Install steps, prerequisites and troubleshooting: [SETUP.md](SETUP.md).

## Project layout

```
.
├── run.sh                  the single entry point (--manifests | --final | --all)
├── src/                    Python: feature extraction, scanning, datasets, training, reporting
│   ├── paths.py            where every input/output lives (single source of truth)
│   ├── k8s_features.py  scan_parser.py  data_cleaning.py      shared logic
│   ├── generate_samples.py  scan_manifests.py  create_dataset.py        manifest pipeline
│   ├── collect_cluster_features.py  collect_falco.py  build_cluster_dataset.py   cluster pipeline
│   └── train_security_models.py  generate_report.py            ML + report
├── scripts/                Bash: runnable pipelines and cluster operations
│   ├── setup-kind-clusters.sh  take_snapshot.sh  continuous_assessment.sh
│   ├── apply_medium_scenario.sh  collect_cluster.sh   helpers called by run.sh
│   └── lib.sh              shared helpers (sourced, not run)
├── manifests/
│   ├── secure/             hardened deployment, RBAC, NetworkPolicy
│   └── insecure/           weak + medium deployments, over-privileged RBAC
├── logs/                   one log per ./run.sh run (git-ignored, newest 30 kept)
├── data/
│   ├── raw/                generated manifests, scans, cluster collections (git-ignored)
│   └── processed/          kubernetes_security_dataset.csv, final_security_dataset.csv, report_input.csv
├── models/                 security_models.joblib
├── reports/                security_report.txt
├── docs/                   README.md, SETUP.md
└── tests/                  unit + integration tests (no cluster needed)
```

Every `./run.sh` run is also saved to `logs/<timestamp>_<mode>.log`: the command,
start time, full output and exit status, so you can see what happened in an
earlier run. (`scripts/take_snapshot.sh` and the other helpers, when run on their
own, only print to the terminal.)

Everything in `data/raw/` is regenerable. All scripts move to the project root
themselves, so they can be started from any directory.

## 1. Lightweight manifest pipeline (recommended first)

Requirements: Python 3.10+, the packages in `requirements.txt`, and the Kubescape
CLI on `PATH`.

```bash
chmod +x run.sh scripts/*.sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./run.sh --manifests --fresh
```

Run `./run.sh --manifests` again to add another generated batch
to the existing dataset. Use `--fresh` only to delete the generated
`data/raw/samples/`, `data/raw/manifest_scans/` and
`data/processed/kubernetes_security_dataset.csv` and start over. (`--midsem` is
still accepted as an alias for `--manifests`.)

The output is `data/processed/kubernetes_security_dataset.csv`. Kubescape is a
required external scanner; the pipeline fails early with a clear message if it
is missing.

## 2. Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
for script in run.sh scripts/*.sh; do bash -n "$script" || exit 1; done
```

`tests/test_project.py` holds unit tests. `tests/test_pipeline.py` runs the real
scripts against fake `kubectl`, `kubescape`, `trivy`, `kind` and `helm` commands
and covers failure paths, atomic snapshots, incomplete-data handling, training
and reporting. They do not validate compatibility with real scanner releases or
actual cluster behaviour.

## 3. Cluster-backed assessment

**Fully automated (recommended):**

```bash
./run.sh --all                              # everything, one command
SNAPSHOTS=8 PAUSE=60 ./run.sh --all         # more/longer collection
```

This creates the clusters, takes the latest assessment, takes baseline
snapshots, applies the medium scenario (the weak workload is always restored
afterwards, even on failure or Ctrl+C), then builds the dataset once, trains and
writes the report. Snapshots of unchanged clusters are near-identical apart from
Falco alerts, so treat the resulting metrics as a pipeline demonstration.

Requirements: Docker, Kind, kubectl, Helm, Kubescape and Trivy usable from the
same shell. This mode creates or reuses two Kind clusters named
`ml-k8s-secure` and `ml-k8s-insecure`, applies the demo workloads and installs
Falco. The insecure cluster is intentionally insecure: use a throwaway machine.

**Step by step:**

```bash
./run.sh --final                          # clusters + first assessment
scripts/take_snapshot.sh snapshot_01      # repeat with unique names
scripts/apply_medium_scenario.sh
scripts/take_snapshot.sh medium_01
INTERVAL=300 scripts/continuous_assessment.sh   # optional, Ctrl+C to stop
python3 src/train_security_models.py
python3 src/generate_report.py            # defaults to data/processed/report_input.csv
```

Snapshot names may contain letters, digits, `.`, `_` and `-`; `latest` is
reserved for `run.sh --final`. A snapshot is collected in a hidden temporary
folder and only saved if both clusters were scanned successfully, so a failed run
never leaves partial data behind. Collect at least 20 rows and, for the grouped
five-fold evaluation, at least five distinct snapshots in each risk class before
training.

`report_input.csv` holds the `latest` assessment of both environments. To report
on other rows, pass any CSV with the model's feature columns:
`python3 src/generate_report.py my_rows.csv [output.txt]`.

Outputs: `data/processed/final_security_dataset.csv`,
`models/security_models.joblib`, `reports/security_report.txt`.

> **Back up before rebuilding.** `build_cluster_dataset.py` regenerates
> `final_security_dataset.csv` from the folders under `data/raw/`. If you keep a
> dataset whose raw snapshots are no longer on disk, fold it back in with
> `python3 src/build_cluster_dataset.py --merge data/processed/old_dataset.csv`.

## Scoring methodology

The evidence score starts at 100 and applies penalties for Kubescape compliance
gaps and high/critical findings, Trivy vulnerabilities and misconfigurations,
secrets, RBAC/service-account risks, risky capabilities, HostPath, missing
NetworkPolicies, root execution, privileged containers, HostPort and Falco
alerts. It is bounded to 0-100. Project-defined risk bands are High (0-39),
Medium (40-69) and Low (70-100); these are not universal Kubernetes standards.
The ML prediction is separate from the evidence score, and `security_score` is
not used as an input feature. The penalty weights live in `score_row()` in
`src/build_cluster_dataset.py`.

## Important limitations

- A passing local test suite is not proof that current versions of Kubescape,
  Trivy, the Falco Helm chart and Kind work together. Validate the cluster
  pipeline on the target machine.
- A collection folder missing a scanner report (`kubescape.json`, `trivy.json`,
  `cluster_features.json`, `falco.log`) or with unreadable JSON is skipped with a
  warning, never scored as zero findings. Read the warnings and re-run any
  skipped snapshot.
- The Kubescape parser understands the two JSON v2 layouts it was written
  against. Check parsed counts against a real report from your installed version.
- Synthetic manifests are useful for pipeline development, not a substitute for
  diverse real-world data. Metrics from small or synthetic datasets are not
  evidence of production accuracy.
- `security_score` is a transparent heuristic, not a compliance certification.
  ML predictions are trained against that heuristic and inherit its assumptions.
- Do not run the intentionally weak manifests or cluster on production
  infrastructure.

## Design and operational notes

- Evaluation keeps rows from the same snapshot together (grouped, stratified
  five-fold). Evidence covers Kubescape, Trivy, Kubernetes configuration, RBAC
  and Falco indicators.
- The synthetic generator varies workload features within hardened, medium and
  weak risk bands instead of repeating three fixed vectors. It uses a fresh seed
  by default (`--seed` makes a run reproducible) and adds numbered manifests;
  the dataset step merges new rows unless `--fresh` is used.
- RBAC risk is based on permissions bound to application service accounts;
  common system/Falco accounts are excluded. Falco collection uses a 5-minute
  event window; no alerts in that window does not prove runtime safety.
- The pipeline checks scanner prerequisites, rejects invalid worker counts and
  duplicate manifest stems, handles multi-document YAML and ephemeral
  containers, and validates report inputs and model features.
- Reusing a snapshot name replaces that snapshot in the dataset; use unique names
  for history.
- Run the cluster workflow only on a disposable local Kind setup.
