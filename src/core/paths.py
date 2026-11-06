"""Single source of truth for where the pipeline reads and writes files.

Everything is resolved relative to the project root (the parent of src/), so
the scripts behave the same no matter which directory they are started from.
scripts/lib.sh mirrors the data/ locations for the shell side.
"""

from pathlib import Path
import sys

# Ensure src/, core/, root, and all subpackages are importable from anywhere
CORE_DIR = Path(__file__).resolve().parent
SRC_DIR = CORE_DIR.parent
ROOT = SRC_DIR.parent

_DIRS_TO_ADD = [
    str(SRC_DIR),
    str(ROOT),
    str(CORE_DIR),
    str(SRC_DIR / "core"),
    str(SRC_DIR / "data"),
    str(SRC_DIR / "scanners"),
    str(SRC_DIR / "models"),
    str(SRC_DIR / "evaluation"),
    str(SRC_DIR / "reporting"),
    str(SRC_DIR / "integrations"),
]

for p in _DIRS_TO_ADD:
    if p not in sys.path:
        sys.path.insert(0, p)

# Raw inputs: generated manifests, scanner output, cluster collections.
# Regenerable, so data/raw/ is git-ignored.
RAW = ROOT / "data" / "raw"
SAMPLES = RAW / "samples"                      # generated manifests
MANIFEST_SCANS = RAW / "manifest_scans"        # one Kubescape JSON per manifest
LATEST = RAW / "latest"                        # one-off collection (./run.sh --final)
SNAPSHOTS = RAW / "snapshots"                  # named snapshots (take_snapshot.sh)
CONTINUOUS = RAW / "continuous_snapshots"      # periodic snapshots

# Processed datasets, trained model and report.
PROCESSED = ROOT / "data" / "processed"
MANIFEST_DATASET = PROCESSED / "kubernetes_security_dataset.csv"
CLUSTER_DATASET = PROCESSED / "final_security_dataset.csv"
REAL_WORLD_DATASET = PROCESSED / "real_world_security_dataset.csv"
COMBINED_DATASET = PROCESSED / "combined_security_dataset.csv"
REPORT_INPUT = PROCESSED / "report_input.csv"
MODEL_FILE = ROOT / "models" / "security_models.joblib"
MODELS_11_FILE = ROOT / "models" / "security_models_11.joblib"
RF_MODEL_FILE = ROOT / "models" / "random_forest_model.joblib"
SVM_MODEL_FILE = ROOT / "models" / "svm_model.joblib"
XGB_MODEL_FILE = ROOT / "models" / "xgboost_model.joblib"
ISO_MODEL_FILE = ROOT / "models" / "isolation_forest_model.joblib"
REPORT_FILE = ROOT / "reports" / "security_report.txt"

# Categorized reports subdirectories
REPORTS_DIR = ROOT / "reports"
REPORTS_AUDIT = REPORTS_DIR / "audit"
REPORTS_DASHBOARDS = REPORTS_DIR / "dashboards"
REPORTS_BENCHMARKS = REPORTS_DIR / "benchmarks"
REPORTS_SCANNER_COMP = REPORTS_DIR / "scanner_comparison"
REPORTS_CI_CD = REPORTS_DIR / "ci_cd"
REPORTS_SQL = REPORTS_DIR / "sql"
REPORTS_LOGS = REPORTS_DIR / "logs"
REPORTS_METRICS = REPORTS_DIR / "metrics"


def rel(path):
    """Project-relative path for friendlier log output."""
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)
