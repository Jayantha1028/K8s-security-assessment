import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    mean_absolute_error,
    mean_squared_error,
    r2_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC, SVR
import xgboost as xgb

import paths
from xgb_wrapper import XGBoostSecurityClassifier

DATASET = paths.CLUSTER_DATASET
MODEL_FILE = paths.MODEL_FILE

FEATURES = [
    "kubescape_failed",
    "kubescape_critical",
    "kubescape_high",
    "critical_cve_count",
    "high_cve_count",
    "critical_misconfig_count",
    "high_misconfig_count",
    "secret_count",
    "rbac_risk_score",
    "service_account_permission_score",
    "risky_capability_count",
    "host_path_count",
    "missing_network_policies",
    "root_execution_count",
    "falco_alert_count",
    "privileged_count",
    "host_port_count",
]


if not DATASET.is_file():
    raise SystemExit(
        f"Dataset not found: {paths.rel(DATASET)}. "
        "Run ./run.sh --final and take some snapshots first."
    )

df = pd.read_csv(DATASET)

# If manifest scans exist and are not yet in df, fold them in for training
if paths.MANIFEST_DATASET.is_file() and not (df["environment"] == "manifest").any():
    from build_cluster_dataset import load_manifest_assessments
    m_rows = load_manifest_assessments()
    if m_rows:
        print(f"Folding in {len(m_rows)} scanned workload manifests into training...")
        df = pd.concat([df, pd.DataFrame(m_rows)], ignore_index=True)

print("Rows:", len(df))
print("Assessment snapshots:", df["snapshot"].nunique())

if len(df) < 20:
    raise SystemExit(
        "Collect at least 20 diverse assessment snapshots before ML training."
    )

if df["risk_level"].nunique() < 2:
    raise SystemExit(
        "Need at least two risk classes for classification."
    )

missing_features = [
    name for name in FEATURES
    if name not in df.columns
]

if missing_features:
    raise SystemExit(
        f"Dataset is missing features: {missing_features}"
    )

# CSVs edited by hand or produced by partial tool runs may contain text in
# numeric columns. Coerce explicitly so bad rows are rejected predictably.
for name in FEATURES + ["security_score"]:
    df[name] = pd.to_numeric(df[name], errors="coerce")

# Defensive: build_cluster_dataset.py cleans the CSV before writing it,
# but this script can be pointed at any CSV on disk, so don't hand
# scikit-learn a NaN silently - drop and say so instead of crashing
# deep inside model.fit with an unhelpful error.
before = len(df)
df = df.dropna(subset=FEATURES + ["security_score", "risk_level"])
dropped = before - len(df)
if dropped:
    print(f"Dropped {dropped} row(s) with missing values before training")

if len(df) < 20:
    raise SystemExit(
        "Fewer than 20 usable rows remain after dropping missing values."
    )

X = df[FEATURES]
y_score = df["security_score"]
y_risk = df["risk_level"]

# Keep the secure and insecure rows from the same snapshot in the
# same split. This avoids leaking information from paired assessments.
groups = df["snapshot"]

# Five-fold grouped stratification needs each risk class to occur in at
# least five independent snapshots; otherwise folds can lose a class or
# fail in a confusing scikit-learn exception.
class_group_counts = df.groupby("risk_level")["snapshot"].nunique()
print("Distinct snapshots per risk class:")
print(class_group_counts.to_string())
insufficient = class_group_counts[class_group_counts < 5]
if not insufficient.empty:
    detail = ", ".join(f"{label}={count}" for label, count in class_group_counts.items())
    raise SystemExit(
        "Need at least 5 distinct snapshots per risk class for the "
        f"grouped 5-fold split; observed: {detail}. Collect more varied snapshots."
    )

splitter = StratifiedGroupKFold(
    n_splits=5,
    shuffle=True,
    random_state=42,
)

try:
    folds = list(splitter.split(X, y_risk, groups))
except ValueError as error:
    raise SystemExit(f"Unable to create a grouped stratified split: {error}") from error


def make_score_model():
    return RandomForestRegressor(n_estimators=200, max_depth=10, min_samples_leaf=2, random_state=42)


def make_risk_model():
    return RandomForestClassifier(
        n_estimators=200, max_depth=10, min_samples_leaf=2, class_weight="balanced", random_state=42,
    )


def make_svm_score_model():
    return make_pipeline(
        StandardScaler(),
        SVR(kernel="rbf", C=50.0, epsilon=1.0)
    )


def make_svm_risk_model():
    return make_pipeline(
        StandardScaler(),
        SVC(kernel="rbf", C=10.0, class_weight="balanced", random_state=42)
    )


def make_xgb_score_model():
    return xgb.XGBRegressor(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.05,
        min_child_weight=0,
        random_state=42,
    )


def make_xgb_risk_model():
    return XGBoostSecurityClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.05,
        min_child_weight=0,
        random_state=42,
    )


# Evaluate on ALL five grouped folds and pool the out-of-fold predictions.
oof_score = pd.Series(np.nan, index=X.index, dtype=float)
oof_risk = pd.Series(index=X.index, dtype=object)
oof_svm_score = pd.Series(np.nan, index=X.index, dtype=float)
oof_svm_risk = pd.Series(index=X.index, dtype=object)
oof_xgb_score = pd.Series(np.nan, index=X.index, dtype=float)
oof_xgb_risk = pd.Series(index=X.index, dtype=object)
oof_logistic = pd.Series(index=X.index, dtype=object)
fold_accuracy = []
fold_svm_accuracy = []
fold_xgb_accuracy = []
skipped_folds = 0

for fold_number, (train_idx, test_idx) in enumerate(folds, start=1):
    if y_risk.iloc[train_idx].nunique() < 2:
        skipped_folds += 1
        print(f"Fold {fold_number}: training split has a single risk class; skipped")
        continue

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]

    # Random Forest
    fold_score_model = make_score_model().fit(X_train, y_score.iloc[train_idx])
    fold_risk_model = make_risk_model().fit(X_train, y_risk.iloc[train_idx])

    oof_score.iloc[test_idx] = fold_score_model.predict(X_test)
    oof_risk.iloc[test_idx] = fold_risk_model.predict(X_test)
    fold_accuracy.append(
        accuracy_score(y_risk.iloc[test_idx], oof_risk.iloc[test_idx])
    )

    # Support Vector Machine (SVM)
    fold_svm_score_model = make_svm_score_model().fit(X_train, y_score.iloc[train_idx])
    fold_svm_risk_model = make_svm_risk_model().fit(X_train, y_risk.iloc[train_idx])

    oof_svm_score.iloc[test_idx] = fold_svm_score_model.predict(X_test)
    oof_svm_risk.iloc[test_idx] = fold_svm_risk_model.predict(X_test)
    fold_svm_accuracy.append(
        accuracy_score(y_risk.iloc[test_idx], oof_svm_risk.iloc[test_idx])
    )

    # XGBoost
    fold_xgb_score_model = make_xgb_score_model().fit(X_train, y_score.iloc[train_idx])
    fold_xgb_risk_model = make_xgb_risk_model().fit(X_train, y_risk.iloc[train_idx])

    oof_xgb_score.iloc[test_idx] = fold_xgb_score_model.predict(X_test)
    oof_xgb_risk.iloc[test_idx] = fold_xgb_risk_model.predict(X_test)
    fold_xgb_accuracy.append(
        accuracy_score(y_risk.iloc[test_idx], oof_xgb_risk.iloc[test_idx])
    )

    # Baseline Logistic Regression
    fold_scaler = StandardScaler().fit(X_train)
    fold_logistic = LogisticRegression(max_iter=2000).fit(
        fold_scaler.transform(X_train), y_risk.iloc[train_idx]
    )
    oof_logistic.iloc[test_idx] = fold_logistic.predict(
        fold_scaler.transform(X_test)
    )

evaluated = oof_score.notna()

if evaluated.sum() == 0:
    raise SystemExit(
        "No fold could be evaluated; collect more balanced snapshots."
    )

print(
    f"\nEvaluated {int(evaluated.sum())} of {len(df)} rows "
    f"across {len(fold_accuracy)} grouped fold(s)"
)

print("\n=== Random Forest: Security Score (grouped 5-fold) ===")
print("R2 :", round(r2_score(y_score[evaluated], oof_score[evaluated]), 3))
print(
    "RMSE:",
    round(np.sqrt(mean_squared_error(y_score[evaluated], oof_score[evaluated])), 3)
)
print(
    "MAE :",
    round(mean_absolute_error(y_score[evaluated], oof_score[evaluated]), 3)
)

print("\n=== Support Vector Machine (SVM): Security Score (grouped 5-fold) ===")
print("R2 :", round(r2_score(y_score[evaluated], oof_svm_score[evaluated]), 3))
print(
    "RMSE:",
    round(np.sqrt(mean_squared_error(y_score[evaluated], oof_svm_score[evaluated])), 3)
)
print(
    "MAE :",
    round(mean_absolute_error(y_score[evaluated], oof_svm_score[evaluated]), 3)
)

print("\n=== Random Forest: Risk Level (grouped 5-fold) ===")
print(
    "Accuracy:",
    round(accuracy_score(y_risk[evaluated], oof_risk[evaluated]), 3),
    f"(per-fold mean {np.mean(fold_accuracy):.3f} +/- {np.std(fold_accuracy):.3f})",
)
print(
    classification_report(
        y_risk[evaluated],
        oof_risk[evaluated],
        zero_division=0,
    )
)

print("\n=== Support Vector Machine (SVM): Risk Level (grouped 5-fold) ===")
print(
    "Accuracy:",
    round(accuracy_score(y_risk[evaluated], oof_svm_risk[evaluated]), 3),
    f"(per-fold mean {np.mean(fold_svm_accuracy):.3f} +/- {np.std(fold_svm_accuracy):.3f})",
)
print(
    classification_report(
        y_risk[evaluated],
        oof_svm_risk[evaluated],
        zero_division=0,
    )
)

print("\n=== XGBoost: Security Score (grouped 5-fold) ===")
print("R2 :", round(r2_score(y_score[evaluated], oof_xgb_score[evaluated]), 3))
print(
    "RMSE:",
    round(np.sqrt(mean_squared_error(y_score[evaluated], oof_xgb_score[evaluated])), 3)
)
print(
    "MAE :",
    round(mean_absolute_error(y_score[evaluated], oof_xgb_score[evaluated]), 3)
)

print("\n=== XGBoost: Risk Level (grouped 5-fold) ===")
print(
    "Accuracy:",
    round(accuracy_score(y_risk[evaluated], oof_xgb_risk[evaluated]), 3),
    f"(per-fold mean {np.mean(fold_xgb_accuracy):.3f} +/- {np.std(fold_xgb_accuracy):.3f})",
)
print(
    classification_report(
        y_risk[evaluated],
        oof_xgb_risk[evaluated],
        zero_division=0,
    )
)

baseline_accuracy = y_risk[evaluated].value_counts(normalize=True).max()

print("=== Classification Model Comparison Summary ===")
print(f"Random Forest Accuracy        : {accuracy_score(y_risk[evaluated], oof_risk[evaluated]):.3f}")
print(f"SVM (RBF Kernel) Accuracy     : {accuracy_score(y_risk[evaluated], oof_svm_risk[evaluated]):.3f}")
print(f"XGBoost Classifier Accuracy   : {accuracy_score(y_risk[evaluated], oof_xgb_risk[evaluated]):.3f}")
print(f"Logistic Regression Accuracy  : {accuracy_score(y_risk[evaluated], oof_logistic[evaluated]):.3f}")
print(f"Most-frequent-class baseline  : {baseline_accuracy:.3f}")

print(
    "\nNote: security_score and risk_level are computed from the same "
    "indicators used as features, so high scores here show the models "
    "reproduce the heuristic, not that they predict real-world breaches."
)

# Final deliverable: refit on ALL usable rows
score_model = make_score_model().fit(X, y_score)
risk_model = make_risk_model().fit(X, y_risk)
svm_score_model = make_svm_score_model().fit(X, y_score)
svm_risk_model = make_svm_risk_model().fit(X, y_risk)
xgb_score_model = make_xgb_score_model().fit(X, y_score)
xgb_risk_model = make_xgb_risk_model().fit(X, y_risk)

print("\n=== Important Security Indicators (Random Forest) ===")

importance = sorted(
    zip(FEATURES, risk_model.feature_importances_),
    key=lambda item: item[1],
    reverse=True,
)

max_imp = max((v for _, v in importance), default=1.0)
for name, value in importance:
    bar_len = int(round((value / max_imp) * 20)) if max_imp > 0 else 0
    bar = "█" * bar_len + "░" * (20 - bar_len)
    print(f"{name:35} [{bar}] {value:.3f}")

print("\n=== Important Security Indicators (XGBoost) ===")

xgb_importance = sorted(
    zip(FEATURES, xgb_risk_model.feature_importances_),
    key=lambda item: item[1],
    reverse=True,
)

max_xgb_imp = max((v for _, v in xgb_importance), default=1.0)
for name, value in xgb_importance:
    bar_len = int(round((value / max_xgb_imp) * 20)) if max_xgb_imp > 0 else 0
    bar = "█" * bar_len + "░" * (20 - bar_len)
    print(f"{name:35} [{bar}] {value:.3f}")


MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(
    {
        "score_model": score_model,
        "risk_model": risk_model,
        "svm_score_model": svm_score_model,
        "svm_risk_model": svm_risk_model,
        "xgb_score_model": xgb_score_model,
        "xgb_risk_model": xgb_risk_model,
        "features": FEATURES,
        "trained_rows": int(len(df)),
    },
    MODEL_FILE,
)

print("\nSaved:", paths.rel(MODEL_FILE))
