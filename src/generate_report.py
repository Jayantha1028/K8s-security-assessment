from pathlib import Path
import sys

import joblib
import pandas as pd

import paths


if len(sys.argv) > 3:
    raise SystemExit(
        "Usage: python3 src/generate_report.py [assessment.csv] [output.txt]\n"
        f"Defaults: {paths.rel(paths.REPORT_INPUT)} -> {paths.rel(paths.REPORT_FILE)}"
    )

input_csv = Path(sys.argv[1]) if len(sys.argv) > 1 else paths.REPORT_INPUT
model_path = paths.MODEL_FILE
if not model_path.is_file():
    raise SystemExit(
        f"Model file not found: {paths.rel(model_path)}. Train the model first."
    )
if not input_csv.is_file():
    raise SystemExit(f"Assessment CSV not found: {input_csv}")
MODEL = joblib.load(model_path)
DATA = pd.read_csv(input_csv)
if DATA.empty:
    raise SystemExit(f"Assessment CSV contains no rows: {input_csv}")
missing = [name for name in MODEL.get("features", []) if name not in DATA.columns]
if missing:
    raise SystemExit(f"Assessment CSV is missing model features: {missing}")

features = MODEL["features"]

# Validate and coerce so a bad cell gives a clear message, not a
# traceback from deep inside scikit-learn.
X = DATA[features].apply(pd.to_numeric, errors="coerce")
bad_rows = X.isna().any(axis=1)
if bad_rows.any():
    raise SystemExit(
        f"Assessment CSV has missing/non-numeric feature values in "
        f"{int(bad_rows.sum())} row(s): {input_csv}"
    )

predicted_scores = MODEL["score_model"].predict(X)
predicted_risks = MODEL["risk_model"].predict(X)

remediations = {
    "privileged_count":
        "Remove privileged containers.",
    "root_execution_count":
        "Run containers as non-root users.",
    "risky_capability_count":
        "Drop unnecessary Linux capabilities.",
    "host_path_count":
        "Replace hostPath mounts with safer storage where possible.",
    "missing_network_policies":
        "Add restrictive NetworkPolicies.",
    "rbac_risk_score":
        "Apply least-privilege Roles and RoleBindings.",
    "service_account_permission_score":
        "Reduce unnecessary service-account permissions.",
    "critical_cve_count":
        "Update or replace images with critical CVEs.",
    "high_cve_count":
        "Update or replace images with high-severity CVEs.",
    "critical_misconfig_count":
        "Remediate critical Kubernetes misconfigurations.",
    "high_misconfig_count":
        "Remediate high-severity Kubernetes misconfigurations.",
    "secret_count":
        "Remove exposed secrets and use Kubernetes Secrets safely.",
    "falco_alert_count":
        "Investigate recent runtime security alerts.",
    "host_port_count":
        "Prefer Kubernetes Services instead of hostPort.",
}


lines = []


def add(line=""):
    print(line)
    lines.append(line)


def describe(position):
    row = DATA.iloc[position]
    predicted_score = float(predicted_scores[position])
    predicted_risk = str(predicted_risks[position])

    add("========================================")
    add("      KUBERNETES SECURITY ASSESSMENT")
    add("========================================")

    label = " / ".join(
        str(row[col]) for col in ("snapshot", "environment")
        if col in DATA.columns
    )
    if label:
        add(f"Assessment         : {label}")

    try:
        evidence = f"{float(row['security_score']):.1f}/100"
    except (KeyError, TypeError, ValueError):
        evidence = "not available"
    add(f"Evidence Score     : {evidence}")

    add(
        f"ML Predicted Score : "
        f"{predicted_score:.1f}/100"
    )

    add(
        f"ML Risk Level      : "
        f"{predicted_risk}"
    )

    add()
    add("Security Indicators")

    for name in features:
        add(
            f"{name:35} "
            f"{row[name]}"
        )

    active = []

    for name in features:
        value = row[name]

        try:
            is_active = float(value) > 0
        except (TypeError, ValueError):
            is_active = False

        if is_active:
            active.append(name)

    add()
    add("Detected Risk Indicators")

    if not active:
        add("No active risk indicators in the selected assessment.")
    else:
        for name in active:
            add(f"- {name}")
            if name in remediations:
                add(f"  Remediation: {remediations[name]}")

    add()
    add("Assessment")
    add(
        "The evidence score is the transparent baseline "
        "computed from collected security indicators."
    )
    add(
        "The ML prediction estimates the security condition "
        "from the same underlying indicators without using "
        "the final score itself as an input feature."
    )

for position in range(len(DATA)):
    if position:
        add()
    describe(position)

report_file = Path(sys.argv[2]) if len(sys.argv) > 2 else paths.REPORT_FILE
report_file.parent.mkdir(parents=True, exist_ok=True)
with open(report_file, "w") as file:
    file.write("\n".join(lines) + "\n")

print()
print("Report saved:", paths.rel(report_file))
