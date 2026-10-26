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
svm_scores = MODEL["svm_score_model"].predict(X) if "svm_score_model" in MODEL else None
svm_risks = MODEL["svm_risk_model"].predict(X) if "svm_risk_model" in MODEL else None
xgb_scores = MODEL["xgb_score_model"].predict(X) if "xgb_score_model" in MODEL else None
xgb_risks = MODEL["xgb_risk_model"].predict(X) if "xgb_risk_model" in MODEL else None
iso_model = MODEL.get("iso_model")
iso_scores = iso_model.decision_function(X) if iso_model is not None else None
iso_preds = iso_model.predict(X) if iso_model is not None else None

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


def make_meter(score, length=20):
    """Render a visual ASCII posture bar."""
    filled = max(0, min(length, int(round((score / 100.0) * length))))
    return "█" * filled + "░" * (length - filled)


def risk_priority(indicator):
    """Categorize risk indicators into critical, high, medium priority tiers."""
    critical_indicators = {
        "critical_cve_count", "critical_misconfig_count", "privileged_count",
    }
    high_indicators = {
        "high_cve_count", "high_misconfig_count", "secret_count",
        "rbac_risk_score", "root_execution_count", "host_path_count",
        "risky_capability_count", "kubescape_critical",
    }
    if indicator in critical_indicators:
        return "CRITICAL"
    if indicator in high_indicators:
        return "HIGH"
    return "MEDIUM"


def indicator_status(name, val):
    """Return status tag and message for an indicator."""
    try:
        num = float(val)
    except (TypeError, ValueError):
        return "[INFO]", str(val)

    if num == 0:
        return "[PASS]", "Clean"
    
    p = risk_priority(name)
    if p == "CRITICAL":
        return "[FAIL]", f"Critical alert ({int(num) if num.is_integer() else num})"
    elif p == "HIGH":
        return "[WARN]", f"High risk ({int(num) if num.is_integer() else num})"
    else:
        return "[NOTE]", f"Active finding ({int(num) if num.is_integer() else num})"


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
        evidence_val = float(row['security_score'])
        evidence = f"{evidence_val:.1f}/100"
        evidence_meter = f"[{make_meter(evidence_val)}] {evidence}"
    except (KeyError, TypeError, ValueError):
        evidence_val = None
        evidence = "not available"
        evidence_meter = evidence

    pred_meter = f"[{make_meter(predicted_score)}] {predicted_score:.1f}/100"

    add(f"Evidence Score     : {evidence}")
    add(f"Posture Bar        : {pred_meter}")
    add(f"RF Predicted Score : {predicted_score:.1f}/100 (Risk: {predicted_risk})")
    if svm_scores is not None:
        add(f"SVM Predicted Score: {svm_scores[position]:.1f}/100 (Risk: {svm_risks[position]})")
    if xgb_scores is not None:
        add(f"XGB Predicted Score: {xgb_scores[position]:.1f}/100 (Risk: {xgb_risks[position]})")
    if iso_scores is not None and iso_preds is not None:
        status_tag = "Normal Inlier" if iso_preds[position] == 1 else "ANOMALY (Outlier)"
        add(f"Isolation Forest   : [{status_tag}] (Decision Score: {iso_scores[position]:+.3f})")
    if svm_scores is None and xgb_scores is None:
        add(f"ML Risk Level      : {predicted_risk}")

    if evidence_val is not None:
        delta = abs(predicted_score - evidence_val)
        confidence = "High ML Alignment" if delta < 5 else "Moderate Alignment" if delta < 15 else "Review Needed"
        add(f"Model Delta (|Δ|)  : {delta:.2f} points ({confidence})")

    add()
    add("Security Indicators (Telemetry Breakdown)")

    # Grouped presentation
    categories = [
        ("Vulnerabilities & Supply Chain", [
            "critical_cve_count", "high_cve_count", "critical_misconfig_count",
            "high_misconfig_count", "secret_count"
        ]),
        ("Configuration & Pod Hardening", [
            "privileged_count", "root_execution_count", "risky_capability_count",
            "host_path_count", "host_port_count", "missing_network_policies"
        ]),
        ("Access & Identity (RBAC)", [
            "rbac_risk_score", "service_account_permission_score"
        ]),
        ("Compliance & Runtime Detection", [
            "kubescape_failed", "kubescape_critical", "kubescape_high",
            "falco_alert_count"
        ]),
    ]

    for cat_name, cat_features in categories:
        add(f"  [{cat_name}]")
        for name in cat_features:
            if name in features:
                val = row[name]
                tag, note = indicator_status(name, val)
                add(f"    {name:33} {str(val):<5} {tag:<8} {note}")
        add()

    active = []

    for name in features:
        value = row[name]

        try:
            is_active = float(value) > 0
        except (TypeError, ValueError):
            is_active = False

        if is_active:
            active.append(name)

    add("Detected Risk Indicators & Remediation Action Plan")

    if not active:
        add("No active risk indicators in the selected assessment. Cluster is well-hardened.")
    else:
        # Sort active indicators by priority (CRITICAL -> HIGH -> MEDIUM)
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        sorted_active = sorted(active, key=lambda k: (order.get(risk_priority(k), 3), k))

        for name in sorted_active:
            priority = risk_priority(name)
            val = row[name]
            add(f"- [{priority}] {name} (observed: {val})")
            if name in remediations:
                add(f"  Action: {remediations[name]}")

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

# If multiple environments were evaluated, append a Comparative Executive Dashboard
if len(DATA) > 1:
    add()
    add("==========================================================================================================")
    add("                                    EXECUTIVE MULTI-CLUSTER COMPARISON                                    ")
    add("==========================================================================================================")
    header = f"{'Environment':<22} {'Evidence':<11} {'RF Score':<11} {'SVM Score':<11}"
    if xgb_scores is not None:
        header += f" {'XGB Score':<11}"
    header += f" {'Risk Tier':<11}"
    if iso_preds is not None:
        header += f" {'Iso Status':<13}"
    header += "Posture"
    add(header)
    divider_len = len(header) + 12
    add("-" * 106)
    for pos in range(len(DATA)):
        r = DATA.iloc[pos]
        lbl = " / ".join(str(r[c]) for c in ("snapshot", "environment") if c in DATA.columns) or f"Target #{pos+1}"
        try:
            ev = f"{float(r['security_score']):.1f}/100"
        except (KeyError, TypeError, ValueError):
            ev = "N/A"
        pred = f"{float(predicted_scores[pos]):.1f}/100"
        svm_p = f"{float(svm_scores[pos]):.1f}/100" if svm_scores is not None else "N/A"
        row_str = f"{lbl:<22} {ev:<11} {pred:<11} {svm_p:<11}"
        if xgb_scores is not None:
            xgb_p = f"{float(xgb_scores[pos]):.1f}/100"
            row_str += f" {xgb_p:<11}"
        tier = str(predicted_risks[pos])
        row_str += f" {tier:<11}"
        if iso_preds is not None:
            iso_label = "Inlier" if iso_preds[pos] == 1 else "ANOMALY!"
            row_str += f" {iso_label:<13}"
        meter = f"[{make_meter(float(predicted_scores[pos]), 10)}]"
        row_str += f" {meter}"
        add(row_str)
    add("==========================================================================================================")

report_file = Path(sys.argv[2]) if len(sys.argv) > 2 else paths.REPORT_FILE
report_file.parent.mkdir(parents=True, exist_ok=True)
with open(report_file, "w") as file:
    file.write("\n".join(lines) + "\n")

print()
print("Report saved:", paths.rel(report_file))
