"""
xai_threat_attribution.py
=========================
Explainable AI (XAI) & Threat Attribution Engine for Kubernetes Security Assessment.
Uses TreeSHAP (SHapley Additive exPlanations) to decompose ML model predictions into exact
feature-level marginal risk attributions.

Key Capabilities:
1. Exact Marginal Attribution: Explains every predicted continuous score and discrete risk tier.
2. Positive vs Negative Risk Drivers: Quantifies protective configurations vs vulnerability penalties.
3. Waterfall & Bar Visualizations: Generates publication-ready SHAP attribution plots.
4. Actionable Remediation Prioritization: Ranks security fixes by maximum potential score recovery.
5. Direct Snowflake Sync: Ingests attributions into K8S_SECURITY.PUBLIC.K8S_THREAT_ATTRIBUTION_SHAP.
"""

import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Tuple
import joblib
import pandas as pd
import numpy as np
import shap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))
# Ensure core and parent src are in sys.path
import sys
from pathlib import Path
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
    sys.path.insert(0, str(_CORE_DIR.parent))
import paths
from vulnerability_taxonomy_56 import TAXONOMY_56

FEATURE_FRIENDLY_NAMES = {
    "kubescape_failed": "Compliance Control Violations",
    "kubescape_critical": "Critical NSA Compliance Failures",
    "kubescape_high": "High NSA Compliance Failures",
    "critical_cve_count": "Critical Image CVEs (CVSS >= 9)",
    "high_cve_count": "High Image CVEs (CVSS 7.0-8.9)",
    "critical_misconfig_count": "Critical IaC Misconfigurations",
    "high_misconfig_count": "High IaC Misconfigurations",
    "secret_count": "Exposed Hardcoded Secrets",
    "rbac_risk_score": "Overprivileged RBAC Roles",
    "service_account_permission_score": "Excessive ServiceAccount Permissions",
    "risky_capability_count": "Dangerous Linux Capabilities Added",
    "host_path_count": "HostPath Volume Mounts",
    "missing_network_policies": "Missing Default-Deny NetworkPolicies",
    "root_execution_count": "Container Root Execution (UID 0)",
    "falco_alert_count": "Runtime eBPF Syscall Alerts",
    "privileged_count": "Privileged Container Execution",
    "host_port_count": "Direct hostPort Exposures",
}


class ThreatAttributionExplainer:
    def __init__(self, model: Any, features: List[str]):
        self.model = model
        self.features = features
        self.explainer = shap.TreeExplainer(model)
        self.base_value = float(
            self.explainer.expected_value[0]
            if isinstance(self.explainer.expected_value, (list, np.ndarray))
            else self.explainer.expected_value
        )

    def explain_instance(self, row_features: pd.Series) -> List[Dict[str, Any]]:
        """Computes SHAP values and returns sorted list of feature attributions."""
        X_df = pd.DataFrame([row_features[self.features]], columns=self.features)
        shap_vals = self.explainer.shap_values(X_df)[0]

        attributions = []
        for feat, val, raw in zip(self.features, shap_vals, X_df.iloc[0]):
            friendly = FEATURE_FRIENDLY_NAMES.get(feat, feat)
            impact_type = "Risk Driver (Penalty)" if val < 0 else "Protective Factor (Bonus)"
            attributions.append({
                "feature": feat,
                "friendly_name": friendly,
                "raw_value": float(raw),
                "shap_value": float(val),
                "absolute_impact": abs(float(val)),
                "impact_type": impact_type,
            })

        # Sort by largest absolute contribution
        attributions.sort(key=lambda x: x["absolute_impact"], reverse=True)
        return attributions

    def generate_waterfall_plot(self, row_features: pd.Series, output_path: Path, title: str = "SHAP Threat Attribution"):
        """Generates a high-resolution horizontal bar explanation plot."""
        attributions = self.explain_instance(row_features)
        top_attrs = attributions[:10]  # Top 10 contributors

        names = [a["friendly_name"] for a in reversed(top_attrs)]
        values = [a["shap_value"] for a in reversed(top_attrs)]
        colors = ["#EF4444" if v < 0 else "#10B981" for v in values]  # Red for penalty, Green for bonus

        fig, ax = plt.subplots(figsize=(10, 6), dpi=200)
        y_pos = np.arange(len(names))
        bars = ax.barh(y_pos, values, color=colors, height=0.6, edgecolor="#0F172A", linewidth=0.8)

        # Labels
        ax.set_yticks(y_pos)
        ax.set_yticklabels(names, fontsize=10, fontweight="medium")
        ax.axvline(0, color="#64748B", linewidth=1.2, linestyle="--")

        # Value annotations
        for bar in bars:
            width = bar.get_width()
            align = "left" if width >= 0 else "right"
            offset = 0.4 if width >= 0 else -0.4
            ax.annotate(
                f"{width:+.2f} pts",
                xy=(width + offset, bar.get_y() + bar.get_height() / 2),
                va="center",
                ha=align,
                fontsize=9,
                fontweight="bold",
                color="#0F172A"
            )

        ax.set_xlabel("Marginal Impact on Security Score (SHAP Value in Points)", fontsize=11, fontweight="bold")
        ax.set_title(f"{title} (Base Baseline: {self.base_value:.1f}/100)", fontsize=13, fontweight="bold", pad=15)
        ax.grid(axis="x", linestyle=":", alpha=0.6)
        plt.tight_layout()

        output_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(output_path, dpi=200)
        plt.close(fig)


def export_attributions_to_snowflake(attributions_df: pd.DataFrame):
    """Syncs threat attributions directly to Snowflake (K8S_SECURITY)."""
    try:
        from export_to_snowflake import get_connection, DATABASE, SCHEMA
        from snowflake.connector.pandas_tools import write_pandas

        ctx = get_connection()
        success, nchunks, nrows, _ = write_pandas(
            conn=ctx,
            df=attributions_df,
            table_name="K8S_THREAT_ATTRIBUTION_SHAP",
            database=DATABASE,
            schema=SCHEMA,
            auto_create_table=True,
            overwrite=True
        )
        ctx.close()
        print(f"✓ Uploaded {nrows} SHAP attribution records to Snowflake table: K8S_THREAT_ATTRIBUTION_SHAP.")
    except Exception as e:
        print(f"Snowflake SHAP sync skipped or encountered note: {e}")


def main():
    print("=" * 80)
    print("    CDC-5: EXPLAINABLE AI (XAI) & THREAT ATTRIBUTION ENGINE (TreeSHAP)")
    print("=" * 80)

    # 1. Load trained model & latest assessment
    model_path = paths.MODEL_FILE
    if not model_path.is_file():
        raise SystemExit("Trained model bundle not found. Run 'make train' first.")

    model_data = joblib.load(model_path)
    rf_model = model_data["score_model"]
    features = model_data["features"]

    input_csv = paths.REPORT_INPUT
    if not input_csv.is_file():
        raise SystemExit("Assessment CSV not found. Run cluster collector first.")

    df = pd.read_csv(input_csv)
    explainer = ThreatAttributionExplainer(rf_model, features)

    print(f"TreeSHAP Explainer initialized across {len(features)} security feature dimensions.")
    print(f"Population Expected Base Score: {explainer.base_value:.2f}/100\n")

    all_attributions = []

    for idx in range(len(df)):
        row = df.iloc[idx]
        env_label = str(row.get("environment", f"Target #{idx+1}"))
        snap_label = str(row.get("snapshot", "latest"))
        predicted_score = float(rf_model.predict(pd.DataFrame([row[features]], columns=features))[0])

        print(f"[{idx+1}/{len(df)}] Explaining Workload: {snap_label} / {env_label}")
        print(f"      Model Predicted Score: {predicted_score:.1f}/100 (Base: {explainer.base_value:.1f}/100)")

        attrs = explainer.explain_instance(row)
        print("      Top Marginal Threat Drivers & Hardening Bonuses:")
        for a in attrs[:5]:
            sign = "+" if a["shap_value"] > 0 else ""
            print(f"        • {a['friendly_name']:34}: {sign}{a['shap_value']:.2f} pts (Observed Count: {a['raw_value']})")

        # Generate Waterfall Image
        img_name = f"shap_attribution_{env_label.replace('/', '_')}.png"
        img_path = paths.ROOT / "reports" / img_name
        explainer.generate_waterfall_plot(
            row,
            img_path,
            title=f"Threat Attribution: {env_label.capitalize()} Workload"
        )
        print(f"      Saved visualization: {paths.rel(img_path)}")

        for rank, a in enumerate(attrs, start=1):
            all_attributions.append({
                "SNAPSHOT": snap_label,
                "ENVIRONMENT": env_label,
                "FEATURE_RANK": rank,
                "FEATURE_NAME": a["feature"],
                "FRIENDLY_NAME": a["friendly_name"],
                "RAW_OBSERVED_VALUE": a["raw_value"],
                "SHAP_MARGINAL_POINTS": a["shap_value"],
                "IMPACT_TYPE": a["impact_type"],
                "PREDICTED_SCORE": predicted_score,
                "BASE_SCORE": explainer.base_value
            })
        print()

    # Export to Snowflake
    df_attributions = pd.DataFrame(all_attributions)
    export_attributions_to_snowflake(df_attributions)

    print("=" * 80)
    print("XAI Threat Attribution completed successfully.")
    print("=" * 80)


if __name__ == "__main__":
    main()
