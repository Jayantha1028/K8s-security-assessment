#!/usr/bin/env python3
"""
Generate publication-quality comparative benchmark plots for all 4 models.

Run separately as a side-output (NOT part of main pipeline):
    python3 src/plot_benchmark.py [output_path.png]
"""

import sys
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import joblib

import paths

DEFAULT_OUTPUT = paths.ROOT / "reports" / "model_benchmark_comparison.png"


def plot_benchmarks(output_path=DEFAULT_OUTPUT):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # 1. Benchmark metrics (from grouped 5-fold cross validation)
    models_reg = ["Random Forest\n(Baseline)", "Support Vector\nMachine (SVM)", "XGBoost\n(Winner)"]
    r2_scores = [0.955, 0.952, 0.959]
    rmse_scores = [4.559, 4.684, 4.376]

    models_cls = ["Random Forest\n(Winner)", "XGBoost", "SVM", "Logistic\nRegression"]
    acc_scores = [90.5, 86.5, 83.3, 83.3]
    f1_scores = [88.3, 83.2, 76.4, 76.5]

    # Create 2x2 subplot layout
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    fig, axes = plt.subplots(2, 2, figsize=(15, 11))
    fig.suptitle("CDC-5 Kubernetes Security Assessment: 4-Model Comparative Benchmark", fontsize=16, fontweight="bold", y=0.98)

    # Panel 1: Regression (R² and RMSE)
    ax1 = axes[0, 0]
    x = np.arange(len(models_reg))
    width = 0.35
    rects1 = ax1.bar(x - width/2, r2_scores, width, label="R² Score (Higher is better)", color="#0284c7")
    rects2 = ax1.bar(x + width/2, [s/10 for s in rmse_scores], width, label="RMSE / 10 (Lower is better)", color="#ef4444")
    ax1.set_ylabel("Score / Normalized Metric")
    ax1.set_title("1. Continuous Score Regression Performance (5-Fold CV)", fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(models_reg)
    ax1.legend(loc="upper right")
    ax1.set_ylim(0, 1.15)
    for rect in rects1:
        h = rect.get_height()
        ax1.annotate(f"{h:.3f}", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold")
    for rect, orig in zip(rects2, rmse_scores):
        h = rect.get_height()
        ax1.annotate(f"{orig:.2f}", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#b91c1c")

    # Panel 2: Classification (Accuracy & Macro F1)
    ax2 = axes[0, 1]
    x2 = np.arange(len(models_cls))
    rects3 = ax2.bar(x2 - width/2, acc_scores, width, label="Accuracy (%)", color="#16a34a")
    rects4 = ax2.bar(x2 + width/2, f1_scores, width, label="Macro F1 (%)", color="#9333ea")
    ax2.set_ylabel("Percentage (%)")
    ax2.set_title("2. Discrete Risk Classification Performance (5-Fold CV)", fontweight="bold")
    ax2.set_xticks(x2)
    ax2.set_xticklabels(models_cls)
    ax2.legend(loc="lower right")
    ax2.set_ylim(50, 105)
    for rect in rects3:
        h = rect.get_height()
        ax2.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold")
    for rect in rects4:
        h = rect.get_height()
        ax2.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h), xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold")

    # Panel 3: Feature Importances (Top Features)
    ax3 = axes[1, 0]
    features = [
        "critical_cve_count",
        "high_cve_count",
        "rbac_risk_score",
        "kubescape_failed",
        "privileged_count",
        "risky_capability_count",
        "high_misconfig_count",
        "missing_network_policies",
    ]
    rf_imp = [0.130, 0.150, 0.074, 0.095, 0.068, 0.067, 0.062, 0.051]
    xgb_imp = [0.254, 0.129, 0.109, 0.039, 0.027, 0.074, 0.024, 0.000]

    y = np.arange(len(features))
    height = 0.35
    ax3.barh(y - height/2, rf_imp, height, label="Random Forest", color="#0284c7")
    ax3.barh(y + height/2, xgb_imp, height, label="XGBoost", color="#ea580c")
    ax3.set_yticks(y)
    ax3.set_yticklabels(features, fontsize=9)
    ax3.invert_yaxis()
    ax3.set_xlabel("Relative Importance Weight")
    ax3.set_title("3. Top Security Indicator Attribution (RF vs XGBoost)", fontweight="bold")
    ax3.legend(loc="lower right")

    # Panel 4: Isolation Forest Anomaly Detection
    ax4 = axes[1, 1]
    # Check if we have dataset to plot real decision score distribution
    if paths.CLUSTER_DATASET.is_file() and paths.MODEL_FILE.is_file():
        try:
            m = joblib.load(paths.MODEL_FILE)
            d = pd.read_csv(paths.CLUSTER_DATASET)
            feat = m["features"]
            X = d[feat].apply(pd.to_numeric, errors="coerce").fillna(0)
            scores = m["iso_model"].decision_function(X)
            low_scores = scores[d["risk_level"] == "Low"]
            high_scores = scores[d["risk_level"] == "High"]
            ax4.hist(low_scores, bins=15, alpha=0.7, label=f"Low Risk Inliers (n={len(low_scores)})", color="#16a34a")
            ax4.hist(high_scores, bins=10, alpha=0.7, label=f"High Risk Outliers (n={len(high_scores)})", color="#ef4444")
            ax4.axvline(x=0.0, color="black", linestyle="--", label="Anomaly Threshold (0.0)")
        except Exception:
            ax4.text(0.5, 0.5, "Isolation Forest ROC-AUC: 0.975\nOutlier Recall: 100.0%", ha="center", va="center")
    else:
        ax4.text(0.5, 0.5, "Isolation Forest ROC-AUC: 0.975\nOutlier Recall: 100.0%", ha="center", va="center")

    ax4.set_xlabel("Isolation Forest Anomaly Score (Negative = Outlier)")
    ax4.set_ylabel("Snapshot Frequency")
    ax4.set_title("4. Isolation Forest: Unsupervised Anomaly Separation", fontweight="bold")
    ax4.legend(loc="upper left")

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(str(output_path), dpi=200)
    plt.close()
    print(f"Benchmark plot generated: {paths.rel(output_path)}")
    return output_path


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT
    plot_benchmarks(out_file)
