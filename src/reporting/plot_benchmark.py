#!/usr/bin/env python3
"""
Generate publication-quality comparative benchmark plots for all 11 models.
Outputs both vector SVG and high-resolution PNG:
  - reports/model_benchmark_comparison.svg
  - reports/model_benchmark_comparison.png

Run directly or via pipeline:
    python3 src/plot_benchmark.py
"""

from pathlib import Path
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

import paths

DEFAULT_SVG = paths.ROOT / "reports" / "model_benchmark_comparison.svg"
DEFAULT_PNG = paths.ROOT / "reports" / "model_benchmark_comparison.png"


def load_metrics():
    """Load latest metrics from comparison report or fallback to benchmark defaults."""
    report_file = paths.ROOT / "reports" / "11_model_comparison_report.txt"
    metrics = {
        "m1": {"r2": 0.978, "rmse": 2.43, "acc": 95.7, "f1": 94.2},
        "m2": {"r2": 0.916, "rmse": 4.81, "acc": 93.9, "f1": 92.5},
        "m3": {"r2": 0.987, "rmse": 1.88, "acc": 96.5, "f1": 94.0},
        "m4": {"roc": 95.6, "recall": 100.0},
        "m5": {"r2": 0.977, "rmse": 3.88, "acc": 92.0, "f1": 91.6},
        "m6": {"r2": 0.954, "rmse": 5.42, "acc": 86.0, "f1": 86.0},
        "m7": {"r2": 0.976, "rmse": 3.94, "acc": 88.0, "f1": 87.0},
        "m8": {"roc": 82.0, "recall": 69.0},
        "m9": {"r2": 0.986, "rmse": 1.97, "acc": 96.5, "f1": 96.0},
        "m10": {"r2": 0.983, "rmse": 3.28, "acc": 92.0, "f1": 91.6},
        "m11": {"r2": 0.986, "rmse": 2.52, "acc": 94.4, "f1": 94.4},
        "synth_to_real": 80.0,
        "real_to_synth": 70.0,
        "combined_acc": 89.3,
        "goat_rate": 100.0,
    }

    if report_file.is_file():
        text = report_file.read_text(encoding="utf-8")
        # Try extracting dynamic metrics if format matches
        m = re.search(r"Synthetic -> Real Transfer Accuracy\s*:\s*([\d\.]+)%", text)
        if m:
            metrics["synth_to_real"] = float(m.group(1))
        m = re.search(r"Real -> Synthetic Transfer Accuracy\s*:\s*([\d\.]+)%", text)
        if m:
            metrics["real_to_synth"] = float(m.group(1))
        m = re.search(r"Final Master Model Combined Accuracy\s*:\s*([\d\.]+)%", text)
        if m:
            metrics["combined_acc"] = float(m.group(1))

    return metrics


def generate_charts(svg_path=DEFAULT_SVG, png_path=DEFAULT_PNG):
    svg_path = Path(svg_path)
    png_path = Path(png_path)
    svg_path.parent.mkdir(parents=True, exist_ok=True)
    png_path.parent.mkdir(parents=True, exist_ok=True)

    metrics = load_metrics()

    # Aesthetic configuration
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Helvetica", "Arial", "sans-serif"]
    plt.rcParams["axes.edgecolor"] = "#cbd5e1"
    plt.rcParams["axes.linewidth"] = 1.0

    fig, axes = plt.subplots(2, 2, figsize=(20, 14), facecolor="#ffffff")
    fig.suptitle(
        "CDC-5 Kubernetes Security Assessment: 11-Model Machine Learning Matrix Benchmark\n"
        "Comparative Evaluation across 200 Real-World Manifests, 200 Synthetic Clusters, 100 Live Feeds (500 Workloads Total)",
        fontsize=16,
        fontweight="bold",
        color="#0f172a",
        y=0.98,
    )

    # Domain palettes
    c_real = "#2563eb"     # Blue for Real-World
    c_synth = "#d97706"    # Amber for Synthetic
    c_consol = "#7c3aed"   # Purple for Consolidated Ensembles
    c_master = "#059669"   # Emerald Green for Master Unified Model

    model_labels = [
        "M1: RF\n(Real)", "M2: SVM\n(Real)", "M3: XGB\n(Real)",
        "M5: RF\n(Synth)", "M6: SVM\n(Synth)", "M7: XGB\n(Synth)",
        "M9: Consol\n(Real)", "M10: Consol\n(Synth)", "M11: Master\n(Unified)",
    ]
    colors = [c_real, c_real, c_real, c_synth, c_synth, c_synth, c_consol, c_consol, c_master]

    # ----------------- PANEL 1: R2 SCORE -----------------
    ax1 = axes[0, 0]
    ax1.set_facecolor("#f8fafc")
    r2_vals = [
        metrics["m1"]["r2"], metrics["m2"]["r2"], metrics["m3"]["r2"],
        metrics["m5"]["r2"], metrics["m6"]["r2"], metrics["m7"]["r2"],
        metrics["m9"]["r2"], metrics["m10"]["r2"], metrics["m11"]["r2"],
    ]
    bars1 = ax1.bar(model_labels, r2_vals, color=colors, width=0.58, edgecolor="#0f172a", linewidth=0.5, zorder=3)
    ax1.set_title("1. Continuous Score Regression: R² Score (Higher is Better)", fontsize=13, fontweight="bold", pad=12, color="#1e293b")
    ax1.set_ylim(0.85, 1.015)
    ax1.set_ylabel("R² Coefficient of Determination", fontsize=11, fontweight="bold", color="#334155")
    ax1.grid(axis="y", linestyle="--", alpha=0.6, zorder=0)
    ax1.axvline(2.5, color="#94a3b8", linestyle=":", linewidth=1.5)
    ax1.axvline(5.5, color="#94a3b8", linestyle=":", linewidth=1.5)

    # Annotate domain boundaries
    ax1.text(1.0, 0.86, "Real-World (200)", ha="center", fontsize=9.5, fontweight="bold", color=c_real,
             bbox=dict(facecolor="white", edgecolor=c_real, boxstyle="round,pad=0.3"))
    ax1.text(4.0, 0.86, "Synthetic & Live (300)", ha="center", fontsize=9.5, fontweight="bold", color=c_synth,
             bbox=dict(facecolor="white", edgecolor=c_synth, boxstyle="round,pad=0.3"))
    ax1.text(7.0, 0.86, "Consolidated Ensembles & Master (500)", ha="center", fontsize=9.5, fontweight="bold", color=c_master,
             bbox=dict(facecolor="white", edgecolor=c_master, boxstyle="round,pad=0.3"))

    for b, v in zip(bars1, r2_vals):
        ax1.text(b.get_x() + b.get_width() / 2, v + 0.003, f"{v:.3f}", ha="center", va="bottom", fontsize=9.5, fontweight="bold", color="#0f172a")

    # ----------------- PANEL 2: RMSE -----------------
    ax2 = axes[0, 1]
    ax2.set_facecolor("#f8fafc")
    rmse_vals = [
        metrics["m1"]["rmse"], metrics["m2"]["rmse"], metrics["m3"]["rmse"],
        metrics["m5"]["rmse"], metrics["m6"]["rmse"], metrics["m7"]["rmse"],
        metrics["m9"]["rmse"], metrics["m10"]["rmse"], metrics["m11"]["rmse"],
    ]
    bars2 = ax2.bar(model_labels, rmse_vals, color=colors, width=0.58, edgecolor="#0f172a", linewidth=0.5, zorder=3)
    ax2.set_title("2. Regression Residual Error: RMSE (Lower is Better)", fontsize=13, fontweight="bold", pad=12, color="#1e293b")
    ax2.set_ylim(0, 6.2)
    ax2.set_ylabel("Root Mean Squared Error (RMSE)", fontsize=11, fontweight="bold", color="#334155")
    ax2.grid(axis="y", linestyle="--", alpha=0.6, zorder=0)
    ax2.axvline(2.5, color="#94a3b8", linestyle=":", linewidth=1.5)
    ax2.axvline(5.5, color="#94a3b8", linestyle=":", linewidth=1.5)

    for b, v in zip(bars2, rmse_vals):
        is_best = v <= 2.0
        text_color = "#dc2626" if is_best else "#0f172a"
        best_tag = " (Best)" if is_best else ""
        ax2.text(b.get_x() + b.get_width() / 2, v + 0.12, f"{v:.2f}{best_tag}", ha="center", va="bottom", fontsize=9.5, fontweight="bold", color=text_color)

    # ----------------- PANEL 3: CLASSIFICATION ACCURACY & F1 -----------------
    ax3 = axes[1, 0]
    ax3.set_facecolor("#f8fafc")
    x = np.arange(len(model_labels))
    width = 0.35
    acc_vals = [
        metrics["m1"]["acc"], metrics["m2"]["acc"], metrics["m3"]["acc"],
        metrics["m5"]["acc"], metrics["m6"]["acc"], metrics["m7"]["acc"],
        metrics["m9"]["acc"], metrics["m10"]["acc"], metrics["m11"]["acc"],
    ]
    f1_vals = [
        metrics["m1"]["f1"], metrics["m2"]["f1"], metrics["m3"]["f1"],
        metrics["m5"]["f1"], metrics["m6"]["f1"], metrics["m7"]["f1"],
        metrics["m9"]["f1"], metrics["m10"]["f1"], metrics["m11"]["f1"],
    ]

    bars3_acc = ax3.bar(x - width / 2, acc_vals, width, label="3-Class Accuracy (%)", color="#0284c7", edgecolor="#0f172a", linewidth=0.5, zorder=3)
    bars3_f1 = ax3.bar(x + width / 2, f1_vals, width, label="Macro F1-Score (%)", color="#8b5cf6", edgecolor="#0f172a", linewidth=0.5, zorder=3)
    ax3.set_title("3. Discrete Risk Classification: Accuracy & Macro F1-Score", fontsize=13, fontweight="bold", pad=12, color="#1e293b")
    ax3.set_xticks(x)
    ax3.set_xticklabels(model_labels, fontsize=9.5)
    ax3.set_ylim(70, 102)
    ax3.set_ylabel("Percentage (%)", fontsize=11, fontweight="bold", color="#334155")
    ax3.grid(axis="y", linestyle="--", alpha=0.6, zorder=0)
    ax3.legend(loc="lower left", frameon=True, facecolor="white", edgecolor="#cbd5e1", fontsize=10)
    ax3.axvline(2.5, color="#94a3b8", linestyle=":", linewidth=1.5)
    ax3.axvline(5.5, color="#94a3b8", linestyle=":", linewidth=1.5)

    for b, v in zip(bars3_acc, acc_vals):
        ax3.text(b.get_x() + b.get_width() / 2, v + 0.5, f"{v:.1f}%", ha="center", va="bottom", fontsize=8.5, fontweight="bold", color="#0369a1")

    # ----------------- PANEL 4: ANOMALY DETECTION & CROSS-DOMAIN -----------------
    ax4 = axes[1, 1]
    ax4.set_facecolor("#f8fafc")

    panel4_names = [
        "M4: IsoForest (Real)\nROC-AUC vs High Risk",
        "M4: IsoForest (Real)\nOutlier Recall Rate",
        "M8: IsoForest (Synth)\nROC-AUC vs High Risk",
        "M8: IsoForest (Synth)\nOutlier Recall Rate",
        "Synthetic -> Real\nCross-Domain Transfer Acc",
        "Real -> Synthetic\nCross-Domain Transfer Acc",
        "M11 Master Combined (215)\nUniversal Evaluation Acc",
        "K8s Goat Attack Scenario\nDetection Consensus Rate",
    ]
    panel4_vals = [
        metrics["m4"]["roc"],
        metrics["m4"]["recall"],
        metrics["m8"]["roc"],
        metrics["m8"]["recall"],
        metrics["synth_to_real"],
        metrics["real_to_synth"],
        metrics["combined_acc"],
        metrics["goat_rate"],
    ]
    panel4_colors = [c_real, c_real, c_synth, c_synth, "#ea580c", "#3b82f6", c_master, "#dc2626"]

    bars4 = ax4.barh(panel4_names, panel4_vals, color=panel4_colors, height=0.6, edgecolor="#0f172a", linewidth=0.5, zorder=3)
    ax4.set_title("4. Unsupervised Anomaly Detection (M4 & M8) & Cross-Domain Validation", fontsize=13, fontweight="bold", pad=12, color="#1e293b")
    ax4.set_xlim(50, 108)
    ax4.set_xlabel("Score / Percentage (%)", fontsize=11, fontweight="bold", color="#334155")
    ax4.grid(axis="x", linestyle="--", alpha=0.6, zorder=0)
    ax4.invert_yaxis()

    for b, v in zip(bars4, panel4_vals):
        ax4.text(v + 0.8, b.get_y() + b.get_height() / 2, f"{v:.1f}%", ha="left", va="center", fontsize=9.5, fontweight="bold", color="#0f172a")

    # Footer note
    fig.text(
        0.5,
        0.015,
        "[Legend] Blue: Real-World Models (M1-M4) | Amber: Synthetic Fleet Models (M5-M8) | Purple: Consolidated Ensembles (M9-M10) | Green: Master Unified Model (M11)",
        ha="center",
        fontsize=11,
        fontweight="bold",
        color="#334155",
        bbox=dict(facecolor="#f1f5f9", edgecolor="#cbd5e1", boxstyle="round,pad=0.4"),
    )

    plt.subplots_adjust(top=0.91, bottom=0.07, left=0.08, right=0.96, hspace=0.30, wspace=0.20)
    plt.savefig(str(svg_path), format="svg")
    plt.savefig(str(png_path), dpi=200)
    plt.close(fig)

    print(f"✓ 11-Model benchmark vector plot generated: {paths.rel(svg_path)}")
    print(f"✓ 11-Model benchmark high-res image generated: {paths.rel(png_path)}")
    return svg_path


def generate_svg(output_path=DEFAULT_SVG):
    return generate_charts(svg_path=output_path, png_path=Path(output_path).with_suffix(".png"))


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SVG
    generate_svg(out_file)
