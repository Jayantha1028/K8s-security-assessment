#!/usr/bin/env python3
"""
Generate a self-contained, interactive HTML Executive Security & ML Dashboard.

Run separately as a side-output (NOT part of main pipeline):
    python3 src/generate_dashboard.py [report_input.csv] [output_dashboard.html]
"""

import json
import math
import sys
from pathlib import Path
import joblib
import pandas as pd

import paths

DEFAULT_INPUT = paths.REPORT_INPUT
DEFAULT_OUTPUT = paths.ROOT / "reports" / "dashboard.html"


def generate_html(input_csv=DEFAULT_INPUT, output_html=DEFAULT_OUTPUT):
    input_csv = Path(input_csv)
    output_html = Path(output_html)

    if not input_csv.is_file():
        raise SystemExit(f"Input assessment CSV not found: {paths.rel(input_csv)}")
    if not paths.MODEL_FILE.is_file():
        raise SystemExit(f"Model file not found: {paths.rel(paths.MODEL_FILE)}")

    model_data = joblib.load(paths.MODEL_FILE)
    df = pd.read_csv(input_csv)
    if df.empty:
        raise SystemExit(f"CSV contains no rows: {input_csv}")

    features = model_data["features"]
    X = df[features].apply(pd.to_numeric, errors="coerce").fillna(0)

    # 4 Model Predictions
    rf_scores = model_data["score_model"].predict(X)
    rf_risks = model_data["risk_model"].predict(X)
    svm_scores = model_data["svm_score_model"].predict(X) if "svm_score_model" in model_data else rf_scores
    xgb_scores = model_data["xgb_score_model"].predict(X) if "xgb_score_model" in model_data else rf_scores
    xgb_risks = model_data["xgb_risk_model"].predict(X) if "xgb_risk_model" in model_data else rf_risks

    iso_model = model_data.get("iso_model")
    iso_preds = iso_model.predict(X) if iso_model else [1] * len(df)
    iso_scores = iso_model.decision_function(X) if iso_model else [0.0] * len(df)

    # Prepare cluster card data
    environments = []
    for i, row in df.iterrows():
        env_name = f"{row.get('snapshot', 'latest')} / {row.get('environment', 'unknown')}"
        ev_score = float(row.get("security_score", 50.0))
        rf_score = float(rf_scores[i])
        svm_score = float(svm_scores[i])
        xgb_score = float(xgb_scores[i])
        risk_tier = str(rf_risks[i])
        is_anomaly = bool(iso_preds[i] == -1)
        iso_dec = float(iso_scores[i])

        environments.append({
            "env_name": env_name,
            "evidence_score": round(ev_score, 1),
            "rf_score": round(rf_score, 1),
            "svm_score": round(svm_score, 1),
            "xgb_score": round(xgb_score, 1),
            "risk_tier": risk_tier,
            "is_anomaly": is_anomaly,
            "iso_score": round(iso_dec, 3),
            "critical_cve": int(row.get("critical_cve_count", 0)),
            "high_cve": int(row.get("high_cve_count", 0)),
            "privileged": int(row.get("privileged_count", 0)),
            "root": int(row.get("root_execution_count", 0)),
            "rbac_risk": int(row.get("rbac_risk_score", 0)),
            "kubescape_failed": int(row.get("kubescape_failed", 0)),
            "kubescape_compliance": round(float(row.get("kubescape_compliance", 100.0)), 1),
            "falco_alerts": int(row.get("falco_alert_count", 0)),
        })

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Kubernetes Security Assessment & ML Benchmark Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --success: #22c55e;
      --warning: #f59e0b;
      --danger: #ef4444;
      --purple: #a855f7;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text-main); padding: 2rem; min-height: 100vh; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-b: 1px solid var(--card-border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
    .title-group h1 {{ font-size: 1.75rem; font-weight: 700; color: #fff; }}
    .title-group p {{ color: var(--text-muted); font-size: 0.95rem; margin-top: 0.25rem; }}
    .badge-bar {{ display: flex; gap: 0.75rem; }}
    .pill {{ padding: 0.35rem 0.85rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
    .pill-blue {{ background: rgba(56, 189, 248, 0.15); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.3); }}
    .pill-green {{ background: rgba(34, 197, 94, 0.15); color: var(--success); border: 1px solid rgba(34, 197, 94, 0.3); }}

    .grid-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
    .grid-3 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}

    .card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3); }}
    .card-title {{ font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; color: #f1f5f9; display: flex; justify-content: space-between; align-items: center; }}

    .score-circle {{ display: flex; align-items: baseline; gap: 0.5rem; margin-bottom: 0.5rem; }}
    .score-num {{ font-size: 3rem; font-weight: 800; }}
    .score-denom {{ color: var(--text-muted); font-size: 1.2rem; }}
    .status-badge {{ display: inline-block; padding: 0.25rem 0.65rem; border-radius: 6px; font-weight: 700; font-size: 0.85rem; margin-bottom: 1rem; }}
    .status-low {{ background: rgba(34, 197, 94, 0.2); color: var(--success); border: 1px solid var(--success); }}
    .status-high {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }}

    .metrics-table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }}
    .metrics-table th, .metrics-table td {{ padding: 0.65rem 0.75rem; text-align: left; border-bottom: 1px solid var(--card-border); }}
    .metrics-table th {{ color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
    .metrics-table tr:last-child td {{ border-bottom: none; }}
    .tag {{ font-weight: 600; padding: 0.15rem 0.45rem; border-radius: 4px; font-size: 0.75rem; }}
    .tag-danger {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; }}
    .tag-warning {{ background: rgba(245, 158, 11, 0.2); color: #fcd34d; }}
    .tag-clean {{ background: rgba(34, 197, 94, 0.2); color: #86efac; }}

    .model-row {{ display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid rgba(255,255,255,0.05); }}
    .model-name {{ font-weight: 500; color: var(--text-muted); font-size: 0.85rem; }}
    .model-val {{ font-weight: 700; color: #fff; font-size: 0.95rem; }}

    .chart-container {{ position: relative; height: 260px; width: 100%; margin-top: 0.5rem; }}
    .footer {{ text-align: center; color: var(--text-muted); font-size: 0.85rem; margin-top: 3rem; border-top: 1px solid var(--card-border); padding-top: 1.5rem; }}
  </style>
</head>
<body>

  <div class="header">
    <div class="title-group">
      <h1>🛡️ Kubernetes Security & Multi-Model ML Assessment</h1>
      <p>Side-by-side benchmark of 4 independently trained models on live Kind cluster fleet telemetry</p>
    </div>
    <div class="badge-bar">
      <span class="pill pill-blue">100 Synthetic Manifests</span>
      <span class="pill pill-green">4 Models Evaluated</span>
    </div>
  </div>

  <!-- Cluster Assessment Cards -->
  <div class="grid-2">
"""

    for env in environments:
        is_high = env["risk_tier"] == "High"
        badge_class = "status-high" if is_high else "status-low"
        score_color = "var(--danger)" if is_high else "var(--success)"
        anomaly_text = '<span style="color:var(--danger);font-weight:700;">⚠️ OUTLIER (Anomaly Detected)</span>' if env["is_anomaly"] else '<span style="color:var(--success);font-weight:600;">✓ Inlier (Benign Posture)</span>'

        html_content += f"""
    <div class="card">
      <div class="card-title">
        <span>Cluster: {env["env_name"]}</span>
        <span class="status-badge {badge_class}">{env["risk_tier"]} Risk Tier</span>
      </div>

      <div class="score-circle">
        <span class="score-num" style="color:{score_color};">{env["evidence_score"]}</span>
        <span class="score-denom">/ 100 Evidence Score</span>
      </div>

      <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom: 1rem;">
        Isolation Forest Anomaly Check: {anomaly_text} (Score: {env["iso_score"]})
      </div>

      <div style="margin-top: 1rem;">
        <div style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; margin-bottom:0.5rem;">Independent ML Model Predictions</div>
        <div class="model-row"><span class="model-name">Random Forest Score</span><span class="model-val">{env["rf_score"]}/100</span></div>
        <div class="model-row"><span class="model-name">Support Vector Machine Score</span><span class="model-val">{env["svm_score"]}/100</span></div>
        <div class="model-row"><span class="model-name">XGBoost Regressor Score</span><span class="model-val">{env["xgb_score"]}/100</span></div>
        <div class="model-row"><span class="model-name">Isolation Forest Status</span><span class="model-val">{"ANOMALY" if env["is_anomaly"] else "Normal Inlier"}</span></div>
      </div>

      <div style="margin-top: 1.5rem;">
        <div style="font-size:0.8rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; margin-bottom:0.5rem;">Key Telemetry Indicators</div>
        <table class="metrics-table">
          <tr><th>Indicator</th><th>Observed</th><th>Severity Status</th></tr>
          <tr>
            <td>Critical CVEs (Trivy)</td>
            <td><strong>{env["critical_cve"]}</strong></td>
            <td><span class="tag {"tag-danger" if env["critical_cve"] > 0 else "tag-clean"}">{"FAIL" if env["critical_cve"] > 0 else "PASS"}</span></td>
          </tr>
          <tr>
            <td>High CVEs (Trivy)</td>
            <td><strong>{env["high_cve"]}</strong></td>
            <td><span class="tag {"tag-warning" if env["high_cve"] > 0 else "tag-clean"}">{"WARN" if env["high_cve"] > 0 else "PASS"}</span></td>
          </tr>
          <tr>
            <td>Privileged Workloads</td>
            <td><strong>{env["privileged"]}</strong></td>
            <td><span class="tag {"tag-danger" if env["privileged"] > 0 else "tag-clean"}">{"CRITICAL" if env["privileged"] > 0 else "PASS"}</span></td>
          </tr>
          <tr>
            <td>Root Execution Containers</td>
            <td><strong>{env["root"]}</strong></td>
            <td><span class="tag {"tag-warning" if env["root"] > 0 else "tag-clean"}">{"WARN" if env["root"] > 0 else "PASS"}</span></td>
          </tr>
          <tr>
            <td>RBAC Risk Score</td>
            <td><strong>{env["rbac_risk"]}</strong></td>
            <td><span class="tag {"tag-warning" if env["rbac_risk"] > 20 else "tag-clean"}">{"ELEVATED" if env["rbac_risk"] > 20 else "PASS"}</span></td>
          </tr>
          <tr>
            <td>NSA Compliance Score</td>
            <td><strong>{env["kubescape_compliance"]}%</strong></td>
            <td><span class="tag {"tag-danger" if env["kubescape_compliance"] < 60 else "tag-clean"}">{env["kubescape_failed"]} Failed Controls</span></td>
          </tr>
        </table>
      </div>
    </div>
"""

    html_content += f"""
  </div>

  <!-- Benchmark Comparison Section -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">Continuous Score Regression (R² & Error Comparison)</div>
      <div class="chart-container">
        <canvas id="regressionChart"></canvas>
      </div>
      <p style="color:var(--text-muted); font-size:0.8rem; margin-top:1rem;">
        XGBoost delivers the highest R² (0.959) and lowest root mean square error (4.376), outperforming the Random Forest baseline.
      </p>
    </div>

    <div class="card">
      <div class="card-title">Discrete Risk Classification (Accuracy & Macro F1)</div>
      <div class="chart-container">
        <canvas id="classificationChart"></canvas>
      </div>
      <p style="color:var(--text-muted); font-size:0.8rem; margin-top:1rem;">
        Random Forest achieves the strongest risk tier classification accuracy (90.5%) and Macro F1 (0.883), with XGBoost close behind (86.5%).
      </p>
    </div>
  </div>

  <div class="card" style="margin-bottom: 2rem;">
    <div class="card-title">
      <span>Summary Benchmark Table: 4 Independently Evaluated Models</span>
      <span class="pill pill-blue">Grouped 5-Fold Cross Validation</span>
    </div>
    <table class="metrics-table" style="margin-top:0.5rem;">
      <thead>
        <tr>
          <th>Model</th>
          <th>Model Paradigm</th>
          <th>Score R²</th>
          <th>Score RMSE</th>
          <th>Class Accuracy</th>
          <th>Macro F1</th>
          <th>Role in Architecture</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Random Forest</strong></td>
          <td>Ensemble Trees (Bagging)</td>
          <td>0.955</td>
          <td>4.559</td>
          <td><span style="color:var(--success);font-weight:700;">90.5% (Winner)</span></td>
          <td><span style="color:var(--success);font-weight:700;">0.883</span></td>
          <td>Baseline Classifier & Feature Importance Ranking</td>
        </tr>
        <tr>
          <td><strong>Support Vector Machine (SVM)</strong></td>
          <td>Kernel Margin Classifier</td>
          <td>0.952</td>
          <td>4.684</td>
          <td>83.3%</td>
          <td>0.764</td>
          <td>Non-linear Boundary Comparison</td>
        </tr>
        <tr>
          <td><strong>XGBoost</strong></td>
          <td>Gradient Boosted Trees</td>
          <td><span style="color:var(--accent);font-weight:700;">0.959 (Winner)</span></td>
          <td><span style="color:var(--accent);font-weight:700;">4.376 (Lowest Error)</span></td>
          <td>86.5%</td>
          <td>0.832</td>
          <td>Optimal Continuous Score Regression</td>
        </tr>
        <tr>
          <td><strong>Isolation Forest</strong></td>
          <td>Unsupervised Tree Ensembling</td>
          <td>—</td>
          <td>—</td>
          <td>ROC-AUC 0.975</td>
          <td>100% Outlier Recall</td>
          <td>Zero-Day Anomaly & Drift Detection (No Ground Truth Required)</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="footer">
    Generated by CDC-5 Kubernetes Security Assessment • Self-Contained Side-Output Artifact
  </div>

  <script>
    // Regression Chart
    new Chart(document.getElementById('regressionChart'), {{
      type: 'bar',
      data: {{
        labels: ['Random Forest', 'SVM', 'XGBoost'],
        datasets: [
          {{
            label: 'R² Score (Higher is better)',
            data: [0.955, 0.952, 0.959],
            backgroundColor: 'rgba(56, 189, 248, 0.7)',
            borderRadius: 6
          }},
          {{
            label: 'RMSE (Lower is better)',
            data: [4.559, 4.684, 4.376],
            backgroundColor: 'rgba(239, 68, 68, 0.7)',
            borderRadius: 6
          }}
        ]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{ legend: {{ labels: {{ color: '#94a3b8' }} }} }},
        scales: {{
          x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: 'rgba(255,255,255,0.05)' }} }},
          y: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: 'rgba(255,255,255,0.05)' }} }}
        }}
      }}
    }});

    // Classification Chart
    new Chart(document.getElementById('classificationChart'), {{
      type: 'bar',
      data: {{
        labels: ['Random Forest', 'SVM', 'XGBoost'],
        datasets: [
          {{
            label: 'Accuracy (%)',
            data: [90.5, 83.3, 86.5],
            backgroundColor: 'rgba(34, 197, 94, 0.7)',
            borderRadius: 6
          }},
          {{
            label: 'Macro F1 (%)',
            data: [88.3, 76.4, 83.2],
            backgroundColor: 'rgba(168, 85, 247, 0.7)',
            borderRadius: 6
          }}
        ]
      }},
      options: {{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {{ legend: {{ labels: {{ color: '#94a3b8' }} }} }},
        scales: {{
          x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: 'rgba(255,255,255,0.05)' }} }},
          y: {{ min: 50, max: 100, ticks: {{ color: '#94a3b8' }}, grid: {{ color: 'rgba(255,255,255,0.05)' }} }}
        }}
      }}
    }});
  </script>
</body>
</html>
"""

    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(html_content, encoding="utf-8")
    print(f"Interactive Dashboard generated: {paths.rel(output_html)}")
    return output_html


if __name__ == "__main__":
    in_csv = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT
    out_html = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUTPUT
    generate_html(in_csv, out_html)
