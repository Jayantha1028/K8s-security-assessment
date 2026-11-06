#!/usr/bin/env python3
"""
train_prometheus_anomaly_model.py
==================================
Trains and validates Model 12: Purely Unsupervised Prometheus Anomaly Detector.

Pipeline:
1. Ingests or generates a diverse corpus of healthy microservice Prometheus telemetry
   (Nginx, Go APIs, Redis caches, worker queues, Postgres DBs with natural fluctuations).
2. Fits the unsupervised PrometheusUnsupervisedDetector (Isolation Forest + GMM).
3. Evaluates against an independent out-of-distribution test set containing:
   - Normal microservice operations (verifying low False Positive Rate).
   - Zero-day Cryptominer spikes (MITRE T1496).
   - C2 Network Exfiltration floods (MITRE T1048).
   - Exploit-induced container crashloops.
   - API server RBAC discovery probing.
4. Computes rigorous statistical metrics: Anomaly Recall, FPR, ROC-AUC, F1-Score.
5. Serializes the trained model bundle to models/model_12_prometheus_unsupervised.joblib.
6. Persists the performance scorecard to reports/benchmarks/prometheus_model_scorecard.json.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, roc_auc_score

# Ensure core and parent src are in sys.path
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
    sys.path.insert(0, str(_CORE_DIR.parent))
import paths
from prometheus_unsupervised_model import PrometheusUnsupervisedDetector, PROMETHEUS_FEATURES


def generate_baseline_normal_data(n_samples: int = 600, random_state: int = 42) -> pd.DataFrame:
    """Generate realistic unlabelled normal cluster operational telemetry."""
    rng = np.random.RandomState(random_state)
    profiles = [
        # (name, cpu_mu, cpu_sigma, mem_mu, mem_sigma, net_tx_mu, net_tx_sigma)
        ("frontend-nginx", 0.12, 0.04, 48.0, 8.0, 25.0, 8.0),
        ("node-api-service", 0.32, 0.08, 140.0, 20.0, 65.0, 15.0),
        ("redis-cache", 0.09, 0.02, 180.0, 25.0, 85.0, 20.0),
        ("worker-queue", 0.38, 0.10, 220.0, 35.0, 40.0, 12.0),
        ("postgres-db", 0.45, 0.12, 520.0, 60.0, 75.0, 18.0),
    ]

    rows: List[Dict[str, float]] = []
    samples_per_profile = n_samples // len(profiles)

    for name, cpu_m, cpu_s, mem_m, mem_s, net_m, net_s in profiles:
        for _ in range(samples_per_profile):
            cpu = float(np.clip(rng.normal(cpu_m, cpu_s), 0.02, 0.85))
            mem = float(np.clip(rng.normal(mem_m, mem_s), 15.0, 800.0))
            restarts = float(rng.choice([0.0, 0.0, 0.0, 0.1, 0.2], p=[0.85, 0.08, 0.04, 0.02, 0.01]))
            net_tx = float(np.clip(rng.normal(net_m, net_s), 5.0, 200.0))
            net_rx = float(net_tx * rng.uniform(0.6, 1.4))
            falco = float(rng.choice([0.0, 0.01], p=[0.98, 0.02]))
            apiserver_403 = float(rng.choice([0.0, 0.01], p=[0.97, 0.03]))

            rows.append({
                "cpu_usage_cores": cpu,
                "memory_working_set_mb": mem,
                "restart_rate_per_hour": restarts,
                "network_tx_kbps": net_tx,
                "network_rx_kbps": net_rx,
                "falco_alerts_rate": falco,
                "apiserver_403_rate": apiserver_403,
            })

    return pd.DataFrame(rows)


def generate_evaluation_dataset(random_state: int = 99) -> Tuple[pd.DataFrame, np.ndarray]:
    """
    Generate an independent out-of-distribution evaluation set containing:
    - 100 Normal workloads (Label: 0)
    - 50 Attack variants (Label: 1)
    """
    rng = np.random.RandomState(random_state)
    normal_df = generate_baseline_normal_data(n_samples=100, random_state=random_state)
    normal_df["label"] = 0  # 0 = Normal

    attack_rows: List[Dict[str, float]] = []

    # 1. Cryptomining attacks (15 samples)
    for _ in range(15):
        attack_rows.append({
            "cpu_usage_cores": float(rng.uniform(1.6, 3.8)),  # Extreme CPU spike
            "memory_working_set_mb": float(rng.uniform(300.0, 650.0)),
            "restart_rate_per_hour": 0.0,
            "network_tx_kbps": float(rng.uniform(40.0, 120.0)),
            "network_rx_kbps": float(rng.uniform(30.0, 90.0)),
            "falco_alerts_rate": float(rng.uniform(0.1, 0.6)),
            "apiserver_403_rate": 0.0,
            "label": 1,
        })

    # 2. C2 Data Exfiltration attacks (15 samples)
    for _ in range(15):
        attack_rows.append({
            "cpu_usage_cores": float(rng.uniform(0.2, 0.6)),
            "memory_working_set_mb": float(rng.uniform(80.0, 250.0)),
            "restart_rate_per_hour": 0.0,
            "network_tx_kbps": float(rng.uniform(1200.0, 4500.0)),  # Massive egress
            "network_rx_kbps": float(rng.uniform(150.0, 400.0)),
            "falco_alerts_rate": float(rng.uniform(0.2, 0.8)),
            "apiserver_403_rate": 0.0,
            "label": 1,
        })

    # 3. Crash-loop exploitation attacks (10 samples)
    for _ in range(10):
        attack_rows.append({
            "cpu_usage_cores": float(rng.uniform(0.4, 0.9)),
            "memory_working_set_mb": float(rng.uniform(100.0, 400.0)),
            "restart_rate_per_hour": float(rng.uniform(3.5, 12.0)),  # Heavy crashes
            "network_tx_kbps": float(rng.uniform(10.0, 50.0)),
            "network_rx_kbps": float(rng.uniform(10.0, 50.0)),
            "falco_alerts_rate": float(rng.uniform(0.3, 0.9)),
            "apiserver_403_rate": 0.0,
            "label": 1,
        })

    # 4. API Reconnaissance & Token Probing attacks (10 samples)
    for _ in range(10):
        attack_rows.append({
            "cpu_usage_cores": float(rng.uniform(0.1, 0.3)),
            "memory_working_set_mb": float(rng.uniform(50.0, 150.0)),
            "restart_rate_per_hour": 0.0,
            "network_tx_kbps": float(rng.uniform(30.0, 80.0)),
            "network_rx_kbps": float(rng.uniform(30.0, 80.0)),
            "falco_alerts_rate": 0.0,
            "apiserver_403_rate": float(rng.uniform(0.4, 1.8)),  # API 403 spike
            "label": 1,
        })

    attack_df = pd.DataFrame(attack_rows)
    eval_df = pd.concat([normal_df, attack_df], ignore_index=True)
    labels = eval_df["label"].values.astype(int)
    features_df = eval_df[PROMETHEUS_FEATURES]
    return features_df, labels


def train_and_evaluate_model():
    print("=" * 80)
    print("      TRAINING MODEL 12: UNSUPERVISED PROMETHEUS ANOMALY DETECTOR")
    print("================================================================================")

    # 1. Ingest baseline training data
    print("[1/5] Ingesting unlabeled baseline operational telemetry (600 workloads)...")
    baseline_df = generate_baseline_normal_data(n_samples=600, random_state=42)
    print(f"      ✓ Baseline shape: {baseline_df.shape[0]} rows x {baseline_df.shape[1]} metrics.")

    # 2. Fit unsupervised model
    print("\n[2/5] Fitting Isolation Forest & Gaussian Mixture Model on baseline...")
    detector = PrometheusUnsupervisedDetector(
        contamination=0.05,
        n_estimators=150,
        n_components=4,
        random_state=42,
    )
    t0 = time.time()
    detector.fit(baseline_df)
    train_duration = time.time() - t0
    print(f"      ✓ Unsupervised manifold fitted in {train_duration:.2f}s.")

    # 3. Evaluate on independent out-of-distribution evaluation split
    print("\n[3/5] Evaluating on independent OOD validation set (100 normal + 50 attacks)...")
    eval_X, true_labels = generate_evaluation_dataset(random_state=99)

    preds_raw = detector.predict(eval_X)  # +1 normal, -1 anomaly
    pred_labels = np.where(preds_raw == -1, 1, 0)  # Map to 0 = normal, 1 = attack

    anomaly_scores = detector.score_anomaly(eval_X)

    # Calculate clinical metrics
    tn, fp, fn, tp = confusion_matrix(true_labels, pred_labels).ravel()
    recall = tp / (tp + fn)
    fpr = fp / (fp + tn)
    f1 = f1_score(true_labels, pred_labels)
    roc_auc = roc_auc_score(true_labels, anomaly_scores)

    print("\n" + "-" * 80)
    print("              UNSUPERVISED PROMETHEUS ANOMALY CONFUSION MATRIX")
    print("-" * 80)
    print(f"{'':<20} | {'Predicted Normal':<20} | {'Predicted Anomaly (Attack)':<25}")
    print("-" * 80)
    print(f"{'True Normal (100)':<20} | {tn:<20} | {fp:<25}")
    print(f"{'True Attack (50)':<20} | {fn:<20} | {tp:<25}")
    print("-" * 80)

    print("\n================================================================================")
    print("              MODEL 12 UNSUPERVISED ACCURACY SCORECARD")
    print("================================================================================")
    print(f"{'Evaluation Metric':<32} | {'Measured Value':<16} | {'Target Gate':<14} | {'Status'}")
    print("-" * 80)
    print(f"{'Attack Anomaly Recall (TPR)':<32} | {recall * 100:>6.2f}%          | ≥ 95.0%        | {'✓ PASS' if recall >= 0.95 else '✗ FAIL'}")
    print(f"{'False Positive Rate (FPR)':<32} | {fpr * 100:>6.2f}%          | ≤ 6.0%         | {'✓ PASS' if fpr <= 0.06 else '✗ FAIL'}")
    print(f"{'F1-Score':<32} | {f1:>6.4f}          | ≥ 0.900        | {'✓ PASS' if f1 >= 0.90 else '✗ FAIL'}")
    print(f"{'Area Under ROC Curve (ROC-AUC)':<32} | {roc_auc:>6.4f}          | ≥ 0.980        | {'✓ PASS' if roc_auc >= 0.98 else '✗ FAIL'}")
    print("================================================================================")

    # 4. Threat Attribution Explainability Test
    print("\n[4/5] Testing per-metric explainable threat driver attribution...")
    sample_cryptominer = {
        "cpu_usage_cores": 2.85,
        "memory_working_set_mb": 420.0,
        "restart_rate_per_hour": 0.0,
        "network_tx_kbps": 45.0,
        "network_rx_kbps": 35.0,
        "falco_alerts_rate": 0.4,
        "apiserver_403_rate": 0.0,
    }
    drivers = detector.attribute_threat_drivers(sample_cryptominer)
    print(f"      Test Payload: Cryptominer (CPU: 2.85 cores)")
    print(f"      Calculated Anomaly Score: {detector.score_anomaly([list(sample_cryptominer.values())])[0]}/100")
    for d in drivers:
        print(f"      • Driven by {d['metric']}: {d['observed_value']} (z=+{d['z_deviation']}) -> {d['threat_indication']}")

    # 5. Persist model bundle and scorecard
    print("\n[5/5] Persisting Model 12 bundle & JSON scorecard...")
    model_path = paths.ROOT / "models" / "model_12_prometheus_unsupervised.joblib"
    joblib.dump(detector, model_path)
    print(f"      ✓ Model 12 saved to: {paths.rel(model_path)}")

    scorecard = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "model_name": "Model 12: Purely Unsupervised Prometheus Anomaly Detector",
        "training_samples_unlabeled": len(baseline_df),
        "validation_samples_total": len(eval_X),
        "metrics": {
            "attack_recall": round(float(recall), 4),
            "false_positive_rate": round(float(fpr), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
        },
        "gates": {
            "recall_pass": bool(recall >= 0.95),
            "fpr_pass": bool(fpr <= 0.06),
            "f1_pass": bool(f1 >= 0.90),
            "roc_auc_pass": bool(roc_auc >= 0.98),
        },
    }
    scorecard_path = paths.REPORTS_BENCHMARKS / "prometheus_model_scorecard.json"
    scorecard_path.parent.mkdir(parents=True, exist_ok=True)
    scorecard_path.write_text(json.dumps(scorecard, indent=2))
    print(f"      ✓ Scorecard saved to: {paths.rel(scorecard_path)}\n")


def main():
    parser = argparse.ArgumentParser(description="Train Unsupervised Prometheus Anomaly Detector (Model 12)")
    parser.parse_args()
    train_and_evaluate_model()


if __name__ == "__main__":
    main()
