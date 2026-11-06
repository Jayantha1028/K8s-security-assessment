#!/usr/bin/env python3
"""
evaluate_prometheus_anomalies.py
=================================
Live & Batch Ingestion Evaluator for Model 12 (Unsupervised Prometheus Anomaly Detector).

Reads telemetry from data/raw/telemetry/prometheus_runtime_metrics.json (or queries
Prometheus via collect_prometheus.py), inferences Model 12, and computes:
- Runtime Anomaly Score (0.0 to 100.0)
- Classification Status: NORMAL (Score < 40) vs CRITICAL_ANOMALY (Score >= 40)
- Explainable Root-Cause Drivers (e.g. CPU spike, exfiltration, crashloops, 403 scan)

Outputs:
- Terminal ASCII Clinical Audit Table
- JSON Assessment: reports/benchmarks/prometheus_runtime_eval.json
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List
import joblib
import pandas as pd

# Ensure core and parent src are in sys.path
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
    sys.path.insert(0, str(_CORE_DIR.parent))
import paths
from prometheus_unsupervised_model import PrometheusUnsupervisedDetector, PROMETHEUS_FEATURES


def evaluate_telemetry_file(
    input_file: Path,
    model_path: Path,
    output_json: Path,
) -> Dict[str, Any]:
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model 12 artifact missing at {model_path}. "
            "Run 'python3 src/models/train_prometheus_anomaly_model.py' first."
        )

    if not input_file.exists():
        raise FileNotFoundError(
            f"Telemetry file missing at {input_file}. "
            "Run 'python3 src/data/collect_prometheus.py' first."
        )

    detector: PrometheusUnsupervisedDetector = joblib.load(model_path)
    raw_payload = json.loads(input_file.read_text(encoding="utf-8"))
    telemetry_list = raw_payload.get("telemetry", [])

    if not telemetry_list:
        print("⚠ Telemetry file contains no workloads.")
        return {}

    eval_results: List[Dict[str, Any]] = []

    print("=" * 90)
    print("      MODEL 12: LIVE PROMETHEUS UNSUPERVISED ANOMALY AUDIT")
    print("=" * 90)
    print(f"Model Artifact  : {paths.rel(model_path)}")
    print(f"Source Telemetry: {paths.rel(input_file)} (Collection Mode: {raw_payload.get('collection_mode', 'UNKNOWN')})")
    print(f"Timestamp       : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("-" * 90)
    print(f"{'Namespace/Workload':<28} | {'Anomaly Score':<14} | {'Status':<18} | {'Primary Threat Driver'}")
    print("-" * 90)

    for item in telemetry_list:
        tag = f"{item.get('namespace', 'default')}/{item.get('workload', 'unknown')}"
        feat_dict = {f: float(item.get(f, 0.0)) for f in PROMETHEUS_FEATURES}
        df_row = pd.DataFrame([feat_dict])

        score = float(detector.score_anomaly(df_row)[0])
        pred = int(detector.predict(df_row)[0])
        status = "CRITICAL_ANOMALY" if pred == -1 else "NORMAL"

        drivers = detector.attribute_threat_drivers(feat_dict)
        top_driver_str = "None (Within Baseline)"
        if drivers:
            d = drivers[0]
            top_driver_str = f"{d['metric']} (z=+{d['z_deviation']}) -> {d['threat_indication']}"

        eval_results.append({
            "namespace": item.get("namespace", "default"),
            "workload": item.get("workload", "unknown"),
            "anomaly_score": round(score, 2),
            "status": status,
            "is_anomaly": bool(pred == -1),
            "threat_drivers": drivers,
            "raw_telemetry": feat_dict,
        })

        status_display = f"\033[91m{status}\033[0m" if pred == -1 else f"\033[92m{status}\033[0m"
        print(f"{tag:<28} | {score:>5.1f} / 100    | {status_display:<27} | {top_driver_str}")

    print("=" * 90)

    summary_payload = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "model": "Model 12: Purely Unsupervised Prometheus Anomaly Detector",
        "workloads_evaluated": len(eval_results),
        "anomalies_detected": sum(1 for r in eval_results if r["is_anomaly"]),
        "evaluations": eval_results,
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(summary_payload, indent=2))
    print(f"✓ Anomaly evaluation JSON saved to: {paths.rel(output_json)}\n")
    return summary_payload


def main():
    parser = argparse.ArgumentParser(description="Evaluate Live Prometheus Telemetry with Model 12")
    parser.add_argument(
        "--input",
        default=str(paths.RAW / "telemetry" / "prometheus_runtime_metrics.json"),
        help="Input Prometheus telemetry JSON path",
    )
    parser.add_argument(
        "--model",
        default=str(paths.ROOT / "models" / "model_12_prometheus_unsupervised.joblib"),
        help="Path to trained Model 12 bundle",
    )
    parser.add_argument(
        "--output",
        default=str(paths.REPORTS_BENCHMARKS / "prometheus_runtime_eval.json"),
        help="Output evaluation JSON path",
    )
    args = parser.parse_args()

    evaluate_telemetry_file(
        input_file=Path(args.input),
        model_path=Path(args.model),
        output_json=Path(args.output),
    )


if __name__ == "__main__":
    main()
