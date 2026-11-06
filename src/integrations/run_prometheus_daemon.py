#!/usr/bin/env python3
"""
run_prometheus_daemon.py
========================
Continuous Prometheus Streaming Anomaly Detector & Online Learning Daemon.

Runs continuously in the background (as a systemd service, Kubernetes sidecar,
or daemon process):
1. Ingests live Prometheus telemetry from running cluster containers on a configurable interval.
2. Inferences Model 12 (Purely Unsupervised Anomaly Detector) in real-time.
3. Detects & alerts on Zero-Day anomalies (Cryptomining, C2 Exfiltration, Crashloops, API Recon).
4. Continuous Online Learning: Updates the running baseline manifold (via Exponential Moving Average)
   on verified healthy telemetry so the model naturally adapts to organic cluster scaling.
5. Anti-Poisoning Guardrail: Rejects anomalous payloads from updating the model's memory.
6. Serves a live OpenMetrics endpoint on http://0.0.0.0:<port>/metrics for Grafana & Alertmanager.
"""

import argparse
import http.server
import json
import os
import signal
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import pandas as pd

# Ensure core and parent src are in sys.path
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
    sys.path.insert(0, str(_CORE_DIR.parent))
import paths
from collect_prometheus import PrometheusCollector
from prometheus_unsupervised_model import PrometheusUnsupervisedDetector, PROMETHEUS_FEATURES

# Global state shared between the daemon loop and the /metrics HTTP server
LATEST_DAEMON_STATE: Dict[str, Any] = {
    "cycle_count": 0,
    "last_cycle_timestamp": 0,
    "total_workloads_monitored": 0,
    "anomalies_intercepted_total": 0,
    "clean_samples_learned_total": 0,
    "workload_evaluations": [],
}


def build_prometheus_exposition_text() -> str:
    """Formats LATEST_DAEMON_STATE into standard Prometheus text format."""
    state = LATEST_DAEMON_STATE
    lines = [
        "# HELP k8s_security_daemon_cycles_total Total number of completed streaming assessment cycles",
        "# TYPE k8s_security_daemon_cycles_total counter",
        f"k8s_security_daemon_cycles_total {state['cycle_count']}",
        "# HELP k8s_security_daemon_anomalies_total Cumulative count of detected runtime attack anomalies",
        "# TYPE k8s_security_daemon_anomalies_total counter",
        f"k8s_security_daemon_anomalies_total {state['anomalies_intercepted_total']}",
        "# HELP k8s_security_daemon_clean_samples_learned_total Cumulative healthy samples absorbed via online learning",
        "# TYPE k8s_security_daemon_clean_samples_learned_total counter",
        f"k8s_security_daemon_clean_samples_learned_total {state['clean_samples_learned_total']}",
        "# HELP k8s_security_prometheus_anomaly_score Model 12 Real-Time Anomaly Score (0.0 to 100.0)",
        "# TYPE k8s_security_prometheus_anomaly_score gauge",
    ]
    for w in state.get("workload_evaluations", []):
        ns = w.get("namespace", "default")
        wl = w.get("workload", "unknown")
        score = w.get("anomaly_score", 0.0)
        lines.append(f'k8s_security_prometheus_anomaly_score{{namespace="{ns}",workload="{wl}"}} {score:.2f}')

    lines.extend([
        "# HELP k8s_security_prometheus_anomaly_status Binary Anomaly Flag (1=Normal, -1=Outlier)",
        "# TYPE k8s_security_prometheus_anomaly_status gauge",
    ])
    for w in state.get("workload_evaluations", []):
        ns = w.get("namespace", "default")
        wl = w.get("workload", "unknown")
        status_flag = -1 if w.get("is_anomaly", False) else 1
        lines.append(f'k8s_security_prometheus_anomaly_status{{namespace="{ns}",workload="{wl}"}} {status_flag}')

    return "\n".join(lines) + "\n"


class DaemonMetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/metrics", "/metrics/"):
            payload = build_prometheus_exposition_text()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))
        elif self.path in ("/", "/healthz", "/livez"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "RUNNING", "cycles": LATEST_DAEMON_STATE["cycle_count"]}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def start_metrics_server(port: int):
    """Run HTTP server in background thread."""
    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    try:
        httpd = ReusableTCPServer(("", port), DaemonMetricsHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return httpd
    except Exception as e:
        print(f"⚠ Warning: Could not bind metrics port {port}: {e}")
        return None


def run_continuous_daemon(
    interval: float = 15.0,
    port: int = 9108,
    url: str = "http://localhost:9090",
    alpha: float = 0.05,
    max_iterations: Optional[int] = None,
    save_checkpoint: bool = True,
):
    print("=" * 90)
    print("      CONTINUOUS PROMETHEUS STREAMING ANOMALY DETECTOR (MODEL 12 DAEMON)")
    print("=" * 90)
    print(f"Prometheus Scrape URL : {url}")
    print(f"Scrape / Learning Rate: Every {interval:.1f}s | Online EMA Alpha: {alpha}")
    print(f"Live /metrics Server  : http://0.0.0.0:{port}/metrics")
    print(f"Mode                  : {'Infinite Daemon (Ctrl+C to stop)' if not max_iterations else f'Bounded ({max_iterations} cycles)'}")
    print("=" * 90)

    # 1. Load Model 12
    model_path = paths.ROOT / "models" / "model_12_prometheus_unsupervised.joblib"
    if not model_path.exists():
        print("Model 12 artifact missing, training initial baseline now...")
        from train_prometheus_anomaly_model import train_and_evaluate_model
        train_and_evaluate_model()

    detector: PrometheusUnsupervisedDetector = joblib.load(model_path)
    collector = PrometheusCollector(base_url=url, timeout=3.0)

    # 2. Start HTTP server in background
    httpd = start_metrics_server(port)

    # 3. Setup log directories
    log_file = paths.ROOT / "logs" / "prometheus_daemon_alerts.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    status_file = paths.REPORTS_METRICS / "prometheus_daemon_status.json"
    status_file.parent.mkdir(parents=True, exist_ok=True)

    running = True

    def handle_sig(sig, frame):
        nonlocal running
        print("\n[DAEMON] Shutdown signal received. Performing graceful shutdown...")
        running = False

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    cycle = 0

    while running:
        cycle += 1
        t_start = time.time()
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        # A. Collect live telemetry
        raw_payload = collector.collect(allow_synthetic_fallback=True)
        telemetry_items = raw_payload.get("telemetry", [])

        if not telemetry_items:
            print(f"[{timestamp_str}] Cycle {cycle}: No running workloads discovered.")
            time.sleep(interval)
            continue

        # B. Construct batch DataFrame
        feat_rows = []
        metadata = []
        for item in telemetry_items:
            ns = item.get("namespace", "default")
            wl = item.get("workload", "unknown")
            metadata.append((ns, wl))
            feat_rows.append({f: float(item.get(f, 0.0)) for f in PROMETHEUS_FEATURES})

        batch_df = pd.DataFrame(feat_rows)

        # C. Real-Time Model 12 Inference
        scores = detector.score_anomaly(batch_df)
        preds = detector.predict(batch_df)

        evaluations = []
        anomalies_in_cycle = 0

        for i, (ns, wl) in enumerate(metadata):
            score = float(scores[i])
            is_anomaly = bool(preds[i] == -1)
            drivers = detector.attribute_threat_drivers(batch_df.iloc[i])

            if is_anomaly:
                anomalies_in_cycle += 1
                top_driver = drivers[0] if drivers else {"metric": "multi_metric", "threat_indication": "Unknown"}
                alert_msg = (
                    f"[{timestamp_str}] 🚨 CRITICAL RUNTIME ANOMALY DETECTED on {ns}/{wl} "
                    f"(Score: {score:.1f}/100) -> {top_driver.get('threat_indication')}"
                )
                print(f"\033[91m{alert_msg}\033[0m")
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(f"{alert_msg}\n")

            evaluations.append({
                "namespace": ns,
                "workload": wl,
                "anomaly_score": score,
                "is_anomaly": is_anomaly,
                "drivers": drivers,
            })

        # D. Continuous Online Learning on Clean Workloads
        update_result = detector.update_online_baseline(batch_df, alpha=alpha, max_anomaly_threshold=30.0)
        learned_count = update_result.get("learned_samples", 0)

        # E. Update Global Shared Daemon State
        LATEST_DAEMON_STATE["cycle_count"] = cycle
        LATEST_DAEMON_STATE["last_cycle_timestamp"] = int(time.time())
        LATEST_DAEMON_STATE["total_workloads_monitored"] = len(evaluations)
        LATEST_DAEMON_STATE["anomalies_intercepted_total"] += anomalies_in_cycle
        LATEST_DAEMON_STATE["clean_samples_learned_total"] += learned_count
        LATEST_DAEMON_STATE["workload_evaluations"] = evaluations

        # F. Persist state snapshot
        status_file.write_text(json.dumps(LATEST_DAEMON_STATE, indent=2))

        # Log Cycle Summary
        elapsed = time.time() - t_start
        print(
            f"[{timestamp_str}] Cycle {cycle:04d} | Monitored: {len(evaluations)} pods | "
            f"Anomalies: {anomalies_in_cycle} | Online Learned: +{learned_count} samples (EMA) | {elapsed:.2f}s"
        )

        if max_iterations and cycle >= max_iterations:
            print(f"\n[DAEMON] Target iterations ({max_iterations}) reached.")
            break

        # Sleep remaining time
        sleep_dur = max(0.0, interval - (time.time() - t_start))
        time.sleep(sleep_dur)

    # 4. Checkpoint updated model on shutdown
    if save_checkpoint:
        joblib.dump(detector, model_path)
        print(f"✓ Saved updated online-learned model checkpoint to: {paths.rel(model_path)}")

    if httpd:
        httpd.shutdown()
        httpd.server_close()
    print("Daemon stopped gracefully.")


def main():
    parser = argparse.ArgumentParser(description="Continuous Prometheus Anomaly Detector & Online Learning Daemon")
    parser.add_argument("--interval", type=float, default=15.0, help="Scrape & assessment interval in seconds")
    parser.add_argument("--port", type=int, default=9108, help="Exposition HTTP port (default: 9108)")
    parser.add_argument("--url", default="http://localhost:9090", help="Prometheus base URL")
    parser.add_argument("--alpha", type=float, default=0.05, help="Online learning EMA alpha")
    parser.add_argument("--iterations", type=int, default=None, help="Max cycles to run (None = infinite)")
    parser.add_argument("--no-save", action="store_true", help="Do not save updated model checkpoint on exit")
    args = parser.parse_args()

    run_continuous_daemon(
        interval=args.interval,
        port=args.port,
        url=args.url,
        alpha=args.alpha,
        max_iterations=args.iterations,
        save_checkpoint=not args.no_save,
    )


if __name__ == "__main__":
    main()
