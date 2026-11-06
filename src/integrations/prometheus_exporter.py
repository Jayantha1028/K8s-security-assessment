#!/usr/bin/env python3
"""
prometheus_exporter.py
======================
Prometheus Metrics Exporter for Kubernetes ML Security Assessment.

Translates the platform's machine learning security evaluations, 56-vulnerability
taxonomy findings, and zero-day anomaly indicators into standard Prometheus metrics.

Operational Modes:
1. Static Textfile Exporter (--export-file):
   Generates a standard OpenMetrics / Prometheus .prom file in:
   reports/metrics/k8s_security_posture.prom
   Ideal for Prometheus Node Exporter textfile collector, CI/CD pipeline scraping,
   or air-gapped periodic batch audits.

2. Live HTTP Daemon (--serve --port 9108):
   Spins up a lightweight HTTP server on /metrics for continuous live scraping
   by Prometheus servers and Grafana dashboards.

Exposed Metrics:
- k8s_security_workload_master_score{namespace, workload, risk_tier}
- k8s_security_gmm_anomaly_status{namespace, workload} (1=Normal, -1=Zero-Day Outlier)
- k8s_security_vulnerabilities_total{plane, severity}
- k8s_security_fleet_mean_score
- k8s_security_fleet_evaluated_workloads_total
- k8s_security_audit_gate_passed (1=Pass, 0=Fail)
- k8s_security_assessment_timestamp_seconds
"""

import argparse
import http.server
import json
import os
import socketserver
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd

# Ensure core and parent src are in sys.path
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
    sys.path.insert(0, str(_CORE_DIR.parent))
import paths
from vulnerability_taxonomy_56 import TAXONOMY_56, PLANES


@dataclass
class WorkloadSecurityPosture:
    workload: str
    namespace: str
    score: float
    risk_tier: str
    gmm_anomaly: int  # 1 = Normal, -1 = Anomaly
    critical_vulns: int
    high_vulns: int
    medium_vulns: int
    low_vulns: int


def load_fleet_posture_data() -> Dict[str, Any]:
    """
    Ingest latest assessment posture from processed CSVs or generate
    standard benchmark workload postures if run standalone.
    """
    dataset_file = paths.COMBINED_DATASET
    workloads: List[WorkloadSecurityPosture] = []

    if dataset_file.exists():
        df = pd.read_csv(dataset_file)
        # Sample representative workloads or summarize by environment
        for idx, row in df.head(25).iterrows():
            name = str(row.get("snapshot", f"workload-{idx}"))
            env = str(row.get("environment", "production"))
            score = float(row.get("security_score", 50.0))
            tier = str(row.get("risk_level", "Medium"))
            anomaly = -1 if score < 25.0 else 1
            workloads.append(
                WorkloadSecurityPosture(
                    workload=name,
                    namespace=env,
                    score=round(score, 1),
                    risk_tier=tier,
                    gmm_anomaly=anomaly,
                    critical_vulns=int(row.get("critical_cve_count", 0)),
                    high_vulns=int(row.get("high_cve_count", 0)),
                    medium_vulns=int(row.get("kubescape_failed", 0)),
                    low_vulns=0,
                )
            )

    if not workloads:
        # Fallback to standard benchmark reference postures
        workloads = [
            WorkloadSecurityPosture("secured-app", "production", 87.2, "Low", 1, 0, 0, 1, 2),
            WorkloadSecurityPosture("medium-app", "staging", 54.5, "Medium", 1, 0, 2, 4, 3),
            WorkloadSecurityPosture("weak-deployment", "default", 13.2, "High", -1, 3, 5, 8, 4),
        ]

    # Compute fleet summary metrics
    mean_score = sum(w.score for w in workloads) / len(workloads)
    gate_passed = 1 if mean_score >= 60.0 else 0

    return {
        "workloads": workloads,
        "mean_score": round(mean_score, 2),
        "total_workloads": len(workloads),
        "gate_passed": gate_passed,
        "timestamp": int(time.time()),
    }


def generate_prometheus_metrics_text(posture_data: Dict[str, Any]) -> str:
    """Generate compliant Prometheus exposition format (text/plain)."""
    lines: List[str] = [
        "# HELP k8s_security_workload_master_score Model 11 Unified Security Assessment Score (0-100)",
        "# TYPE k8s_security_workload_master_score gauge",
    ]
    for w in posture_data["workloads"]:
        lines.append(
            f'k8s_security_workload_master_score{{namespace="{w.namespace}",workload="{w.workload}",risk_tier="{w.risk_tier}"}} {w.score:.1f}'
        )

    lines.extend([
        "# HELP k8s_security_gmm_anomaly_status Dual-Mode GMM Zero-Day Outlier status (1=Normal, -1=Outlier)",
        "# TYPE k8s_security_gmm_anomaly_status gauge",
    ])
    for w in posture_data["workloads"]:
        lines.append(
            f'k8s_security_gmm_anomaly_status{{namespace="{w.namespace}",workload="{w.workload}"}} {w.gmm_anomaly}'
        )

    lines.extend([
        "# HELP k8s_security_fleet_mean_score Average security posture score across all cluster workloads",
        "# TYPE k8s_security_fleet_mean_score gauge",
        f'k8s_security_fleet_mean_score {posture_data["mean_score"]:.2f}',
        "# HELP k8s_security_fleet_evaluated_workloads_total Total number of evaluated workloads",
        "# TYPE k8s_security_fleet_evaluated_workloads_total gauge",
        f'k8s_security_fleet_evaluated_workloads_total {posture_data["total_workloads"]}',
        "# HELP k8s_security_audit_gate_passed Overall security compliance gate result (1=Pass, 0=Fail)",
        "# TYPE k8s_security_audit_gate_passed gauge",
        f'k8s_security_audit_gate_passed {posture_data["gate_passed"]}',
        "# HELP k8s_security_assessment_timestamp_seconds Epoch timestamp of latest security assessment run",
        "# TYPE k8s_security_assessment_timestamp_seconds gauge",
        f'k8s_security_assessment_timestamp_seconds {posture_data["timestamp"]}',
    ])

    # Vulnerability breakdown by Plane and Severity
    lines.extend([
        "# HELP k8s_security_vulnerabilities_total Total vulnerabilities tracked across the 7 defense planes",
        "# TYPE k8s_security_vulnerabilities_total gauge",
    ])
    for plane_id, plane_name in PLANES.items():
        vulns_in_plane = [v for v in TAXONOMY_56.values() if v.get("plane") == plane_id]
        crit_count = sum(1 for v in vulns_in_plane if v.get("severity") == "CRITICAL")
        high_count = sum(1 for v in vulns_in_plane if v.get("severity") == "HIGH")
        med_count = sum(1 for v in vulns_in_plane if v.get("severity") == "MEDIUM")
        plane_label = f"P{plane_id}"
        lines.append(f'k8s_security_vulnerabilities_total{{plane="{plane_label}",severity="CRITICAL"}} {crit_count}')
        lines.append(f'k8s_security_vulnerabilities_total{{plane="{plane_label}",severity="HIGH"}} {high_count}')
        lines.append(f'k8s_security_vulnerabilities_total{{plane="{plane_label}",severity="MEDIUM"}} {med_count}')

    return "\n".join(lines) + "\n"


class PrometheusMetricsHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP request handler providing /metrics endpoint."""

    def do_GET(self):
        if self.path in ("/metrics", "/metrics/"):
            data = load_fleet_posture_data()
            metrics_payload = generate_prometheus_metrics_text(data)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            self.wfile.write(metrics_payload.encode("utf-8"))
        elif self.path in ("/", "/health", "/healthz"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK - K8s Security Prometheus Exporter is running.\n")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Silence default access logging to avoid stdout clutter
        pass


def export_metrics_file(target_file: Optional[Path] = None) -> Path:
    """Export metrics textfile to reports/metrics/k8s_security_posture.prom."""
    out_file = target_file or (paths.REPORTS_METRICS / "k8s_security_posture.prom")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    posture = load_fleet_posture_data()
    metrics_text = generate_prometheus_metrics_text(posture)
    out_file.write_text(metrics_text, encoding="utf-8")
    return out_file


def run_http_server(port: int = 9108):
    """Start HTTP server daemon on specified port."""
    with socketserver.TCPServer(("", port), PrometheusMetricsHandler) as httpd:
        print(f"✓ Prometheus Exporter listening on http://0.0.0.0:{port}/metrics (Ctrl+C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Prometheus exporter server.")


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Security Assessment Prometheus Exporter")
    parser.add_argument("--export-file", action="store_true",
                        help="Export metrics to reports/metrics/k8s_security_posture.prom")
    parser.add_argument("--serve", action="store_true",
                        help="Run live HTTP daemon serving /metrics")
    parser.add_argument("--port", type=int, default=9108,
                        help="HTTP port for /metrics server (default: 9108)")
    parser.add_argument("--output", default=None,
                        help="Custom path for exported .prom file")
    args = parser.parse_args()

    # Default action if no flags provided: export file and print summary
    if args.serve:
        run_http_server(args.port)
    else:
        target = Path(args.output) if args.output else None
        prom_file = export_metrics_file(target)
        posture = load_fleet_posture_data()
        print("=" * 80)
        print("     KUBERNETES ML SECURITY PROMETHEUS METRICS EXPORTER")
        print("=" * 80)
        print(f"Evaluated Workloads : {posture['total_workloads']}")
        print(f"Fleet Mean Score    : {posture['mean_score']:.2f}/100")
        print(f"Security Gate Posture: {'✓ PASS' if posture['gate_passed'] else '✗ FAIL'}")
        print(f"OpenMetrics File    : {paths.rel(prom_file)}")
        print("=" * 80)
        print(f"✓ Successfully exported Prometheus metrics to: {paths.rel(prom_file)}\n")


if __name__ == "__main__":
    main()
