import io
import os
import sys
import unittest
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
for _sub in ['core', 'data', 'scanners', 'models', 'evaluation', 'reporting', 'integrations']:
    _p = str(ROOT / 'src' / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import paths
from collect_prometheus import (
    PrometheusCollector,
    generate_synthetic_telemetry,
    WorkloadTelemetry,
    SECURITY_QUERIES,
)
from prometheus_exporter import (
    load_fleet_posture_data,
    generate_prometheus_metrics_text,
    export_metrics_file,
    PrometheusMetricsHandler,
)


def setUpModule():
    os.chdir(ROOT)


class PrometheusIntegrationTests(unittest.TestCase):
    def test_synthetic_telemetry_generation(self):
        records = generate_synthetic_telemetry(mock_anomalies=True)
        self.assertGreaterEqual(len(records), 3)

        # Secured app should have no anomalies
        secured = next(r for r in records if r.workload == "secured-app")
        self.assertFalse(secured.is_cpu_anomaly)
        self.assertFalse(secured.is_network_anomaly)
        self.assertEqual(secured.restart_rate_per_hour, 0.0)

        # Vulnerable app under attack should exhibit cryptomining & exfil flags
        vuln = next(r for r in records if r.workload == "vulnerable-app")
        self.assertTrue(vuln.is_cpu_anomaly)
        self.assertTrue(vuln.is_network_anomaly)
        self.assertTrue(vuln.is_restart_anomaly)
        self.assertGreater(vuln.cpu_usage_cores, 1.0)
        self.assertGreater(vuln.network_tx_kbps, 1000.0)

    def test_collector_offline_fallback(self):
        # Query an unreachable local port to test offline tolerance
        collector = PrometheusCollector(base_url="http://127.0.0.1:54321", timeout=0.1)
        self.assertFalse(collector.check_connection())

        payload = collector.collect(allow_synthetic_fallback=True)
        self.assertIn("SYNTHETIC_FALLBACK", payload["collection_mode"])
        self.assertGreaterEqual(payload["workloads_monitored"], 3)
        self.assertIn("telemetry", payload)

    def test_security_queries_syntax(self):
        self.assertIn("cpu_rate", SECURITY_QUERIES)
        self.assertIn("memory_mb", SECURITY_QUERIES)
        self.assertIn("restart_rate", SECURITY_QUERIES)
        self.assertIn("network_tx_kbps", SECURITY_QUERIES)
        self.assertIn("falco_rate", SECURITY_QUERIES)
        self.assertIn("apiserver_403", SECURITY_QUERIES)

    def test_prometheus_metrics_text_format(self):
        posture = load_fleet_posture_data()
        metrics_text = generate_prometheus_metrics_text(posture)

        # OpenMetrics / Prometheus compliance assertions
        self.assertIn("# HELP k8s_security_workload_master_score", metrics_text)
        self.assertIn("# TYPE k8s_security_workload_master_score gauge", metrics_text)
        self.assertIn("k8s_security_workload_master_score{", metrics_text)

        self.assertIn("# HELP k8s_security_gmm_anomaly_status", metrics_text)
        self.assertIn("k8s_security_fleet_mean_score", metrics_text)
        self.assertIn("k8s_security_vulnerabilities_total{plane=\"P1\"", metrics_text)
        self.assertIn("k8s_security_audit_gate_passed", metrics_text)

    def test_metrics_file_persistence(self):
        test_out = paths.ROOT / "reports" / "metrics" / "test_k8s_posture.prom"
        exported = export_metrics_file(test_out)
        self.assertTrue(exported.exists())
        content = exported.read_text(encoding="utf-8")
        self.assertIn("k8s_security_workload_master_score", content)
        if test_out.exists():
            test_out.unlink()

    def test_alerting_rules_yaml_syntax(self):
        rules_path = paths.ROOT / "config" / "prometheus" / "k8s_security_rules.yml"
        self.assertTrue(rules_path.exists(), "Alert rules file missing")
        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self.assertIn("groups", data)
        group = data["groups"][0]
        self.assertEqual(group["name"], "kubernetes_security_posture_alerts")
        alert_names = [r["alert"] for r in group.get("rules", [])]

        self.assertIn("K8sWorkloadHighSecurityRisk", alert_names)
        self.assertIn("K8sWorkloadZeroDayAnomaly", alert_names)
        self.assertIn("K8sCriticalVulnerabilitiesDetected", alert_names)
        self.assertIn("K8sFleetSecurityPostureDegraded", alert_names)
        self.assertIn("K8sCryptominingPrivilegeCorrelation", alert_names)


if __name__ == "__main__":
    unittest.main()
