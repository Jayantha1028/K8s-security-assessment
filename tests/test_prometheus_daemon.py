import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
for _sub in ['core', 'data', 'scanners', 'models', 'evaluation', 'reporting', 'integrations']:
    _p = str(ROOT / 'src' / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import paths
from prometheus_unsupervised_model import PrometheusUnsupervisedDetector, PROMETHEUS_FEATURES
from train_prometheus_anomaly_model import generate_baseline_normal_data
from run_prometheus_daemon import run_continuous_daemon, build_prometheus_exposition_text, LATEST_DAEMON_STATE


def setUpModule():
    os.chdir(ROOT)


class PrometheusDaemonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline_df = generate_baseline_normal_data(n_samples=200, random_state=42)
        cls.model = PrometheusUnsupervisedDetector(
            contamination=0.05,
            n_estimators=50,
            n_components=3,
            anomaly_score_threshold=40.0,
            random_state=42,
        )
        cls.model.fit(cls.baseline_df)

    def test_online_baseline_adaptive_update(self):
        initial_cpu_mean = float(self.model.feature_means[0])

        # Elevated but clean operational load (e.g. 0.40 cores)
        clean_load = pd.DataFrame([{
            "cpu_usage_cores": 0.40,
            "memory_working_set_mb": 60.0,
            "restart_rate_per_hour": 0.0,
            "network_tx_kbps": 30.0,
            "network_rx_kbps": 20.0,
            "falco_alerts_rate": 0.0,
            "apiserver_403_rate": 0.0,
        }])

        res = self.model.update_online_baseline(clean_load, alpha=0.10, max_anomaly_threshold=30.0)
        self.assertEqual(res["learned_samples"], 1)
        self.assertEqual(res["poisonous_rejected"], 0)
        self.assertEqual(res["status"], "BASELINE_UPDATED")

        # Mean should shift smoothly towards the new load
        updated_cpu_mean = float(self.model.feature_means[0])
        self.assertGreater(updated_cpu_mean, initial_cpu_mean)

    def test_online_baseline_anti_poisoning_guardrail(self):
        initial_means = self.model.feature_means.copy()

        # Severe cryptomining payload (should be rejected from baseline learning)
        poison_payload = pd.DataFrame([{
            "cpu_usage_cores": 3.5,
            "memory_working_set_mb": 500.0,
            "restart_rate_per_hour": 0.0,
            "network_tx_kbps": 40.0,
            "network_rx_kbps": 30.0,
            "falco_alerts_rate": 0.5,
            "apiserver_403_rate": 0.0,
        }])

        res = self.model.update_online_baseline(poison_payload, alpha=0.10, max_anomaly_threshold=30.0)
        self.assertEqual(res["learned_samples"], 0)
        self.assertEqual(res["poisonous_rejected"], 1)
        self.assertEqual(res["status"], "ALL_VETOED_BY_GUARDRAIL")

        # Baseline means must be preserved unchanged
        np.testing.assert_array_equal(self.model.feature_means, initial_means)

    def test_daemon_bounded_run_and_status_export(self):
        status_file = paths.REPORTS_METRICS / "prometheus_daemon_status.json"

        # Execute 2 bounded cycles
        run_continuous_daemon(
            interval=0.1,
            port=9197,
            url="http://localhost:9090",
            alpha=0.05,
            max_iterations=2,
            save_checkpoint=False,
        )

        self.assertTrue(status_file.exists())
        status_data = json.loads(status_file.read_text(encoding="utf-8"))
        self.assertGreaterEqual(status_data["cycle_count"], 2)
        self.assertGreater(status_data["total_workloads_monitored"], 0)

    def test_daemon_metrics_exposition_format(self):
        LATEST_DAEMON_STATE["cycle_count"] = 5
        LATEST_DAEMON_STATE["anomalies_intercepted_total"] = 2
        LATEST_DAEMON_STATE["clean_samples_learned_total"] = 8
        LATEST_DAEMON_STATE["workload_evaluations"] = [
            {"namespace": "default", "workload": "test-pod", "anomaly_score": 15.2, "is_anomaly": False}
        ]

        text = build_prometheus_exposition_text()
        self.assertIn("k8s_security_daemon_cycles_total 5", text)
        self.assertIn("k8s_security_daemon_anomalies_total 2", text)
        self.assertIn("k8s_security_daemon_clean_samples_learned_total 8", text)
        self.assertIn('k8s_security_prometheus_anomaly_score{namespace="default",workload="test-pod"} 15.20', text)


if __name__ == "__main__":
    unittest.main()
