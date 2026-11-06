import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
import joblib
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
from train_prometheus_anomaly_model import generate_baseline_normal_data, generate_evaluation_dataset
from evaluate_prometheus_anomalies import evaluate_telemetry_file


def setUpModule():
    os.chdir(ROOT)


class PrometheusAnomalyModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline_df = generate_baseline_normal_data(n_samples=250, random_state=42)
        cls.model = PrometheusUnsupervisedDetector(
            contamination=0.05,
            n_estimators=50,
            n_components=3,
            anomaly_score_threshold=40.0,
            random_state=42,
        )
        cls.model.fit(cls.baseline_df)

    def test_unsupervised_training_and_fitting(self):
        self.assertTrue(self.model.is_fitted)
        self.assertEqual(len(self.model.feature_means), len(PROMETHEUS_FEATURES))
        self.assertEqual(len(self.model.feature_stds), len(PROMETHEUS_FEATURES))

    def test_anomaly_score_bounds_and_calibration(self):
        eval_X, labels = generate_evaluation_dataset(random_state=42)
        scores = self.model.score_anomaly(eval_X)

        self.assertEqual(len(scores), len(eval_X))
        self.assertTrue(np.all(scores >= 0.0), "Scores below 0.0 detected")
        self.assertTrue(np.all(scores <= 100.0), "Scores above 100.0 detected")

        # Mean score for normal should be significantly lower than attacks
        normal_mean = np.mean(scores[labels == 0])
        attack_mean = np.mean(scores[labels == 1])
        self.assertLess(normal_mean, 35.0, "Normal workloads scoring unexpectedly high")
        self.assertGreater(attack_mean, 60.0, "Attack workloads scoring unexpectedly low")

    def test_binary_predictions_and_accuracy(self):
        eval_X, labels = generate_evaluation_dataset(random_state=42)
        preds = self.model.predict(eval_X)  # +1 normal, -1 anomaly

        # Check binary format
        self.assertTrue(set(np.unique(preds)).issubset({-1, 1}))

        # Recall on attacks should be high
        attack_preds = preds[labels == 1]
        detected_attacks = np.sum(attack_preds == -1)
        recall = detected_attacks / len(attack_preds)
        self.assertGreaterEqual(recall, 0.95, f"Recall {recall} below 95% target")

    def test_threat_driver_attribution(self):
        # 1. Cryptomining test
        crypto_sample = {
            "cpu_usage_cores": 3.5,
            "memory_working_set_mb": 200.0,
            "restart_rate_per_hour": 0.0,
            "network_tx_kbps": 30.0,
            "network_rx_kbps": 20.0,
            "falco_alerts_rate": 0.0,
            "apiserver_403_rate": 0.0,
        }
        drivers = self.model.attribute_threat_drivers(crypto_sample)
        self.assertGreater(len(drivers), 0)
        self.assertEqual(drivers[0]["metric"], "cpu_usage_cores")
        self.assertIn("Cryptomining", drivers[0]["threat_indication"])

        # 2. Exfiltration test
        exfil_sample = {
            "cpu_usage_cores": 0.1,
            "memory_working_set_mb": 50.0,
            "restart_rate_per_hour": 0.0,
            "network_tx_kbps": 3500.0,
            "network_rx_kbps": 50.0,
            "falco_alerts_rate": 0.0,
            "apiserver_403_rate": 0.0,
        }
        drivers_exfil = self.model.attribute_threat_drivers(exfil_sample)
        self.assertGreater(len(drivers_exfil), 0)
        self.assertEqual(drivers_exfil[0]["metric"], "network_tx_kbps")
        self.assertIn("Exfiltration", drivers_exfil[0]["threat_indication"])

    def test_joblib_persistence_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir) / "test_model_12.joblib"
            joblib.dump(self.model, tmp_path)
            self.assertTrue(tmp_path.exists())

            loaded: PrometheusUnsupervisedDetector = joblib.load(tmp_path)
            self.assertTrue(loaded.is_fitted)

            sample = self.baseline_df.iloc[[0]]
            orig_score = self.model.score_anomaly(sample)
            loaded_score = loaded.score_anomaly(sample)
            np.testing.assert_almost_equal(orig_score, loaded_score)

    def test_evaluator_script_execution(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_json = Path(tmp_dir) / "eval_out.json"
            model_path = paths.ROOT / "models" / "model_12_prometheus_unsupervised.joblib"
            telemetry_path = paths.RAW / "telemetry" / "prometheus_runtime_metrics.json"

            res = evaluate_telemetry_file(
                input_file=telemetry_path,
                model_path=model_path,
                output_json=out_json,
            )
            self.assertTrue(out_json.exists())
            self.assertIn("workloads_evaluated", res)
            self.assertGreaterEqual(res["workloads_evaluated"], 3)


if __name__ == "__main__":
    unittest.main()
