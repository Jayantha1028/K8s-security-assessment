#!/usr/bin/env python3
"""
test_model_accuracy_rigor.py
============================
Automated Rigor Unit & Regression Suite enforcing the 12 Statistical & Clinical Gates.
"""

import sys
import unittest
from pathlib import Path

# Add src/ to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
for _sub in ['core', 'data', 'scanners', 'models', 'evaluation', 'reporting', 'integrations']:
    _p = str(ROOT / 'src' / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


import joblib
import pandas as pd
import paths
from evaluate_model_rigor import (
    FEATURES,
    evaluate_clinical_metrics,
    evaluate_probability_calibration,
    evaluate_golden_pair_monotonicity,
    evaluate_semantic_invariance,
    evaluate_zero_shot_helm_workloads,
)


class TestModelAccuracyRigor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.assertTrue(paths.MODELS_11_FILE.exists(), "Model 11 bundle must exist")
        cls.assertTrue(paths.COMBINED_DATASET.exists(), "Combined dataset must exist")
        bundle = joblib.load(paths.MODELS_11_FILE)
        cls.m11 = bundle["models"]["M11_final_master"]
        cls.df = pd.read_csv(paths.COMBINED_DATASET)
        cls.X = cls.df[FEATURES]
        cls.y_risk = cls.df["risk_level"]
        cls.y_score = cls.df["security_score"]

    def test_clinical_confusion_matrix_and_balanced_accuracy(self):
        """Assert Balanced Accuracy >= 95%, MCC >= 0.90, and Zero High-Risk False Negatives."""
        res = evaluate_clinical_metrics(self.m11, self.X, self.y_risk, self.y_score)
        self.assertGreaterEqual(res["balanced_accuracy"], 95.0)
        self.assertGreaterEqual(res["mcc"], 0.90)
        self.assertGreaterEqual(res["cohen_kappa"], 0.90)
        self.assertEqual(res["fnr_high"], 0.0, "Catastrophic False Negative Rate on High-Risk must be 0.0%")
        self.assertEqual(res["fpr_low_to_high"], 0.0, "False Alarm Rate (Low predicted as High) must be 0.0%")

    def test_probability_calibration_ece_and_brier(self):
        """Assert Expected Calibration Error < 0.05 and Brier Score Loss <= 0.08."""
        res = evaluate_probability_calibration(self.m11, self.X, self.y_risk)
        self.assertLess(res["ece"], 0.05, f"ECE must be < 0.05; got {res['ece']:.4f}")
        self.assertLessEqual(res["brier_score"], 0.08, f"Brier score must be <= 0.08; got {res['brier_score']:.4f}")

    def test_golden_pair_monotonicity_and_zero_inversions(self):
        """Assert 100% Monotonicity Consistency Ratio and 0 Inversions across 20 workload twins."""
        res = evaluate_golden_pair_monotonicity(self.m11)
        self.assertEqual(res["inversions"], 0, f"Found {res['inversions']} vulnerability inversions")
        self.assertEqual(res["monotonicity_consistency_ratio"], 100.0)
        self.assertGreaterEqual(res["mean_hardening_delta"], 15.0)

    def test_semantic_invariance_under_metadata_jitter(self):
        """Assert Maximum Semantic Drift <= 1.0 point under non-security attribute modifications."""
        res = evaluate_semantic_invariance(self.m11, self.X)
        self.assertLessEqual(res["max_drift"], 1.0)
        self.assertEqual(res["invariance_pass_rate"], 100.0)

    def test_zero_shot_external_workloads_benchmark(self):
        """Assert Zero-Shot 3rd-Party Production Helm Workloads Accuracy >= 90%."""
        res = evaluate_zero_shot_helm_workloads(self.m11)
        self.assertGreaterEqual(res["zero_shot_accuracy"], 90.0)
        self.assertEqual(res["correct_matches"], res["total_workloads"])


if __name__ == "__main__":
    unittest.main()
