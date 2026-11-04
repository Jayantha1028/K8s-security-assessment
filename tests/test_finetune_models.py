#!/usr/bin/env python3
"""
test_finetune_models.py
=======================
Unit and integration tests for Automated Incremental Fine-Tuning (src/finetune_models.py).
"""

import sys
import unittest
from pathlib import Path

# Add src to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import pandas as pd
import joblib
import paths
from finetune_models import (
    FEATURES,
    load_snapshots_from_disk,
    get_anchor_replay_buffer,
    evaluate_k8s_goat_guardrail,
    finetune_model_11,
)


class TestIncrementalFineTuner(unittest.TestCase):
    def setUp(self):
        self.assertTrue(paths.MODELS_11_FILE.exists(), "Master bundle models_11 must exist")

    def test_features_contract(self):
        """Verify feature dimensions match Model 11 expected input."""
        m11_bundle = joblib.load(paths.MODELS_11_FILE)
        self.assertEqual(len(FEATURES), len(m11_bundle["features"]))
        self.assertEqual(FEATURES, m11_bundle["features"])

    def test_load_snapshots_from_disk(self):
        """Verify snapshots are ingested and scored correctly."""
        df_snaps = load_snapshots_from_disk()
        if not df_snaps.empty:
            self.assertIn("security_score", df_snaps.columns)
            self.assertIn("risk_level", df_snaps.columns)
            for f in FEATURES:
                self.assertIn(f, df_snaps.columns)

    def test_anchor_replay_buffer(self):
        """Verify anti-catastrophic forgetting replay buffer retrieval."""
        df_anchor = get_anchor_replay_buffer(sample_ratio=0.10)
        if paths.COMBINED_DATASET.exists():
            self.assertFalse(df_anchor.empty)
            self.assertGreater(len(df_anchor), 0)

    def test_k8s_goat_guardrail(self):
        """Verify baseline Model 11 intercepts Kubernetes Goat exploit scenarios."""
        m11_bundle = joblib.load(paths.MODELS_11_FILE)
        m11 = m11_bundle["models"]["M11_final_master"]
        score, risk, is_caught = evaluate_k8s_goat_guardrail(m11)
        self.assertTrue(is_caught, f"Expected Goat exploit to be caught as High risk; got {risk} ({score})")
        self.assertEqual(risk, "High")
        self.assertLess(score, 40.0)

    def test_finetune_dry_run_execution(self):
        """Verify full warm-start incremental training in dry-run mode."""
        # Must execute without exceptions and preserve disk state
        finetune_model_11(
            incremental_trees=5,
            finetune_lr=0.02,
            replay_ratio=0.10,
            checkpoint=False,
            dry_run=True,
        )


if __name__ == "__main__":
    unittest.main()
