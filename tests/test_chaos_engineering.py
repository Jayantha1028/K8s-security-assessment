"""
test_chaos_engineering.py
==========================
Unit & Integration tests for the Security Chaos Engineering (SCE) Suite.
"""

import unittest
import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
for _sub in ['core', 'data', 'scanners', 'models', 'evaluation', 'reporting', 'integrations']:
    _p = str(Path(__file__).resolve().parent.parent / 'src' / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


import paths
from train_11_models import ConsolidatedSecurityModel, FinalMasterModel
from security_chaos_testing import SecurityChaosEngine


class SecurityChaosEngineeringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = SecurityChaosEngine()

    def test_sce_1_adversarial_camouflage(self):
        """Verify Model 11 resists cosmetic camouflage wrapping lethal exploits."""
        self.engine.test_adversarial_camouflage()
        res = [r for r in self.engine.results if r["code"] == "SCE-1"]
        self.assertTrue(len(res) > 0)
        self.assertEqual(res[-1]["status"], "PASS")

    def test_sce_2_sensor_blackout(self):
        """Verify pipeline handles missing sensor telemetry gracefully."""
        self.engine.test_sensor_blackout()
        res = [r for r in self.engine.results if r["code"] == "SCE-2"]
        self.assertTrue(len(res) > 0)
        self.assertEqual(res[-1]["status"], "PASS")

    def test_sce_3_alert_overflow_flood(self):
        """Verify mathematical stability under 10,000+ alert DoS storm."""
        self.engine.test_alert_overflow_flood()
        res = [r for r in self.engine.results if r["code"] == "SCE-3"]
        self.assertTrue(len(res) > 0)
        self.assertEqual(res[-1]["status"], "PASS")

    def test_sce_4_out_of_distribution_anomaly(self):
        """Verify Dual-Mode GMM detects zero-day out-of-distribution payloads."""
        self.engine.test_out_of_distribution_anomaly()
        res = [r for r in self.engine.results if r["code"] == "SCE-4"]
        self.assertTrue(len(res) > 0)
        self.assertEqual(res[-1]["status"], "PASS")

    def test_sce_5_manifest_parser_fuzzing(self):
        """Verify parser isolates malformed and corrupted ASTs."""
        self.engine.test_manifest_parser_fuzzing()
        res = [r for r in self.engine.results if r["code"] == "SCE-5"]
        self.assertTrue(len(res) > 0)
        self.assertEqual(res[-1]["status"], "PASS")

    def test_sce_6_multi_manifest_fragmentation(self):
        """Verify fragmented kill-chain multi-file attacks are caught."""
        self.engine.test_multi_manifest_fragmentation()
        res = [r for r in self.engine.results if r["code"] == "SCE-6"]
        self.assertTrue(len(res) > 0)
        self.assertEqual(res[-1]["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
