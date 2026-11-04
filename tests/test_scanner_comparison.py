#!/usr/bin/env python3
"""
test_scanner_comparison.py
==========================
Unit and integration tests for Scanner Comparison Module (comparator/ package).
"""

import sys
import unittest
from pathlib import Path

# Add project root and src/ to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from comparator.cve_intelligence import (
    lookup_image_cves,
    normalize_image_name,
    summarize_cve_counts,
)
from comparator.scanner_benchmark import ScannerComparator
from comparator.comparator_cli import run_comprehensive_comparison


class TestScannerComparisonModule(unittest.TestCase):
    def setUp(self):
        self.comparator = ScannerComparator()

    def test_cve_intelligence_known_images(self):
        """Verify CVE lookups return critical CVEs for vulnerable image versions."""
        cves_log4j = lookup_image_cves("docker.io/library/openjdk:8")
        self.assertGreater(len(cves_log4j), 0)
        cve_ids = [c.cve_id for c in cves_log4j]
        self.assertIn("CVE-2021-44228", cve_ids, "Log4Shell CVE must be detected in openjdk:8")

        cves_nginx = lookup_image_cves("nginx:1.14.2")
        self.assertGreater(len(cves_nginx), 0)
        counts = summarize_cve_counts(cves_nginx)
        self.assertGreater(counts["CRITICAL"], 0)

    def test_cve_intelligence_normalization(self):
        """Verify image tag stripping and digest removal."""
        self.assertEqual(normalize_image_name("registry.k8s.io/kube-apiserver:v1.28.0@sha256:abc"), "kube-apiserver:v1.28.0")
        self.assertEqual(normalize_image_name("nginx:latest"), "nginx:latest")

    def test_scanner_benchmark_workload(self):
        """Verify side-by-side benchmark comparison execution and speedup calculation."""
        res = self.comparator.benchmark_workload("manifests/insecure/weak-deployment.yaml")
        self.assertEqual(res.native_metrics.predicted_risk_tier, "High")
        self.assertGreater(res.native_metrics.total_findings, 5)
        self.assertGreater(res.speedup_factor, 100.0, "Native scanner must be at least 100x faster than simulated external CLIs")
        self.assertTrue(res.risk_concordance)

    def test_comparator_cli_execution_and_reports(self):
        """Verify CLI comparator runs cleanly and produces markdown and json artifacts."""
        run_comprehensive_comparison(
            manifests=["manifests/insecure/weak-deployment.yaml", "manifests/secure/hardened-deployment.yaml"],
            output_md=True,
            output_json=True,
        )
        md_file = ROOT / "reports" / "scanner_comparison_matrix.md"
        json_file = ROOT / "reports" / "scanner_comparison_report.json"
        self.assertTrue(md_file.is_file(), "Comparison markdown file must exist")
        self.assertTrue(json_file.is_file(), "Comparison JSON file must exist")
        self.assertGreater(md_file.stat().st_size, 100)


if __name__ == "__main__":
    unittest.main()
