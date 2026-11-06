#!/usr/bin/env python3
"""
test_cve_sync_engine.py
=======================
Unit tests for the automated CVE sync engine & embedded SQLite vulnerability database.
"""

from pathlib import Path
import sys
import tempfile
import unittest

# Path setup
ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
CORE_DIR = SRC_DIR / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from scanners.cve_sync_engine import CVEDatabaseEngine


class TestCVESyncEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "test_cve.sqlite"
        self.engine = CVEDatabaseEngine(db_path=self.db_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_db_initialization_and_seeding(self):
        self.assertTrue(self.db_path.exists())
        stats = self.engine.get_stats()
        self.assertGreater(stats["total_cves"], 0)
        self.assertIn("CRITICAL", stats["severities"])
        self.assertIn("HIGH", stats["severities"])

    def test_02_upsert_and_query_cve(self):
        success = self.engine.upsert_cve(
            cve_id="CVE-2026-99999",
            package_name="test-crypto-lib",
            ecosystem="pip",
            severity="CRITICAL",
            cvss_score=9.9,
            vulnerable_versions="< 2.0.0",
            description="Remote code execution in test crypto parser",
            source_feed="TEST_SUITE",
        )
        self.assertTrue(success)

        # Query
        results = self.engine.query_package_cves("test-crypto-lib")
        self.assertEqual(len(results), 1)
        cve = results[0]
        self.assertEqual(cve.cve_id, "CVE-2026-99999")
        self.assertEqual(cve.severity, "CRITICAL")
        self.assertEqual(cve.cvss_score, 9.9)

    def test_03_query_nonexistent_package(self):
        results = self.engine.query_package_cves("nonexistent-package-xyz-123")
        self.assertEqual(len(results), 0)

    def test_04_stats_structure(self):
        stats = self.engine.get_stats()
        self.assertIn("total_cves", stats)
        self.assertIn("db_size_kb", stats)
        self.assertIn("severities", stats)
        self.assertIn("ecosystems", stats)
        self.assertIn("last_synced", stats)


if __name__ == "__main__":
    unittest.main()
