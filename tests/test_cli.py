#!/usr/bin/env python3
"""
test_cli.py
===========
Unit tests for the unified k8s-sec CLI interface.
"""

from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

# Ensure core and src are in path
ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
CORE_DIR = SRC_DIR / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cli.main import main


class TestUnifiedCLI(unittest.TestCase):
    def test_01_version_command(self):
        with patch("sys.argv", ["k8s-sec", "version"]):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                main()
                output = fake_out.getvalue()
                self.assertIn("v2.0.0", output)
                self.assertIn("Model 11", output)

    def test_02_scan_json_output(self):
        target = str(ROOT_DIR / "manifests" / "secure" / "hardened-deployment.yaml")
        with patch("sys.argv", ["k8s-sec", "scan", target, "--output", "json"]):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                main()
                output = fake_out.getvalue()
                data = json.loads(output)
                self.assertIsInstance(data, list)
                self.assertEqual(len(data), 1)
                self.assertGreaterEqual(data[0]["compliance_score"], 80.0)

    def test_03_scan_gate_pass(self):
        target = str(ROOT_DIR / "manifests" / "secure" / "hardened-deployment.yaml")
        with patch("sys.argv", ["k8s-sec", "scan", target, "--gate", "--threshold", "35.0"]):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                # Should not raise SystemExit
                main()
                output = fake_out.getvalue()
                self.assertIn("Summary", output)

    def test_04_scan_gate_fail(self):
        target = str(ROOT_DIR / "manifests" / "insecure" / "weak-deployment.yaml")
        with patch("sys.argv", ["k8s-sec", "scan", target, "--gate", "--threshold", "35.0"]):
            with patch("sys.stdout", new=StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    main()
                self.assertEqual(cm.exception.code, 1)

    def test_05_remediate_command(self):
        import tempfile
        target = str(ROOT_DIR / "manifests" / "insecure" / "weak-deployment.yaml")
        with tempfile.NamedTemporaryFile(suffix=".yaml") as tmp:
            with patch("sys.argv", ["k8s-sec", "remediate", target, "--output", tmp.name, "--quiet"]):
                main()
                self.assertTrue(Path(tmp.name).exists())
                content = Path(tmp.name).read_text()
                self.assertIn("readOnlyRootFilesystem", content)

    def test_06_bin_executable_script(self):
        bin_path = ROOT_DIR / "bin" / "k8s-sec"
        res = subprocess.run([str(bin_path), "version"], stdout=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Kubernetes ML Security Assessment Platform (v2.0.0)", res.stdout)


if __name__ == "__main__":
    unittest.main()
