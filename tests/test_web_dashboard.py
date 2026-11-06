#!/usr/bin/env python3
"""
test_web_dashboard.py
=====================
Unit tests for the enterprise self-hosted Web Management Console.
"""

import json
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
import urllib.request

# Path setup
ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
CORE_DIR = SRC_DIR / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from reporting.web_dashboard import start_web_console


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class TestWebDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = get_free_port()
        cls.server = start_web_console(host="127.0.0.1", port=cls.port)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_01_index_html(self):
        url = f"{self.base_url}/"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            content = resp.read().decode("utf-8")
            self.assertIn("Kubernetes Security Assessment Platform", content)
            self.assertIn("Live Manifest Security Scanner", content)

    def test_02_api_stats(self):
        url = f"{self.base_url}/api/stats"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("fleet_compliance_score", data)
            self.assertIn("scanned_workloads", data)

    def test_03_api_scan_endpoint(self):
        url = f"{self.base_url}/api/scan"
        payload = {
            "yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\nspec:\n  containers:\n  - name: test\n    image: nginx\n    securityContext:\n      privileged: true"
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("compliance_score", data)
            self.assertEqual(data.get("risk_tier"), "High")
            self.assertTrue(any(f["vuln_id"] == "V01" for f in data.get("findings", [])))

    def test_04_api_remediate_endpoint(self):
        url = f"{self.base_url}/api/remediate"
        payload = {
            "yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n      - name: web\n        image: nginx"
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            remediated = data.get("remediated_yaml", "")
            self.assertIn("readOnlyRootFilesystem", remediated)


if __name__ == "__main__":
    unittest.main()
