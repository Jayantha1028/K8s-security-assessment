#!/usr/bin/env python3
"""
test_native_security_scanner.py
===============================
Unit tests for Native Independent Security Scanner (src/native_security_scanner.py).
"""

import sys
import unittest
from pathlib import Path

# Add src to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
for _sub in ['core', 'data', 'scanners', 'models', 'evaluation', 'reporting', 'integrations']:
    _p = str(ROOT / 'src' / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


from native_security_scanner import (
    NativeSecurityScanner,
    shannon_entropy,
    audit_cross_scanner_concordance,
)


class TestNativeSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NativeSecurityScanner()

    def test_insecure_workload_ast_detection(self):
        """Verify native scanner flags critical vectors in weak-deployment.yaml."""
        report = self.scanner.scan_file("manifests/insecure/weak-deployment.yaml")
        self.assertLess(report.compliance_score, 40.0)
        self.assertEqual(report.risk_tier, "High")
        self.assertIn("V01", report.detected_vuln_ids, "Privileged container (V01) must be flagged")
        self.assertIn("V02", report.detected_vuln_ids, "Root user UID 0 (V02) must be flagged")
        self.assertIn("V09", report.detected_vuln_ids, "HostNetwork (V09) must be flagged")
        self.assertIn("V10", report.detected_vuln_ids, "HostPID (V10) must be flagged")

    def test_hardened_workload_ast_detection(self):
        """Verify native scanner awards passing grade to hardened manifest."""
        report = self.scanner.scan_file("manifests/secure/hardened-deployment.yaml")
        self.assertGreaterEqual(report.compliance_score, 80.0)
        self.assertEqual(report.risk_tier, "Low")
        self.assertNotIn("V01", report.detected_vuln_ids)
        self.assertNotIn("V02", report.detected_vuln_ids)

    def test_shannon_entropy_calculation(self):
        """Verify Shannon entropy accurately distinguishes random keys from plaintext."""
        low_entropy = "helloworld123"
        high_entropy_key = "aF9#zK2$pL8*qM4!vX7@rN1^wY5="
        self.assertLess(shannon_entropy(low_entropy), 3.8)
        self.assertGreater(shannon_entropy(high_entropy_key), 4.0)

    def test_raw_yaml_entropy_and_secret_detection(self):
        """Verify high-entropy credentials inside environment variables trigger V18."""
        raw_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: credential-leak-pod
spec:
  containers:
  - name: leaky-app
    image: nginx:1.25
    env:
    - name: AWS_SECRET_ACCESS_KEY
      value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""
        report = self.scanner.scan_yaml_content(raw_yaml)
        self.assertIn("V18", report.detected_vuln_ids, "High-entropy secret must be flagged under V18")

    def test_rbac_wildcard_detection(self):
        """Verify wildcard permissions and cluster-admin are detected natively."""
        raw_rbac = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dangerous-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
"""
        report = self.scanner.scan_yaml_content(raw_rbac)
        self.assertIn("V24", report.detected_vuln_ids, "Wildcard resources (V24) must be flagged")
        self.assertIn("V25", report.detected_vuln_ids, "Wildcard verbs (V25) must be flagged")
        self.assertIn("V26", report.detected_vuln_ids, "Cluster-admin binding (V26) must be flagged")


if __name__ == "__main__":
    unittest.main()
