#!/usr/bin/env python3
"""
test_admission_webhook.py
=========================
Unit and integration tests for the In-Cluster Kubernetes Admission Controller.
Verifies ValidatingAdmissionWebhook (/validate), MutatingAdmissionWebhook (/mutate),
health probes, and OpenMetrics export.
"""

import base64
import json
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
import urllib.request

# Ensure core and src are in path
ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
CORE_DIR = SRC_DIR / "core"
if str(CORE_DIR) not in sys.path:
    sys.path.insert(0, str(CORE_DIR))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from integrations.admission_webhook import (
    AdmissionSecurityEngine,
    generate_self_signed_cert,
    start_admission_server,
)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class TestAdmissionWebhook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = get_free_port()
        cls.server = start_admission_server(
            host="127.0.0.1",
            port=cls.port,
            use_tls=False,  # Use HTTP for unit tests to avoid self-signed warnings
            risk_threshold=35.0,
            enable_mutation=True,
            enable_model_11=True,
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)  # Warmup
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_01_healthz_endpoint(self):
        url = f"{self.base_url}/healthz"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data.get("status"), "healthy")
            self.assertEqual(data.get("service"), "k8s-security-admission-controller")

    def test_02_validate_allowed_secure_pod(self):
        secure_pod_review = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test-uid-secure-001",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "namespace": "production",
                "operation": "CREATE",
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "hardened-microservice", "namespace": "production"},
                    "spec": {
                        "securityContext": {
                            "runAsNonRoot": True,
                            "runAsUser": 10001,
                            "runAsGroup": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"}
                        },
                        "containers": [{
                            "name": "web",
                            "image": "redis:7-alpine",
                            "securityContext": {
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}
                            },
                            "resources": {
                                "limits": {"cpu": "200m", "memory": "256Mi"},
                                "requests": {"cpu": "50m", "memory": "64Mi"}
                            }
                        }]
                    }
                }
            }
        }
        url = f"{self.base_url}/validate"
        req = urllib.request.Request(
            url,
            data=json.dumps(secure_pod_review).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            review_resp = data.get("response", {})
            self.assertEqual(review_resp.get("uid"), "test-uid-secure-001")
            self.assertTrue(review_resp.get("allowed"), "Hardened pod must be approved")
            self.assertEqual(review_resp.get("status", {}).get("code"), 200)

    def test_03_validate_rejected_privileged_pod(self):
        insecure_pod_review = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test-uid-insecure-002",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "namespace": "default",
                "operation": "CREATE",
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "trojan-horse-pod", "namespace": "default"},
                    "spec": {
                        "hostNetwork": True,
                        "hostPID": True,
                        "containers": [{
                            "name": "root-shell",
                            "image": "ubuntu:latest",
                            "securityContext": {
                                "privileged": True,
                                "allowPrivilegeEscalation": True
                            }
                        }]
                    }
                }
            }
        }
        url = f"{self.base_url}/validate"
        req = urllib.request.Request(
            url,
            data=json.dumps(insecure_pod_review).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            review_resp = data.get("response", {})
            self.assertEqual(review_resp.get("uid"), "test-uid-insecure-002")
            self.assertFalse(review_resp.get("allowed"), "Privileged / HostPID pod must be rejected!")
            self.assertEqual(review_resp.get("status", {}).get("code"), 403)
            msg = review_resp.get("status", {}).get("message", "")
            self.assertIn("REJECTED", msg)
            self.assertTrue("V01" in msg or "V04" in msg or "Exploit" in msg)

    def test_04_mutate_json_patch_injection(self):
        unhardened_deployment = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test-uid-mutate-003",
                "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
                "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
                "namespace": "staging",
                "operation": "CREATE",
                "object": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {"name": "unhardened-app", "namespace": "staging"},
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [{
                                    "name": "web",
                                    "image": "nginx:1.21"
                                }]
                            }
                        }
                    }
                }
            }
        }
        url = f"{self.base_url}/mutate"
        req = urllib.request.Request(
            url,
            data=json.dumps(unhardened_deployment).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            review_resp = data.get("response", {})
            self.assertEqual(review_resp.get("uid"), "test-uid-mutate-003")
            self.assertTrue(review_resp.get("allowed"))
            self.assertEqual(review_resp.get("patchType"), "JSONPatch")

            # Decode JSON Patch
            patch_b64 = review_resp.get("patch")
            self.assertIsNotNone(patch_b64)
            patch_str = base64.b64decode(patch_b64).decode("utf-8")
            patches = json.loads(patch_str)
            self.assertGreater(len(patches), 0)

            # Check that securityContext runAsNonRoot and readOnlyRootFilesystem were injected
            paths = [p.get("path") for p in patches]
            self.assertTrue(any("securityContext" in p for p in paths))

    def test_05_openmetrics_endpoint(self):
        url = f"{self.base_url}/metrics"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            content = resp.read().decode("utf-8")
            self.assertIn("k8s_security_admissions_total", content)
            self.assertIn("k8s_security_admissions_approved_total", content)
            self.assertIn("k8s_security_admissions_rejected_total", content)

    def test_06_self_signed_cert_generator(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            c_path = Path(tmpdir) / "cert.pem"
            k_path = Path(tmpdir) / "key.pem"
            generate_self_signed_cert(str(c_path), str(k_path), domain="test.svc")
            self.assertTrue(c_path.exists())
            self.assertTrue(k_path.exists())
            self.assertGreater(c_path.stat().st_size, 500)
            self.assertGreater(k_path.stat().st_size, 500)


if __name__ == "__main__":
    unittest.main()
