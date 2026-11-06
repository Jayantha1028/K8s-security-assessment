import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
for _sub in ['core', 'data', 'scanners', 'models', 'evaluation', 'reporting', 'integrations']:
    _p = str(ROOT / 'src' / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import paths
from container_layer_scanner import HybridContainerLayerScanner, SBOMScanReport, InstalledPackage


def create_mock_oci_image_tar() -> bytes:
    """Construct a valid OCI container image tarball in-memory for testing."""
    # 1. Mock Layer 1: Debian dpkg/status
    layer1_bio = io.BytesIO()
    with tarfile.open(fileobj=layer1_bio, mode="w") as l1_tf:
        dpkg_data = (
            "Package: nginx\n"
            "Status: install ok installed\n"
            "Priority: optional\n"
            "Section: httpd\n"
            "Installed-Size: 2500\n"
            "Maintainer: Debian Nginx Maintainers\n"
            "Architecture: amd64\n"
            "Version: 1.14.2-1~deb9u1\n\n"
            "Package: openssl\n"
            "Status: install ok installed\n"
            "Priority: standard\n"
            "Section: utils\n"
            "Architecture: amd64\n"
            "Version: 1.1.0j-1~deb9u1\n\n"
            "Package: bsdutils\n"
            "Status: install ok installed\n"
            "Architecture: amd64\n"
            "Version: 1:2.29.2-1\n"
        ).encode("utf-8")

        ti = tarfile.TarInfo(name="var/lib/dpkg/status")
        ti.size = len(dpkg_data)
        ti.type = tarfile.REGTYPE
        l1_tf.addfile(ti, io.BytesIO(dpkg_data))

    layer1_bytes = layer1_bio.getvalue()

    # 2. Mock Layer 2: Alpine apk/installed & requirements.txt
    layer2_bio = io.BytesIO()
    with tarfile.open(fileobj=layer2_bio, mode="w") as l2_tf:
        apk_data = (
            "P:musl\n"
            "V:1.2.2-r0\n"
            "L:MIT\n"
            "o:alpine-baselayout\n\n"
            "P:busybox\n"
            "V:1.32.1-r6\n"
            "L:GPL-2.0-only\n"
        ).encode("utf-8")

        ti_apk = tarfile.TarInfo(name="lib/apk/db/installed")
        ti_apk.size = len(apk_data)
        ti_apk.type = tarfile.REGTYPE
        l2_tf.addfile(ti_apk, io.BytesIO(apk_data))

        req_data = b"flask==1.1.2\nrequests==2.24.0\n"
        ti_req = tarfile.TarInfo(name="app/requirements.txt")
        ti_req.size = len(req_data)
        ti_req.type = tarfile.REGTYPE
        l2_tf.addfile(ti_req, io.BytesIO(req_data))

    layer2_bytes = layer2_bio.getvalue()

    # 3. Outer Image Tarball containing manifest.json and layer archives
    image_bio = io.BytesIO()
    with tarfile.open(fileobj=image_bio, mode="w") as img_tf:
        manifest = [
            {
                "Config": "config.json",
                "RepoTags": ["test-app:1.0.0"],
                "Layers": ["layer1.tar", "layer2.tar"]
            }
        ]
        manifest_bytes = json.dumps(manifest).encode("utf-8")
        ti_manifest = tarfile.TarInfo(name="manifest.json")
        ti_manifest.size = len(manifest_bytes)
        img_tf.addfile(ti_manifest, io.BytesIO(manifest_bytes))

        # Add layer1.tar
        ti_l1 = tarfile.TarInfo(name="layer1.tar")
        ti_l1.size = len(layer1_bytes)
        img_tf.addfile(ti_l1, io.BytesIO(layer1_bytes))

        # Add layer2.tar
        ti_l2 = tarfile.TarInfo(name="layer2.tar")
        ti_l2.size = len(layer2_bytes)
        img_tf.addfile(ti_l2, io.BytesIO(layer2_bytes))

    return image_bio.getvalue()


class ContainerLayerScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image_tar_bytes = create_mock_oci_image_tar()
        cls.scanner = HybridContainerLayerScanner()

    def test_pure_python_layer_unpacking_memory(self):
        report = self.scanner.scan_tar_bytes(self.image_tar_bytes, source_name="test-app:1.0.0")

        self.assertEqual(report.execution_mode, "PURE_PYTHON_OCI")
        self.assertEqual(report.layers_inspected, 2)
        self.assertEqual(report.os_distro, "alpine")  # Layer 2 parsed last
        self.assertGreaterEqual(report.total_packages, 5)

        pkg_names = {p.name for p in report.packages}
        self.assertIn("nginx", pkg_names)
        self.assertIn("openssl", pkg_names)
        self.assertIn("bsdutils", pkg_names)
        self.assertIn("musl", pkg_names)
        self.assertIn("flask", pkg_names)

        # Check debian vs apk vs python type attribution
        nginx_pkg = next(p for p in report.packages if p.name == "nginx")
        self.assertEqual(nginx_pkg.package_type, "deb")
        self.assertEqual(nginx_pkg.version, "1.14.2-1~deb9u1")
        self.assertEqual(nginx_pkg.layer_index, 0)

        musl_pkg = next(p for p in report.packages if p.name == "musl")
        self.assertEqual(musl_pkg.package_type, "apk")
        self.assertEqual(musl_pkg.version, "1.2.2-r0")
        self.assertEqual(musl_pkg.layer_index, 1)

        flask_pkg = next(p for p in report.packages if p.name == "flask")
        self.assertEqual(flask_pkg.package_type, "python")
        self.assertEqual(flask_pkg.version, "1.1.2")

    def test_scan_tarball_from_disk(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tar_file = Path(tmp_dir) / "test_image.tar"
            tar_file.write_bytes(self.image_tar_bytes)

            report = self.scanner.scan_tarball(str(tar_file))
            self.assertEqual(report.layers_inspected, 2)
            self.assertGreaterEqual(report.total_packages, 5)
            self.assertLess(report.scan_latency_ms, 500.0)

    def test_offline_catalog_fallback_on_unreachable_docker(self):
        # Force fallback by specifying non-existent trivy and no docker stream
        offline_scanner = HybridContainerLayerScanner(trivy_bin="/nonexistent/trivy")
        offline_scanner.has_docker = False

        report = offline_scanner.scan_image("debian:9", use_trivy_if_available=False)
        self.assertEqual(report.execution_mode, "OFFLINE_CATALOG_FALLBACK")
        self.assertGreater(report.total_cves, 0)
        self.assertTrue(any(c.cve_id == "CVE-2016-2779" for c in report.high_cves))

    def test_report_serialization(self):
        report = self.scanner.scan_tar_bytes(self.image_tar_bytes, source_name="test-app:1.0.0")
        d = report.to_dict()
        self.assertIn("packages", d)
        self.assertIn("execution_mode", d)
        self.assertIn("scan_latency_ms", d)
        json_str = json.dumps(d)
        self.assertIn("test-app:1.0.0", json_str)


if __name__ == "__main__":
    unittest.main()
