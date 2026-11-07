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

    def test_go_buildinfo_symbol_parsing(self):
        # Mock Go ELF binary header with .go.buildinfo magic and module dependencies
        mock_go_elf = (
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"
            b"\xff Go buildinf:\x08\x00"
            b"path\tk8s.io/kubernetes/cmd/kubelet\n"
            b"mod\tk8s.io/kubernetes\tv1.28.2\th1:abc==\n"
            b"dep\tk8s.io/client-go\tv0.28.2\th1:xyz==\n"
            b"dep\tgithub.com/opencontainers/runc\tv1.1.9\th1:def==\n"
            b"dep\tgoogle.golang.org/grpc\tv1.58.2\th1:jkl==\n"
            b"build\tCGO_ENABLED=0\n"
            b"go1.22.1\x00"
        )
        pkgs = self.scanner._parse_elf_symbols(mock_go_elf, binary_name="kubelet")
        pkg_names = {p.name: p for p in pkgs}

        self.assertIn("k8s.io/kubernetes", pkg_names)
        self.assertEqual(pkg_names["k8s.io/kubernetes"].version, "v1.28.2")
        self.assertEqual(pkg_names["k8s.io/kubernetes"].package_type, "go-module")

        self.assertIn("k8s.io/client-go", pkg_names)
        self.assertEqual(pkg_names["k8s.io/client-go"].version, "v0.28.2")

        self.assertIn("github.com/opencontainers/runc", pkg_names)
        self.assertEqual(pkg_names["github.com/opencontainers/runc"].version, "v1.1.9")

        self.assertIn("golang", pkg_names)
        self.assertEqual(pkg_names["golang"].version, "go1.22.1")
        self.assertEqual(pkg_names["golang"].package_type, "go-runtime")

    def test_rust_cargo_auditable_symbol_parsing(self):
        # Mock Rust ELF binary with cargo-auditable embedded dependency JSON
        cargo_json = json.dumps({
            "packages": [
                {"name": "tokio", "version": "1.35.0", "license": "MIT"},
                {"name": "serde", "version": "1.0.193", "license": "Apache-2.0"},
            ]
        }).encode("utf-8")
        mock_rust_elf = (
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"
            + cargo_json +
            b"\x00rustc 1.77.0 (aedd173a2 2024-03-17)\x00"
        )
        pkgs = self.scanner._parse_elf_symbols(mock_rust_elf, binary_name="microservice")
        pkg_names = {p.name: p for p in pkgs}

        self.assertIn("tokio", pkg_names)
        self.assertEqual(pkg_names["tokio"].version, "1.35.0")
        self.assertEqual(pkg_names["tokio"].package_type, "rust-crate")

        self.assertIn("serde", pkg_names)
        self.assertEqual(pkg_names["serde"].version, "1.0.193")

        self.assertIn("rustc", pkg_names)
        self.assertEqual(pkg_names["rustc"].version, "1.77.0")
        self.assertEqual(pkg_names["rustc"].package_type, "rust-runtime")

    def test_static_elf_layer_unpacking_in_tar(self):
        # Create an in-memory OCI tarball with a distroless/scratch Go binary
        mock_go_elf = (
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"
            b"\xff Go buildinf:\x08\x00"
            b"path\tgithub.com/traefik/traefik\n"
            b"mod\tgithub.com/traefik/traefik\tv3.0.0\n"
            b"dep\tgolang.org/x/crypto\tv0.21.0\n"
        )
        layer_bio = io.BytesIO()
        with tarfile.open(fileobj=layer_bio, mode="w") as l_tf:
            ti = tarfile.TarInfo(name="app/traefik")
            ti.size = len(mock_go_elf)
            ti.type = tarfile.REGTYPE
            l_tf.addfile(ti, io.BytesIO(mock_go_elf))

        outer_bio = io.BytesIO()
        with tarfile.open(fileobj=outer_bio, mode="w") as out_tf:
            manifest = [{"Config": "cfg.json", "RepoTags": ["traefik:v3"], "Layers": ["layer.tar"]}]
            mb = json.dumps(manifest).encode("utf-8")
            ti_m = tarfile.TarInfo(name="manifest.json")
            ti_m.size = len(mb)
            out_tf.addfile(ti_m, io.BytesIO(mb))

            ti_l = tarfile.TarInfo(name="layer.tar")
            lb = layer_bio.getvalue()
            ti_l.size = len(lb)
            out_tf.addfile(ti_l, io.BytesIO(lb))

        report = self.scanner.scan_tar_bytes(outer_bio.getvalue(), source_name="traefik:v3")
        self.assertEqual(report.os_distro, "distroless/static-elf")
        pkg_names = {p.name for p in report.packages}
        self.assertIn("github.com/traefik/traefik", pkg_names)
        self.assertIn("golang.org/x/crypto", pkg_names)


if __name__ == "__main__":
    unittest.main()
