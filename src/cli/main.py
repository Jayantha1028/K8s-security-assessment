#!/usr/bin/env python3
"""
main.py
=======
Unified Command-Line Interface (CLI) for the Kubernetes Security Assessment Platform.

Commands:
  scan         - Audit Kubernetes YAML manifests or directories (56-rule AST + Model 11)
  scan-image   - Deep unpack container image layers & extract OS/Python SBOM
  remediate    - Auto-harden insecure Kubernetes manifests with least-privilege securityContext
  admission    - Run In-Cluster Admission Controller Webhook (/validate & /mutate)
  daemon       - Run continuous Prometheus runtime anomaly detection daemon (Model 12)
  audit        - Generate Executive Compliance Audit Report (PDF & HTML)
  version      - Display engine versions, ML model bundles, and operational status
"""

import argparse
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

# Path resolution: Ensure core and src are in sys.path
_SRC_DIR = Path(__file__).resolve().parents[1]
_CORE_DIR = _SRC_DIR / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

import paths

VERSION = "2.0.0"
BANNER = rf"""
================================================================================
  _    ___        ____                       _ _         
 | | _| _ \ ___  / ___|  ___  ___ _   _ _ __(_) |_ _   _ 
 | |/ / (_) / __| \___ \ / _ \/ __| | | | '__| | __| | | |
 |   < \__, \__ \  ___) |  __/ (__| |_| | |  | | |_| |_| |
 |_|\_\  /_/|___/ |____/ \___|\___|\__,_|_|  |_|\__|\__, |
                                                    |___/ 
  Kubernetes ML Security Assessment Platform (v{VERSION})
================================================================================
"""


def cmd_version(args):
    print(BANNER)
    print(f"Platform Engine Version : v{VERSION}")
    print(f"Python Runtime          : {sys.version.split()[0]} ({sys.platform})")

    # Check Model 11
    m11_path = paths.ROOT / "models" / "model_11_final_master.joblib"
    m11_status = "Available (Unified Ridge Ensemble)" if m11_path.is_file() else "Not Found"
    print(f"Model 11 (Static Master): {m11_status}")

    # Check Model 12
    m12_path = paths.ROOT / "models" / "model_12_prometheus_unsupervised.joblib"
    m12_status = "Available (Isolation Forest + GMM)" if m12_path.is_file() else "Not Found"
    print(f"Model 12 (Runtime Anomaly): {m12_status}")

    # Check Docker Daemon
    import shutil, subprocess
    docker_ok = False
    if shutil.which("docker"):
        try:
            res = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            docker_ok = res.returncode == 0
        except Exception:
            pass
    print(f"Docker Daemon Socket    : {'Connected & Active' if docker_ok else 'Inactive / Not Available'}")

    # Check Trivy
    trivy_path = shutil.which("trivy") or "/opt/homebrew/bin/trivy"
    trivy_ok = os.path.isfile(trivy_path) and os.access(trivy_path, os.X_OK)
    print(f"Trivy CLI Engine        : {'Installed (' + trivy_path + ')' if trivy_ok else 'Not Installed (Using Offline Engine)'}")
    print("=" * 80)


def cmd_scan(args):
    from scanners.native_security_scanner import NativeSecurityScanner

    scanner = NativeSecurityScanner(
        entropy_threshold=args.entropy_threshold,
        enable_deep_layer_scan=args.deep_layers,
    )

    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Target path '{args.path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    reports = []
    if target_path.is_dir():
        reports = scanner.scan_directory(str(target_path), recursive=not args.no_recursive)
    else:
        reports = [scanner.scan_file(str(target_path))]

    if args.output == "json":
        data = [r.to_dict() for r in reports]
        print(json.dumps(data, indent=2))
        return

    # Table output
    print(BANNER)
    print(f"Target Path: {target_path} | Audited Manifests: {len(reports)}")
    print("-" * 80)
    print(f"{'Manifest File':<42} | {'Score':<8} | {'Tier':<8} | {'Vulns'}")
    print("-" * 80)

    worst_score = 100.0
    total_findings = 0
    for r in reports:
        fname = Path(r.manifest_path).name
        worst_score = min(worst_score, r.compliance_score)
        total_findings += len(r.findings)
        print(f"{fname:<42} | {r.compliance_score:<8.1f} | {r.risk_tier:<8} | {len(r.findings)}")

    print("=" * 80)
    print(f"Summary: Worst Score: {worst_score:.1f}/100 | Total Findings: {total_findings}")

    if args.gate and worst_score < args.threshold:
        print(f"\n[CI/CD GATE FAILED] Minimum score {worst_score:.1f} is below policy threshold {args.threshold:.1f}!", file=sys.stderr)
        sys.exit(1)


def cmd_scan_image(args):
    from scanners.container_layer_scanner import HybridContainerLayerScanner, print_sbom_report

    scanner = HybridContainerLayerScanner()
    if args.tar:
        report = scanner.scan_tarball(args.tar)
    elif args.image:
        report = scanner.scan_image(args.image, use_trivy_if_available=not args.no_trivy)
    else:
        print("Error: Specify either an image name or --tar path.", file=sys.stderr)
        sys.exit(1)

    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_sbom_report(report)


def cmd_remediate(args):
    from scanners.auto_remediate import remediate_manifest

    target = Path(args.path)
    if not target.is_file():
        print(f"Error: Manifest '{args.path}' not found.", file=sys.stderr)
        sys.exit(1)

    remediate_manifest(
        manifest_path=str(target),
        output_path=args.output,
        show_diff=not args.quiet,
    )


def cmd_admission(args):
    from integrations.admission_webhook import start_admission_server

    print(BANNER)
    server = start_admission_server(
        host=args.host,
        port=args.port,
        cert_file=args.cert,
        key_file=args.key,
        use_tls=not args.insecure_http,
        risk_threshold=args.risk_threshold,
        enable_mutation=not args.no_mutation,
        enable_model_11=not args.no_model_11,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Admission Controller...")
        server.server_close()


def cmd_daemon(args):
    from integrations.run_prometheus_daemon import run_continuous_daemon

    print(BANNER)
    run_continuous_daemon(
        url=args.prometheus,
        interval=args.interval,
        port=args.port,
        alpha=args.alpha,
        max_iterations=args.cycles,
    )


def cmd_audit(args):
    from reporting.generate_executive_audit import generate_compliance_reports

    print(BANNER)
    print("Generating Executive Compliance Audit (HTML & PDF)...")
    generate_compliance_reports()


def cmd_sync_cve(args):
    from scanners.cve_sync_engine import CVEDatabaseEngine

    print(BANNER)
    engine = CVEDatabaseEngine()
    if args.seed:
        engine.seed_baseline_catalog()
    if args.query:
        cves = engine.query_package_cves(args.query)
        print(f"\nDiscovered {len(cves)} CVEs affecting package '{args.query}':")
        print("-" * 80)
        for c in cves:
            print(f"{c.cve_id:<18} | {c.severity:<10} | Score: {c.cvss_score:<4.1f} | {c.description[:50]}")
        print("=" * 80)
        return
    if args.stats:
        stats = engine.get_stats()
        print(f"Total CVE Records: {stats['total_cves']} | Database Size: {stats['db_size_kb']} KB | Last Synced: {stats['last_synced']}")
        return

    print("Syncing CVE delta threat feeds (OSV.dev / NVD / GHSA)...")
    synced = engine.sync_osv_dev_delta()
    print(f"✓ Delta synchronization complete: {synced} CVE records updated.")


def cmd_web(args):
    from reporting.web_dashboard import start_web_console

    print(BANNER)
    server = start_web_console(host=args.host, port=args.port)
    print(f"Web Management Console active at: http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Web Console...")
        server.server_close()


def main():
    parser = argparse.ArgumentParser(
        prog="k8s-sec",
        description="Kubernetes Security Assessment Platform - Unified CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. scan
    p_scan = subparsers.add_parser("scan", help="Scan Kubernetes manifests or directories")
    p_scan.add_argument("path", help="Path to manifest file or directory")
    p_scan.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    p_scan.add_argument("--entropy-threshold", type=float, default=3.8, help="Shannon entropy threshold")
    p_scan.add_argument("--deep-layers", action="store_true", help="Enable deep container layer scanning")
    p_scan.add_argument("--no-recursive", action="store_true", help="Do not recurse into subdirectories")
    p_scan.add_argument("--gate", action="store_true", help="Fail with exit code 1 if score < threshold")
    p_scan.add_argument("--threshold", type=float, default=35.0, help="Security gate threshold (default: 35.0)")
    p_scan.set_defaults(func=cmd_scan)

    # 2. scan-image
    p_img = subparsers.add_parser("scan-image", help="Deep unpack container image layers & extract SBOM")
    p_img.add_argument("image", nargs="?", default=None, help="Container image tag (e.g. redis:7-alpine)")
    p_img.add_argument("--tar", default=None, help="Path to local OCI/Docker tarball archive")
    p_img.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    p_img.add_argument("--no-trivy", action="store_true", help="Disable Trivy CLI delegation fallback")
    p_img.set_defaults(func=cmd_scan_image)

    # 3. remediate
    p_rem = subparsers.add_parser("remediate", help="Auto-harden insecure Kubernetes manifests")
    p_rem.add_argument("path", help="Path to manifest file to remediate")
    p_rem.add_argument("--output", default=None, help="Output hardened YAML file path")
    p_rem.add_argument("--quiet", action="store_true", help="Do not display unified diff")
    p_rem.set_defaults(func=cmd_remediate)

    # 4. admission
    p_adm = subparsers.add_parser("admission", help="Run in-cluster admission controller webhook")
    p_adm.add_argument("--host", default="0.0.0.0", help="Host interface to bind")
    p_adm.add_argument("--port", type=int, default=8443, help="Port to listen on (default: 8443)")
    p_adm.add_argument("--cert", default=None, help="Path to TLS certificate")
    p_adm.add_argument("--key", default=None, help="Path to TLS private key")
    p_adm.add_argument("--insecure-http", action="store_true", help="Run without TLS (for local curl tests)")
    p_adm.add_argument("--risk-threshold", type=float, default=35.0, help="Minimum score to admit workloads")
    p_adm.add_argument("--no-mutation", action="store_true", help="Disable mutating webhook auto-remediation")
    p_adm.add_argument("--no-model-11", action="store_true", help="Disable Model 11 ML inference")
    p_adm.set_defaults(func=cmd_admission)

    # 5. daemon
    p_dae = subparsers.add_parser("daemon", help="Run continuous Prometheus runtime anomaly daemon")
    p_dae.add_argument("--prometheus", default="http://localhost:9090", help="Prometheus scrape URL")
    p_dae.add_argument("--interval", type=float, default=15.0, help="Scrape interval in seconds")
    p_dae.add_argument("--port", type=int, default=9197, help="Live /metrics export port")
    p_dae.add_argument("--alpha", type=float, default=0.05, help="EMA online learning rate")
    p_dae.add_argument("--cycles", type=int, default=0, help="Number of cycles (0 = infinite)")
    p_dae.set_defaults(func=cmd_daemon)

    # 6. audit
    p_aud = subparsers.add_parser("audit", help="Generate Executive Compliance Audit (PDF & HTML)")
    p_aud.set_defaults(func=cmd_audit)

    # 7. sync-cve
    p_cve = subparsers.add_parser("sync-cve", help="Sync delta CVE records & query embedded vulnerability database")
    p_cve.add_argument("--sync", action="store_true", help="Pull delta CVE records from external threat feeds")
    p_cve.add_argument("--seed", action="store_true", help="Re-seed native baseline catalog")
    p_cve.add_argument("--stats", action="store_true", help="Display CVE database statistics")
    p_cve.add_argument("--query", default=None, help="Query CVEs affecting a package name")
    p_cve.set_defaults(func=cmd_sync_cve)

    # 8. web
    p_web = subparsers.add_parser("web", help="Start self-hosted Web Management Console")
    p_web.add_argument("--host", default="0.0.0.0", help="Host interface to bind")
    p_web.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    p_web.set_defaults(func=cmd_web)

    # 9. version
    p_ver = subparsers.add_parser("version", help="Display platform version and engine capabilities")
    p_ver.set_defaults(func=cmd_version)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
