#!/usr/bin/env python3
"""
cluster_scanner.py
==================
Live In-Cluster Security Posture & Vulnerability Scanner (CSPM Engine).

Audits live running Kubernetes workloads directly from the Kubernetes Control Plane API
(kube-apiserver) without needing local YAML manifest files.

Capabilities:
1. Dual-Mode Control Plane Ingestion:
   - In-Cluster: Uses ServiceAccount token (/var/run/secrets/kubernetes.io/serviceaccount/)
   - Out-of-Cluster: Uses active kubectl context or ~/.kube/config
2. Pure In-Memory Workload Auditing:
   - Streams live JSON objects directly into NativeSecurityScanner (56 rules)
   - Evaluates Model 11 Bayesian Ridge Stacking Ensemble
   - Enforces Catastrophic Exploit Veto (Privileged, Root UID 0, HostPID, Cluster-Admin)
3. Instant Remediation Output:
   - Optional 1-click export of hardened manifests for failing workloads
"""

import argparse
from dataclasses import asdict, dataclass, field
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Path resolution
_SRC_DIR = Path(__file__).resolve().parents[1]
_CORE_DIR = _SRC_DIR / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
import paths
from scanners.native_security_scanner import NativeSecurityScanner, ScanReport
from scanners.auto_remediate import remediate_workload_dict
from models.model_loader import load_master_model

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [CLUSTER-SCANNER] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ClusterScanner")


@dataclass
class WorkloadAuditResult:
    workload_id: str
    namespace: str
    kind: str
    name: str
    compliance_score: float
    risk_tier: str
    veto_triggered: bool
    findings_count: int
    top_findings: List[str] = field(default_factory=list)
    remediated_yaml: Optional[str] = None

    @property
    def has_exploit_veto(self) -> bool:
        return self.veto_triggered

    @property
    def security_score(self) -> float:
        return self.compliance_score

    def to_dict(self):
        d = asdict(self)
        d["has_exploit_veto"] = self.has_exploit_veto
        d["security_score"] = self.security_score
        return d


@dataclass
class LiveClusterReport:
    total_workloads: int = 0
    average_score: float = 100.0
    cluster_risk_tier: str = "Low"
    scan_latency_ms: float = 0.0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    veto_count: int = 0
    namespace_breakdown: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    workload_results: List[WorkloadAuditResult] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    @property
    def cluster_score(self) -> float:
        return self.average_score

    @property
    def worst_workload_score(self) -> float:
        return min((w.compliance_score for w in self.workload_results), default=100.0)

    @property
    def passed_workloads(self) -> int:
        return self.low_risk_count + self.medium_risk_count

    @property
    def failing_workloads(self) -> int:
        return self.high_risk_count

    @property
    def remediated_count(self) -> int:
        return sum(1 for w in self.workload_results if w.remediated_yaml is not None)

    @property
    def leaderboard(self) -> List[WorkloadAuditResult]:
        return self.workload_results

    def to_dict(self):
        d = asdict(self)
        d["cluster_score"] = self.cluster_score
        d["worst_workload_score"] = self.worst_workload_score
        d["passed_workloads"] = self.passed_workloads
        d["failing_workloads"] = self.failing_workloads
        d["remediated_count"] = self.remediated_count
        d["workload_results"] = [w.to_dict() for w in self.workload_results]
        d["leaderboard"] = [w.to_dict() for w in self.leaderboard]
        return d


class LiveClusterScanner:
    """Live In-Cluster Kubernetes Security Scanner."""

    def __init__(self, kubeconfig: Optional[str] = None):
        self.kubeconfig = kubeconfig
        self.scanner = NativeSecurityScanner()
        self.master_bundle = load_master_model()
        self.has_kubectl = shutil.which("kubectl") is not None

    def is_cluster_reachable(self) -> bool:
        """Check if Kubernetes cluster is responding via kubectl or in-cluster API."""
        if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token"):
            return True
        if not self.has_kubectl:
            return False
        try:
            cmd = ["kubectl", "version", "--client", "-o", "json"]
            if self.kubeconfig:
                cmd.extend(["--kubeconfig", self.kubeconfig])
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            if res.returncode != 0:
                return False
            # Verify cluster connectivity
            res2 = subprocess.run(["kubectl", "get", "ns"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            return res2.returncode == 0
        except Exception:
            return False

    def fetch_live_workloads(
        self,
        namespace: Optional[str] = None,
        resources: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch live Kubernetes objects directly from kube-apiserver."""
        target_resources = resources or ["pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"]
        res_str = ",".join(target_resources)

        cmd = ["kubectl", "get", res_str, "-o", "json"]
        if namespace:
            cmd.extend(["-n", namespace])
        else:
            cmd.append("--all-namespaces")
        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])

        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        if proc.returncode != 0:
            logger.warning(f"kubectl failed to query live cluster: {proc.stderr.strip()[:100]}")
            return []

        try:
            data = json.loads(proc.stdout)
            items = data.get("items", [])
            logger.info(f"Retrieved {len(items)} live workloads from cluster.")
            return items
        except Exception as e:
            logger.error(f"Failed to parse live cluster JSON: {e}")
            return []

    def scan_cluster(
        self,
        namespace: Optional[str] = None,
        remediate_dir: Optional[str] = None,
        mock_objects: Optional[List[Dict[str, Any]]] = None,
        gate_threshold: float = 35.0,
    ) -> LiveClusterReport:
        """
        Execute full live cluster security posture audit across active workloads.
        """
        t0 = time.time()
        report = LiveClusterReport()

        # Ingest workloads
        if mock_objects is not None:
            workloads = mock_objects
        else:
            workloads = self.fetch_live_workloads(namespace=namespace)

        if not workloads:
            report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
            return report

        report.total_workloads = len(workloads)
        total_score = 0.0
        rem_path = Path(remediate_dir) if remediate_dir else None
        if rem_path:
            rem_path.mkdir(parents=True, exist_ok=True)

        for obj in workloads:
            kind = obj.get("kind", "Unknown")
            metadata = obj.get("metadata", {}) or {}
            name = metadata.get("name", "unnamed")
            ns = metadata.get("namespace", namespace or "default")
            target_id = f"{ns}/{kind}/{name}"

            # Filter out non-workload objects
            if kind not in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"):
                continue

            # 1. Native AST Evaluation (56 Rules + Shannon Entropy)
            scan_rep = self.scanner.scan_dict(obj, source_name=target_id)
            score = scan_rep.compliance_score
            risk_tier = scan_rep.risk_tier

            # 2. Catastrophic Exploit Veto Check
            veto_rules = {"V01", "V02", "V03", "V04", "V14", "V26"}
            triggered_vetoes = sorted(list(veto_rules.intersection(scan_rep.detected_vuln_ids)))
            is_veto = len(triggered_vetoes) > 0

            # 3. Model 11 Inference
            if self.master_bundle is not None and not is_veto:
                try:
                    ml_score, ml_risk = self.master_bundle.predict(scan_rep.features)
                    score = ml_score
                    risk_tier = ml_risk
                except Exception:
                    pass

            if is_veto:
                score = min(score, 35.0)
                risk_tier = "High"
                report.veto_count += 1

            total_score += score
            if risk_tier == "High":
                report.high_risk_count += 1
            elif risk_tier == "Medium":
                report.medium_risk_count += 1
            else:
                report.low_risk_count += 1

            # Track Namespace Breakdown
            if ns not in report.namespace_breakdown:
                report.namespace_breakdown[ns] = {"total": 0, "scores": [], "high_risk": 0}
            report.namespace_breakdown[ns]["total"] += 1
            report.namespace_breakdown[ns]["scores"].append(score)
            if risk_tier == "High":
                report.namespace_breakdown[ns]["high_risk"] += 1

            # Auto-Remediation if requested and failing
            remediated_yaml_str = None
            if rem_path and (score < gate_threshold or risk_tier == "High"):
                import yaml
                hardened_dict, _ = remediate_workload_dict(obj)
                remediated_yaml_str = yaml.dump(hardened_dict, sort_keys=False)
                out_file = rem_path / f"{ns}_{kind.lower()}_{name}_hardened.yaml"
                out_file.write_text(remediated_yaml_str, encoding="utf-8")

            top_findings = [f"{f.vuln_id}: {f.title}" for f in scan_rep.findings[:3]]
            report.workload_results.append(WorkloadAuditResult(
                workload_id=target_id,
                namespace=ns,
                kind=kind,
                name=name,
                compliance_score=round(score, 1),
                risk_tier=risk_tier,
                veto_triggered=is_veto,
                findings_count=len(scan_rep.findings),
                top_findings=top_findings,
                remediated_yaml=remediated_yaml_str,
            ))

        # Compute cluster averages
        if report.workload_results:
            report.average_score = round(total_score / len(report.workload_results), 1)
            if report.average_score < 40.0 or report.high_risk_count > 0:
                report.cluster_risk_tier = "High"
            elif report.average_score < 70.0:
                report.cluster_risk_tier = "Medium"
            else:
                report.cluster_risk_tier = "Low"

        # Finalize namespace breakdown averages
        for ns, stats in report.namespace_breakdown.items():
            scores = stats.pop("scores")
            stats["avg_score"] = round(sum(scores) / len(scores), 1) if scores else 100.0
            stats["failing"] = stats.get("high_risk", 0)

        # Sort workloads: worst offenders first
        report.workload_results.sort(key=lambda w: (w.compliance_score, -w.findings_count))
        report.scan_latency_ms = round((time.time() - t0) * 1000, 2)
        return report


def print_cluster_report(report: LiveClusterReport):
    """Render terminal report with leaderboard and security posture."""
    print("=" * 85)
    print("      LIVE IN-CLUSTER KUBERNETES SECURITY POSTURE AUDIT (CSPM)")
    print("=" * 85)
    print(f"Scanned Workloads  : {len(report.workload_results)} live objects across cluster")
    print(f"Cluster Security   : {report.average_score} / 100 ({report.cluster_risk_tier.upper()} RISK)")
    print(f"Risk Distribution  : {report.high_risk_count} High | {report.medium_risk_count} Medium | {report.low_risk_count} Low")
    print(f"Exploit Veto Flags : {report.veto_count} active critical exploit vetos")
    print(f"Scan Duration      : {report.scan_latency_ms:.1f} ms")
    print("-" * 85)

    if report.namespace_breakdown:
        print("NAMESPACE COMPLIANCE BREAKDOWN:")
        print(f"{'Namespace':<24} | {'Workloads':<10} | {'Avg Score':<12} | {'High Risk Count'}")
        print("-" * 85)
        for ns, data in sorted(report.namespace_breakdown.items()):
            print(f"{ns:<24} | {data['total']:<10} | {data['avg_score']:<12.1f} | {data['high_risk']}")
        print("-" * 85)

    if report.workload_results:
        print("WORST-OFFENDER WORKLOAD LEADERBOARD:")
        print(f"{'Target Workload':<36} | {'Score':<8} | {'Tier':<8} | {'Top Security Violation'}")
        print("-" * 85)
        for w in report.workload_results[:8]:
            top = w.top_findings[0] if w.top_findings else "None (Hardened)"
            if len(top) > 30:
                top = top[:27] + "..."
            print(f"{w.workload_id:<36} | {w.compliance_score:<8.1f} | {w.risk_tier:<8} | {top}")
        if len(report.workload_results) > 8:
            print(f"... [{len(report.workload_results) - 8} additional live workloads cataloged]")
    print("=" * 85 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Live In-Cluster Kubernetes Security Scanner")
    parser.add_argument("--namespace", "-n", default=None, help="Specific namespace to scan (default: all namespaces)")
    parser.add_argument("--remediate-out", default=None, help="Directory to export auto-remediated YAML manifests")
    parser.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--gate", action="store_true", help="Fail with exit code 1 if cluster score < threshold")
    parser.add_argument("--threshold", type=float, default=35.0, help="Policy gate threshold (default: 35.0)")

    args = parser.parse_args()
    scanner = LiveClusterScanner()

    if not scanner.is_cluster_reachable():
        print("Error: No active Kubernetes cluster connection detected via kubectl or in-cluster ServiceAccount.", file=sys.stderr)
        print("Please check your ~/.kube/config or verify that your cluster is running.", file=sys.stderr)
        sys.exit(1)

    report = scanner.scan_cluster(
        namespace=args.namespace,
        remediate_dir=args.remediate_out,
        gate_threshold=args.threshold,
    )

    if args.output == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_cluster_report(report)

    if args.gate and (report.average_score < args.threshold or report.high_risk_count > 0):
        print(f"[GATE FAILED] Cluster security posture does not meet policy threshold ({report.average_score:.1f} < {args.threshold:.1f})!", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
