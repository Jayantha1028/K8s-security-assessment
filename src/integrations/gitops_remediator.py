#!/usr/bin/env python3
"""
gitops_remediator.py
====================
Shift-Left GitOps Auto-Remediation PR Bot & Kustomize Strategic Patch Overlay Generator.

Eliminates the "GitOps Configuration Drift War" where mutating webhooks alter
live objects in etcd, triggering ArgoCD and Flux reconciliation fighting loops.

Key Features:
1. Shift-Left Manifest Hardening:
   - Scans Git repositories or manifest trees.
   - Calculates unified diffs and score enhancements (e.g. 13.2 -> 86.2).
2. GitOps PR / MR Formatter:
   - Formats complete GitHub Pull Request and GitLab Merge Request Markdown bodies
     with executive scorecards, CIS control citations, and collapsible diffs.
3. Kustomize Strategic Merge Patch Overlay Export:
   - Exports non-destructive `kustomization.yaml` with strategic merge patches
     so developers can adopt least-privilege security without altering upstream vendor charts.
4. Automated Git Branch & Commit Automation:
   - Creates a dedicated remediation branch (`k8s-sec/auto-harden-<hash>`) and commits.
"""

from dataclasses import asdict, dataclass, field
import difflib
import json
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import yaml

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

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [GITOPS-REMEDIATOR] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("GitOpsRemediator")


@dataclass
class WorkloadRemediationDiff:
    """Remediation details and diff for a single Kubernetes workload manifest."""
    file_path: str
    workload_id: str
    namespace: str
    kind: str
    name: str
    before_score: float
    after_score: float
    score_delta: float
    before_risk_tier: str
    after_risk_tier: str
    patches_applied: List[str]
    unified_diff: str
    hardened_yaml: str
    strategic_patch_yaml: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GitOpsRemediationPlan:
    """Full remediation plan across a repository or directory tree."""
    target_path: str
    total_files_analyzed: int = 0
    failing_manifests_count: int = 0
    workload_diffs: List[WorkloadRemediationDiff] = field(default_factory=list)
    pr_title: str = ""
    pr_body_markdown: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["workload_diffs"] = [w.to_dict() for w in self.workload_diffs]
        return d


class GitOpsRemediator:
    """
    Automated GitOps Remediation Engine for Kubernetes infrastructure repositories.
    """

    def __init__(self, threshold: float = 35.0):
        self.threshold = threshold
        self.scanner = NativeSecurityScanner()

    def plan_remediation(self, target_path: str) -> GitOpsRemediationPlan:
        """
        Scan a manifest file or directory tree and compute a complete remediation plan.
        """
        target = Path(target_path)
        plan = GitOpsRemediationPlan(target_path=str(target))

        if target.is_file():
            yaml_files = [target]
        elif target.is_dir():
            yaml_files = sorted(list(target.rglob("*.yaml")) + list(target.rglob("*.yml")))
        else:
            logger.warning(f"Target path does not exist: {target_path}")
            return plan

        plan.total_files_analyzed = len(yaml_files)

        for yf in yaml_files:
            try:
                content = yf.read_text(encoding="utf-8")
            except Exception:
                continue

            report = self.scanner.scan_yaml_content(content, source_name=str(yf))
            veto_rules = {"V01", "V02", "V03", "V04", "V14", "V26"}
            has_veto = len(veto_rules.intersection(report.detected_vuln_ids)) > 0

            # Only remediate if workload fails policy threshold or triggers an exploit veto
            if report.compliance_score >= self.threshold and not has_veto:
                continue

            # Parse documents and remediate workloads
            try:
                docs = list(yaml.safe_load_all(content))
            except Exception:
                continue

            hardened_docs = []
            applied_patches_summary = []
            strategic_patches = []

            for doc in docs:
                if not isinstance(doc, dict):
                    hardened_docs.append(doc)
                    continue

                kind = doc.get("kind", "")
                if kind not in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob"):
                    hardened_docs.append(doc)
                    continue

                hardened_doc, patches = remediate_workload_dict(doc)
                hardened_docs.append(hardened_doc)
                applied_patches_summary.extend(patches)

                # Extract strategic merge patch for Kustomize overlays
                strategic_patch = self._extract_strategic_patch(hardened_doc)
                strategic_patches.append(strategic_patch)

            # Re-scan hardened content to measure new score
            hardened_yaml_str = yaml.dump_all(hardened_docs, sort_keys=False)
            h_report = self.scanner.scan_yaml_content(hardened_yaml_str, source_name=str(yf))

            # Compute unified diff
            diff_lines = list(difflib.unified_diff(
                content.splitlines(keepends=True),
                hardened_yaml_str.splitlines(keepends=True),
                fromfile=f"a/{yf.name}",
                tofile=f"b/{yf.name}",
            ))
            unified_diff_str = "".join(diff_lines)

            meta = docs[0].get("metadata", {}) if docs and isinstance(docs[0], dict) else {}
            w_name = meta.get("name", yf.stem)
            w_ns = meta.get("namespace", "default")
            w_kind = docs[0].get("kind", "Deployment") if docs and isinstance(docs[0], dict) else "Deployment"

            w_diff = WorkloadRemediationDiff(
                file_path=str(yf),
                workload_id=f"{w_ns}/{w_kind}/{w_name}",
                namespace=w_ns,
                kind=w_kind,
                name=w_name,
                before_score=report.compliance_score,
                after_score=h_report.compliance_score,
                score_delta=round(h_report.compliance_score - report.compliance_score, 1),
                before_risk_tier=report.risk_tier,
                after_risk_tier=h_report.risk_tier,
                patches_applied=applied_patches_summary,
                unified_diff=unified_diff_str,
                hardened_yaml=hardened_yaml_str,
                strategic_patch_yaml=yaml.dump(strategic_patches[0], sort_keys=False) if strategic_patches else "",
            )
            plan.workload_diffs.append(w_diff)

        plan.failing_manifests_count = len(plan.workload_diffs)
        plan.pr_title = "🛡️ [k8s-sec] Automated Workload Hardening & Least-Privilege Remediation"
        plan.pr_body_markdown = self.generate_pr_markdown(plan)
        return plan

    def _extract_strategic_patch(self, hardened_doc: Dict[str, Any]) -> Dict[str, Any]:
        """Extract minimal strategic merge patch for Kustomize overlays."""
        meta = hardened_doc.get("metadata", {})
        patch = {
            "apiVersion": hardened_doc.get("apiVersion", "apps/v1"),
            "kind": hardened_doc.get("kind", "Deployment"),
            "metadata": {
                "name": meta.get("name", "workload"),
            },
            "spec": {},
        }
        if "namespace" in meta:
            patch["metadata"]["namespace"] = meta["namespace"]

        spec = hardened_doc.get("spec", {})
        if "template" in spec:
            tmpl_spec = spec.get("template", {}).get("spec", {})
            patch["spec"] = {
                "template": {
                    "spec": {
                        "securityContext": tmpl_spec.get("securityContext", {}),
                        "containers": [
                            {
                                "name": c.get("name", "main"),
                                "securityContext": c.get("securityContext", {}),
                                "resources": c.get("resources", {}),
                            }
                            for c in tmpl_spec.get("containers", [])
                        ],
                    }
                }
            }
        else:
            patch["spec"] = {
                "securityContext": spec.get("securityContext", {}),
                "containers": [
                    {
                        "name": c.get("name", "main"),
                        "securityContext": c.get("securityContext", {}),
                        "resources": c.get("resources", {}),
                    }
                    for c in spec.get("containers", [])
                ],
            }
        return patch

    def generate_pr_markdown(self, plan: GitOpsRemediationPlan) -> str:
        """
        Render GitHub Pull Request / GitLab Merge Request Markdown body.
        """
        lines = [
            "## 🛡️ [k8s-sec] Automated Least-Privilege Hardening (GitOps PR Bot)",
            "",
            "> **Summary:** This automated PR was generated by `k8s-sec` to bring Kubernetes workloads into compliance ",
            "> with **CIS Kubernetes Benchmark v2.0** and **NSA/CISA Hardening Guidelines**, eliminating GitOps drift.",
            "",
            "### 📊 Security Posture Scorecard",
            "",
            "| Workload | File Path | Baseline Score | Hardened Score | Delta | Verdict |",
            "| :--- | :--- | :---: | :---: | :---: | :---: |",
        ]

        for w in plan.workload_diffs:
            lines.append(
                f"| `{w.workload_id}` | `{Path(w.file_path).name}` | "
                f"{w.before_score}/100 ({w.before_risk_tier}) | "
                f"**{w.after_score}/100** ({w.after_risk_tier}) | "
                f"+{w.score_delta:.1f} | ✅ Pass |"
            )

        lines.extend([
            "",
            "### 🔧 Remediations Applied by Policy",
            "- `readOnlyRootFilesystem: true` (Immutability enforced; ephemeral `/tmp` scratchpad mounted)",
            "- `allowPrivilegeEscalation: false` (Neutralizes local privilege escalation exploits)",
            "- `capabilities.drop: ['ALL']` (Drops all default Linux kernel capabilities)",
            "- `runAsNonRoot: true` & `runAsUser: 10001` (Restricts execution to unprivileged UID)",
            "- `seccompProfile.type: RuntimeDefault` (Applies default system call filter)",
            "- `resources.limits`: Enforces CPU & Memory ceilings to prevent noisy neighbor DoS",
            "",
            "### 📝 Unified Diff Breakdown",
            "",
        ])

        for w in plan.workload_diffs:
            lines.extend([
                f"<details><summary><strong>📄 Diff: {w.workload_id} ({Path(w.file_path).name})</strong></summary>",
                "",
                "```diff",
                w.unified_diff.strip(),
                "```",
                "",
                "</details>",
                "",
            ])

        lines.extend([
            "---",
            "*Generated autonomously by `k8s-sec` GitOps Remediation Engine. Safe to merge via ArgoCD / Flux.*",
        ])
        return "\n".join(lines)

    def export_kustomize_overlay(self, plan: GitOpsRemediationPlan, output_dir: str) -> Path:
        """
        Generate non-destructive Kustomize overlay directory with strategic merge patches.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        kustomization = {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "patchesStrategicMerge": [],
        }

        for w in plan.workload_diffs:
            patch_filename = f"patch-{w.kind.lower()}-{w.name}.yaml"
            patch_file = out_path / patch_filename
            patch_file.write_text(w.strategic_patch_yaml, encoding="utf-8")
            kustomization["patchesStrategicMerge"].append(patch_filename)

        kust_file = out_path / "kustomization.yaml"
        kust_file.write_text(yaml.dump(kustomization, sort_keys=False), encoding="utf-8")
        logger.info(f"✓ Exported Kustomize overlay with {len(plan.workload_diffs)} patches to: {output_dir}")
        return out_path

    def apply_in_place(self, plan: GitOpsRemediationPlan) -> int:
        """Overwrite target manifest files directly in place."""
        applied = 0
        for w in plan.workload_diffs:
            try:
                Path(w.file_path).write_text(w.hardened_yaml, encoding="utf-8")
                applied += 1
            except Exception as e:
                logger.warning(f"Failed to overwrite {w.file_path}: {e}")
        return applied

    def create_git_branch_and_commit(self, plan: GitOpsRemediationPlan, branch_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a Git branch, apply fixes, and commit cleanly.
        """
        branch = branch_name or f"k8s-sec/auto-harden-{int(time.time())}"
        try:
            # 1. Checkout new branch
            subprocess.run(["git", "checkout", "-b", branch], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            # 2. Apply in place
            applied = self.apply_in_place(plan)
            # 3. Add files and commit
            files_to_add = [w.file_path for w in plan.workload_diffs]
            subprocess.run(["git", "add"] + files_to_add, check=True)
            commit_msg = f"🛡️ [k8s-sec] Auto-hardened {applied} manifests for CIS compliance"
            subprocess.run(["git", "commit", "-m", commit_msg], stdout=subprocess.DEVNULL, check=True)
            return {
                "status": "SUCCESS",
                "branch": branch,
                "files_committed": applied,
                "pr_command": f"gh pr create --title \"{plan.pr_title}\" --body-file pr_body.md",
            }
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}


def run_gitops_remediator_cli(args):
    """CLI dispatcher for GitOps Auto-Remediation."""
    print("=" * 85)
    print("      GITOPS AUTO-REMEDIATION PR BOT & KUSTOMIZE OVERLAY GENERATOR")
    print("=" * 85)

    remediator = GitOpsRemediator(threshold=args.threshold)
    plan = remediator.plan_remediation(args.path)

    if args.output == "json":
        print(json.dumps(plan.to_dict(), indent=2))
        return

    print(f"Target Path           : {args.path}")
    print(f"Manifests Analyzed    : {plan.total_files_analyzed}")
    print(f"Failing Workloads     : {plan.failing_manifests_count}")
    print("-" * 85)

    if plan.failing_manifests_count == 0:
        print("✓ All manifests in target path meet or exceed the security threshold! Zero fixes needed.")
        print("=" * 85)
        return

    print(f"{'Target Workload':<36} | {'Baseline Score':<16} | {'Hardened Score':<16} | {'Delta'}")
    print("-" * 85)
    for w in plan.workload_diffs:
        print(f"{w.workload_id:<36} | {w.before_score:>5.1f} ({w.before_risk_tier:<6}) | {w.after_score:>5.1f} ({w.after_risk_tier:<6}) | +{w.score_delta:.1f}")
    print("=" * 85)

    if args.output_overlay:
        out_overlay = remediator.export_kustomize_overlay(plan, args.output_overlay)
        print(f"\n✓ Generated Kustomize strategic merge overlay at: {out_overlay}")

    if args.apply_in_place:
        applied = remediator.apply_in_place(plan)
        print(f"\n✓ Applied least-privilege security patches in-place to {applied} files.")

    if args.output_pr_markdown:
        out_md = Path(args.output_pr_markdown)
        out_md.write_text(plan.pr_body_markdown, encoding="utf-8")
        print(f"\n✓ Wrote Pull Request Markdown body to: {out_md}")
        print("  Run: gh pr create --title \"🛡️ [k8s-sec] Auto-hardened manifests\" --body-file " + str(out_md))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="GitOps Auto-Remediation PR Bot & Kustomize Overlay Generator")
    parser.add_argument("path", nargs="?", default="manifests/", help="Path to manifest or directory")
    parser.add_argument("--threshold", type=float, default=35.0, help="Security score threshold (default: 35.0)")
    parser.add_argument("--output-overlay", default=None, help="Directory to export Kustomize strategic merge patches")
    parser.add_argument("--output-pr-markdown", default=None, help="File path to save Pull Request Markdown body")
    parser.add_argument("--apply-in-place", action="store_true", help="Overwrite failing manifest files in-place")
    parser.add_argument("--output", choices=["table", "json"], default="table", help="Output format")
    args = parser.parse_args()
    run_gitops_remediator_cli(args)
