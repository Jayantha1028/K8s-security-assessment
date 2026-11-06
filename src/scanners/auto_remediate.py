#!/usr/bin/env python3
"""
auto_remediate.py
=================
Automated Kubernetes Security Remediation Engine.

Applies NSA/CISA and CIS Benchmark v2.0 hardening rules across any Kubernetes workload:
- Pod
- Deployment
- DaemonSet
- StatefulSet
- Job / CronJob

Functions:
- remediate_workload_dict: In-memory dictionary hardening (used by Admission Controller)
- remediate_yaml_string: In-memory YAML string hardening (used by Web Console & CLI)
- remediate_manifest: File-based hardening with optional unified diff
"""

import argparse
import copy
import difflib
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple
import yaml


def _get_pod_spec(workload_dict: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str]:
    """Retrieve the mutable pod spec dictionary and path prefix based on workload kind."""
    kind = workload_dict.get("kind", "")
    if kind == "Pod":
        return workload_dict.setdefault("spec", {}), "spec"
    elif kind in ("Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet"):
        spec = workload_dict.setdefault("spec", {})
        template = spec.setdefault("template", {})
        return template.setdefault("spec", {}), "spec.template.spec"
    elif kind == "CronJob":
        spec = workload_dict.setdefault("spec", {})
        job_template = spec.setdefault("jobTemplate", {})
        j_spec = job_template.setdefault("spec", {})
        template = j_spec.setdefault("template", {})
        return template.setdefault("spec", {}), "spec.jobTemplate.spec.template.spec"
    return None, ""


def remediate_workload_dict(data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Apply least-privilege security context fixes to a Kubernetes workload dictionary in memory.
    Returns: (hardened_dict, list_of_changes_applied)
    """
    if not isinstance(data, dict):
        return data, []

    hardened = copy.deepcopy(data)
    pod_spec, prefix = _get_pod_spec(hardened)
    if pod_spec is None:
        return data, []

    changes_applied = []

    # 1. Eliminate host namespaces
    if pod_spec.pop("hostNetwork", None):
        changes_applied.append("Disabled hostNetwork")
    if pod_spec.pop("hostPID", None):
        changes_applied.append("Disabled hostPID")
    if pod_spec.pop("hostIPC", None):
        changes_applied.append("Disabled hostIPC")

    # 2. Pod-level security context
    pod_sec = pod_spec.setdefault("securityContext", {})
    if not pod_sec.get("runAsNonRoot"):
        pod_sec["runAsNonRoot"] = True
        pod_sec["runAsUser"] = 10001
        pod_sec["runAsGroup"] = 10001
        changes_applied.append("Enforced runAsNonRoot (UID 10001)")

    if "seccompProfile" not in pod_sec:
        pod_sec["seccompProfile"] = {"type": "RuntimeDefault"}
        changes_applied.append("Applied RuntimeDefault seccomp profile")

    # 3. Container-level hardening
    containers = pod_spec.get("containers", [])
    has_empty_dir = False
    for c in containers:
        c_name = c.get("name", "container")
        c_sec = c.setdefault("securityContext", {})
        if c_sec.get("privileged"):
            c_sec["privileged"] = False
            changes_applied.append(f"Revoked privileged container access on '{c_name}'")
        if c_sec.get("allowPrivilegeEscalation") is not False:
            c_sec["allowPrivilegeEscalation"] = False
            changes_applied.append(f"Disabled allowPrivilegeEscalation on '{c_name}'")
        if not c_sec.get("readOnlyRootFilesystem"):
            c_sec["readOnlyRootFilesystem"] = True
            c.setdefault("volumeMounts", []).extend([
                {"name": "tmp-storage", "mountPath": "/tmp"},
                {"name": "var-run", "mountPath": "/var/run"}
            ])
            has_empty_dir = True
            changes_applied.append(f"Enforced readOnlyRootFilesystem on '{c_name}'")

        caps = c_sec.setdefault("capabilities", {})
        caps["drop"] = ["ALL"]
        if "NET_ADMIN" in caps.get("add", []):
            caps["add"].remove("NET_ADMIN")
            changes_applied.append(f"Removed risky capability NET_ADMIN on '{c_name}'")
        if not caps.get("add"):
            caps.pop("add", None)
        changes_applied.append(f"Dropped ALL Linux capabilities on '{c_name}'")

        # Clean hostPort if present
        for port in c.get("ports", []):
            if "hostPort" in port:
                port.pop("hostPort")
                changes_applied.append(f"Removed hostPort binding on '{c_name}'")

        # Ensure resource limits exist
        res = c.setdefault("resources", {})
        if "limits" not in res:
            res["limits"] = {"cpu": "250m", "memory": "128Mi"}
            res["requests"] = {"cpu": "50m", "memory": "64Mi"}
            changes_applied.append(f"Configured CPU & memory resource limits on '{c_name}'")

    if has_empty_dir:
        vols = pod_spec.setdefault("volumes", [])
        vols.extend([
            {"name": "tmp-storage", "emptyDir": {}},
            {"name": "var-run", "emptyDir": {}}
        ])

    return hardened, changes_applied


def remediate_yaml_string(yaml_text: str) -> Tuple[str, List[str]]:
    """Harden raw YAML string in-memory without writing to disk."""
    try:
        data = yaml.safe_load(yaml_text)
    except Exception:
        return yaml_text, []

    hardened_dict, changes = remediate_workload_dict(data)
    new_yaml = yaml.dump(hardened_dict, sort_keys=False)
    return new_yaml, changes


def remediate_manifest(manifest_path: str, output_path: Optional[str] = None, show_diff: bool = True):
    """File-based CLI wrapper with unified diff output."""
    path = Path(manifest_path)
    if not path.is_file():
        raise SystemExit(f"File not found: {manifest_path}")

    raw_text = path.read_text(encoding="utf-8")
    new_yaml, changes_applied = remediate_yaml_string(raw_text)

    if not changes_applied:
        print(f"Skipping {manifest_path}: No applicable workload spec found for auto-remediation.")
        return

    print(f"\n=======================================================")
    print(f"   AUTO-REMEDIATION REPORT: {path.name}")
    print(f"=======================================================")
    print(f"Applied {len(changes_applied)} Security Fixes:")
    for change in sorted(set(changes_applied)):
        print(f"  ✓ {change}")

    if show_diff:
        print("\nUnified Hardening Diff:")
        diff = difflib.unified_diff(
            raw_text.splitlines(keepends=True),
            new_yaml.splitlines(keepends=True),
            fromfile=f"original/{path.name}",
            tofile=f"remediated/{path.name}",
        )
        sys.stdout.writelines(diff)

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(new_yaml, encoding="utf-8")
        print(f"\nRemediated manifest written to: {out_p}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated Kubernetes Security Remediation Engine")
    parser.add_argument("manifest", help="Path to input YAML manifest")
    parser.add_argument("--output", "-o", default=None, help="Path to write remediated YAML")
    parser.add_argument("--diff", action="store_true", default=True, help="Display unified diff")
    args = parser.parse_args()

    remediate_manifest(args.manifest, output_path=args.output, show_diff=args.diff)
