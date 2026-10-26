#!/usr/bin/env python3
"""
Automated Kubernetes Security Remediation Generator.

Analyzes an insecure Kubernetes workload manifest, applies NSA/CISA hardening
rules, and generates a remediated, hardened YAML manifest with a unified diff.

Run separately as a side-output (NOT part of main pipeline):
    python3 src/auto_remediate.py manifests/insecure/weak-deployment.yaml [--output manifests/remediated/hardened.yaml] [--diff]
"""

import argparse
import copy
import difflib
import sys
from pathlib import Path
import yaml


def remediate_manifest(manifest_path, output_path=None, show_diff=True):
    path = Path(manifest_path)
    if not path.is_file():
        raise SystemExit(f"File not found: {manifest_path}")

    raw_text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw_text)

    if not isinstance(data, dict) or data.get("kind") != "Deployment":
        print(f"Skipping {manifest_path}: Only Deployment manifests are currently auto-remediated.")
        return

    hardened = copy.deepcopy(data)
    spec = hardened.setdefault("spec", {})
    template = spec.setdefault("template", {})
    pod_spec = template.setdefault("spec", {})

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
        c_sec = c.setdefault("securityContext", {})
        if c_sec.get("privileged"):
            c_sec["privileged"] = False
            changes_applied.append(f"Revoked privileged container access on '{c.get('name')}'")
        if c_sec.get("allowPrivilegeEscalation") is not False:
            c_sec["allowPrivilegeEscalation"] = False
            changes_applied.append(f"Disabled allowPrivilegeEscalation on '{c.get('name')}'")
        if not c_sec.get("readOnlyRootFilesystem"):
            c_sec["readOnlyRootFilesystem"] = True
            c.setdefault("volumeMounts", []).extend([
                {"name": "tmp-storage", "mountPath": "/tmp"},
                {"name": "var-run", "mountPath": "/var/run"}
            ])
            has_empty_dir = True
            changes_applied.append(f"Enforced readOnlyRootFilesystem on '{c.get('name')}'")

        caps = c_sec.setdefault("capabilities", {})
        caps["drop"] = ["ALL"]
        if "NET_ADMIN" in caps.get("add", []):
            caps["add"].remove("NET_ADMIN")
            changes_applied.append("Removed risky capability NET_ADMIN")
        if not caps.get("add"):
            caps.pop("add", None)
        changes_applied.append(f"Dropped ALL Linux capabilities on '{c.get('name')}'")

        # Clean hostPort if present
        for port in c.get("ports", []):
            if "hostPort" in port:
                port.pop("hostPort")
                changes_applied.append("Removed hostPort binding")

        # Ensure resource limits exist
        res = c.setdefault("resources", {})
        if "limits" not in res:
            res["limits"] = {"cpu": "250m", "memory": "128Mi"}
            res["requests"] = {"cpu": "50m", "memory": "64Mi"}
            changes_applied.append(f"Configured CPU & memory resource limits on '{c.get('name')}'")

    if has_empty_dir:
        vols = pod_spec.setdefault("volumes", [])
        vols.extend([
            {"name": "tmp-storage", "emptyDir": {}},
            {"name": "var-run", "emptyDir": {}}
        ])

    new_yaml = yaml.dump(hardened, sort_keys=False)

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
    parser = argparse.ArgumentParser(description="Automated Kubernetes Security Remediation")
    parser.add_argument("manifest", help="Path to input YAML manifest")
    parser.add_argument("--output", "-o", default=None, help="Path to write remediated YAML")
    parser.add_argument("--diff", action="store_true", default=True, help="Display unified diff")
    args = parser.parse_args()

    remediate_manifest(args.manifest, output_path=args.output, show_diff=args.diff)
