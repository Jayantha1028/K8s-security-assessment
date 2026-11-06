"""Build final_security_dataset.csv from every collected cluster assessment.

Reads data/raw/latest, data/raw/snapshots/* and data/raw/continuous_snapshots/*
(each holding a ``secure`` and an ``insecure`` collection), scores each one
and writes one row per (snapshot, environment).
"""

import argparse
import json
import math
import re
from pathlib import Path

import pandas as pd

# Ensure core and parent src are in sys.path
import sys
from pathlib import Path
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
    sys.path.insert(0, str(_CORE_DIR.parent))
import paths
from data_cleaning import clean_dataset
from scan_parser import parse_kubescape_data

ENVIRONMENTS = ["secure", "insecure"]

REQUIRED_FILES = [
    "kubescape.json", "trivy.json", "cluster_features.json", "falco.log",
]
REQUIRED_CLUSTER_KEYS = [
    "rbac_risk_score", "service_account_permission_score",
    "wildcard_rbac_rules", "cluster_admin_bindings", "rbac_binding_count",
    "privileged_count", "root_execution_count", "host_path_count",
    "risky_capability_count", "host_port_count",
    "missing_network_policies", "workload_count",
]

# Every count/score column assembled from Kubescape, Trivy, Falco and kubectl
# output. clean_dataset makes a stray NaN explicit (and reports it) instead of
# silently handing the model a float NaN feature.
COUNT_COLUMNS = [
    "kubescape_failed", "kubescape_passed", "kubescape_skipped",
    "kubescape_critical", "kubescape_high", "kubescape_medium",
    "kubescape_low",
    "critical_cve_count", "high_cve_count",
    "critical_misconfig_count", "high_misconfig_count", "secret_count",
    "rbac_risk_score", "service_account_permission_score",
    "wildcard_rbac_rules", "cluster_admin_bindings", "rbac_binding_count",
    "privileged_count", "root_execution_count", "host_path_count",
    "risky_capability_count", "host_port_count",
    "missing_network_policies", "workload_count",
    "falco_alert_count", "falco_critical_count", "falco_warning_count",
]


def read_json(path):
    with open(path) as file:
        return json.load(file)


def trivy_counts(data):
    """Count findings in an already-parsed Trivy JSON report."""
    counts = {
        "critical_cve_count": 0,
        "high_cve_count": 0,
        "critical_misconfig_count": 0,
        "high_misconfig_count": 0,
        "secret_count": 0,
    }

    def walk(value):
        if isinstance(value, dict):
            vulnerabilities = value.get("Vulnerabilities")
            if isinstance(vulnerabilities, list):
                for item in vulnerabilities:
                    severity = str(item.get("Severity", "")).upper()

                    if severity == "CRITICAL":
                        counts["critical_cve_count"] += 1
                    elif severity == "HIGH":
                        counts["high_cve_count"] += 1

            misconfigs = value.get("Misconfigurations")
            if isinstance(misconfigs, list):
                for item in misconfigs:
                    status = str(item.get("Status", "FAIL")).upper()

                    if status != "FAIL":
                        continue

                    severity = str(item.get("Severity", "")).upper()

                    if severity == "CRITICAL":
                        counts["critical_misconfig_count"] += 1
                    elif severity == "HIGH":
                        counts["high_misconfig_count"] += 1

            secrets = value.get("Secrets")
            if isinstance(secrets, list):
                counts["secret_count"] += len(secrets)

            for child in value.values():
                walk(child)

        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return counts


# Count only real alert lines, not startup messages or rule descriptions
# that happen to contain the word "Warning" or "Critical". Falco's text
# output looks like "08:00:00.123456789: Warning <rule text>" (optionally
# with a full ISO timestamp) and its JSON output has a "priority" field.
FALCO_TEXT_RE = re.compile(
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?:\s+"
    r"(Emergency|Alert|Critical|Warning)\b",
    re.IGNORECASE,
)
FALCO_JSON_RE = re.compile(
    r'"priority"\s*:\s*"(Emergency|Alert|Critical|Warning)"',
    re.IGNORECASE,
)
FALCO_CRITICAL = {"emergency", "alert", "critical"}


def falco_counts(path):
    counts = {
        "falco_alert_count": 0,
        "falco_critical_count": 0,
        "falco_warning_count": 0,
    }

    for line in path.read_text(errors="replace").splitlines():
        match = FALCO_TEXT_RE.search(line) or FALCO_JSON_RE.search(line)
        if not match:
            continue

        if match.group(1).lower() in FALCO_CRITICAL:
            counts["falco_critical_count"] += 1
        else:
            counts["falco_warning_count"] += 1

    counts["falco_alert_count"] = (
        counts["falco_critical_count"] + counts["falco_warning_count"]
    )
    return counts


def load_collection(folder):
    """
    Read and validate one collection folder in a single pass.

    Returns (evidence, None) when the folder is complete, or (None, reason)
    when it is incomplete or unreadable. A missing or truncated scan must not
    be treated as "zero findings": that would turn a failed scan into a high
    security score, so such folders are skipped with a warning instead.
    Each JSON file is parsed exactly once.
    """
    for name in REQUIRED_FILES:
        path = folder / name
        if not path.is_file():
            return None, f"missing {name}"
        if path.suffix == ".json" and path.stat().st_size == 0:
            return None, f"empty {name}"

    docs = {}
    for name in ("kubescape.json", "trivy.json", "cluster_features.json"):
        try:
            docs[name] = read_json(folder / name)
        except (OSError, ValueError) as error:
            return None, f"unreadable {name} ({error})"

    cluster = docs["cluster_features.json"]
    if not isinstance(cluster, dict):
        return None, "cluster_features.json is not a JSON object"
    absent = [key for key in REQUIRED_CLUSTER_KEYS if key not in cluster]
    if absent:
        return None, f"cluster_features.json lacks keys: {', '.join(absent)}"

    try:
        kubescape = parse_kubescape_data(
            docs["kubescape.json"], source=folder / "kubescape.json"
        )
    except (OSError, ValueError, TypeError) as error:
        return None, f"kubescape.json not parseable ({error})"

    return {
        **kubescape,
        **trivy_counts(docs["trivy.json"]),
        **cluster,
        **falco_counts(folder / "falco.log"),
    }, None


def score_row(row):
    """
    Transparent multi-pillar bounded evidence score.
    Balances Workload Hardening, CVEs, RBAC, Compliance, and Runtime Telemetry
    so that a single high-count indicator does not run away and wipe out the score.
    """
    # Pillar 1: Workload & Pod Hardening (max 25 pts penalty)
    p_workload = min(25.0, (
        row.get("privileged_count", 0) * 10.0
        + row.get("root_execution_count", 0) * 3.0
        + row.get("risky_capability_count", 0) * 4.0
        + row.get("host_path_count", 0) * 4.0
        + row.get("host_port_count", 0) * 2.0
    ))

    # Pillar 2: Vulnerabilities & Supply Chain (max 30 pts penalty)
    # Square-root scaling provides sub-linear diminishing penalty for repetitive CVEs
    high_cves = max(0.0, float(row.get("high_cve_count", 0)))
    p_cve = min(30.0, (
        row.get("critical_cve_count", 0) * 5.0
        + math.sqrt(high_cves) * 2.5
        + row.get("critical_misconfig_count", 0) * 4.0
        + row.get("high_misconfig_count", 0) * 2.0
        + row.get("secret_count", 0) * 3.0
    ))

    # Pillar 3: RBAC & Access Control (max 20 pts penalty)
    p_rbac = min(20.0, (
        row.get("rbac_risk_score", 0) * 0.12
        + row.get("service_account_permission_score", 0) * 0.08
        + row.get("wildcard_rbac_rules", 0) * 5.0
    ))

    # Pillar 4: Compliance & Network Policy (max 15 pts penalty)
    p_comp = min(15.0, (
        max(0.0, 100.0 - float(row.get("kubescape_compliance", 100.0))) * 0.10
        + row.get("missing_network_policies", 0) * 3.0
        + row.get("kubescape_critical", 0) * 3.0
        + row.get("kubescape_high", 0) * 1.5
    ))

    # Pillar 5: Runtime Telemetry (max 10 pts penalty)
    # Weights real critical alerts higher than routine background warning probes
    p_runtime = min(10.0, (
        row.get("falco_critical_count", 0) * 0.3
        + row.get("falco_warning_count", 0) * 0.1
    ))

    total_penalty = p_workload + p_cve + p_rbac + p_comp + p_runtime
    row["security_score"] = round(max(0.0, min(100.0, 100.0 - total_penalty)), 2)

    if row["security_score"] < 40:
        row["risk_level"] = "High"
    elif row["security_score"] < 70:
        row["risk_level"] = "Medium"
    else:
        row["risk_level"] = "Low"

    # Multi-pillar Vulnerability Type Classification
    # Identifies whether the dominant vulnerability is Access-, Network-, or Resource-related
    p_network = min(15.0, (
        row.get("missing_network_policies", 0) * 3.5
        + row.get("host_port_count", 0) * 4.0
    ))
    penalties = {
        "Resource": p_workload,
        "Access": p_rbac,
        "Network": p_network,
        "Vulnerability": p_cve,
    }

    if row["security_score"] >= 80 and max(penalties.values()) < 3.0:
        row["vulnerability_type"] = "Hardened"
    else:
        row["vulnerability_type"] = max(penalties, key=penalties.get)

    active_vulns = [k for k, v in penalties.items() if v >= 3.0]
    row["vulnerability_breakdown"] = ", ".join(active_vulns) if active_vulns else "Clean"

    return row


def generate_synthetic_rows(n=120, seed=42):
    """
    Generate diverse synthetic cluster assessments spanning High, Medium, and Low risk.
    Ensures broad training spectrum and eliminates model blind spots across all 5 pillars.
    """
    import numpy as np
    rng = np.random.default_rng(seed)
    synth_rows = []
    for i in range(n):
        comp = float(rng.uniform(20.0, 95.0))
        crit_cve = int(rng.choice([0, 1, 2, 5, 15, 30], p=[0.3, 0.2, 0.2, 0.15, 0.1, 0.05]))
        high_cve = int(rng.integers(0, 85))
        crit_misc = int(rng.choice([0, 1], p=[0.7, 0.3]))
        high_misc = int(rng.integers(0, 7))
        sec = int(rng.choice([0, 1, 2], p=[0.8, 0.15, 0.05]))
        rbac = int(rng.integers(0, 80))
        sa = int(rng.integers(0, 60))
        wild = int(rng.choice([0, 1], p=[0.6, 0.4]))
        priv = int(rng.choice([0, 1], p=[0.7, 0.3]))
        root = int(rng.choice([0, 1, 2], p=[0.3, 0.5, 0.2]))
        risk_cap = int(rng.choice([0, 1, 2], p=[0.7, 0.2, 0.1]))
        hpath = int(rng.choice([0, 1], p=[0.8, 0.2]))
        hport = int(rng.choice([0, 1, 2], p=[0.7, 0.2, 0.1]))
        miss_np = int(rng.choice([0, 1, 2]))
        f_crit = int(rng.choice([0, 1, 2], p=[0.8, 0.15, 0.05]))
        f_warn = int(rng.integers(0, 5))

        r = {
            "snapshot": f"synth_{i+1:03d}",
            "environment": "synthetic",
            "kubescape_compliance": round(comp, 2),
            "kubescape_failed": int(rng.integers(0, 16)),
            "kubescape_passed": int(rng.integers(5, 20)),
            "kubescape_skipped": 5,
            "kubescape_critical": int(rng.choice([0, 1, 2])),
            "kubescape_high": int(rng.choice([0, 2, 5])),
            "kubescape_medium": int(rng.choice([2, 5, 8])),
            "kubescape_low": int(rng.choice([0, 1])),
            "critical_cve_count": crit_cve,
            "high_cve_count": high_cve,
            "critical_misconfig_count": crit_misc,
            "high_misconfig_count": high_misc,
            "secret_count": sec,
            "rbac_risk_score": rbac,
            "service_account_permission_score": sa,
            "wildcard_rbac_rules": wild,
            "cluster_admin_bindings": int(rng.choice([0, 1], p=[0.9, 0.1])),
            "rbac_binding_count": 78,
            "privileged_count": priv,
            "root_execution_count": root,
            "host_path_count": hpath,
            "risky_capability_count": risk_cap,
            "host_port_count": hport,
            "missing_network_policies": miss_np,
            "workload_count": 2,
            "falco_alert_count": f_crit + f_warn,
            "falco_critical_count": f_crit,
            "falco_warning_count": f_warn,
        }
        synth_rows.append(score_row(r))
    return synth_rows


def load_manifest_assessments(manifest_dataset_path=paths.MANIFEST_DATASET):
    """
    Ingest workload manifest scans from kubernetes_security_dataset.csv,
    mapping each manifest into cluster-equivalent security indicators.
    """
    manifest_file = Path(manifest_dataset_path)
    if not manifest_file.is_file():
        return []
    try:
        df_m = pd.read_csv(manifest_file)
    except Exception:
        return []

    manifest_rows = []
    for _, r in df_m.iterrows():
        c_row = {
            "snapshot": str(r.get("workload", "manifest")).split(":")[0],
            "environment": "manifest",
            "kubescape_compliance": float(r.get("kubescape_compliance", 50.0)),
            "kubescape_failed": int(r.get("kubescape_failed", 0)),
            "kubescape_passed": int(r.get("kubescape_passed", 0)),
            "kubescape_skipped": int(r.get("kubescape_skipped", 0)),
            "kubescape_critical": int(r.get("kubescape_critical", 0)),
            "kubescape_high": int(r.get("kubescape_high", 0)),
            "kubescape_medium": int(r.get("kubescape_medium", 0)),
            "kubescape_low": int(r.get("kubescape_low", 0)),
            "critical_cve_count": int(r.get("image_latest", 0) * 2),
            "high_cve_count": int(r.get("image_latest", 0) * 12),
            "critical_misconfig_count": int(r.get("privileged", 0)),
            "high_misconfig_count": int(r.get("allow_priv_esc", 0) + r.get("host_network", 0)),
            "secret_count": 0,
            "rbac_risk_score": int(r.get("automount_sa_token", 0) * 25),
            "service_account_permission_score": int(r.get("automount_sa_token", 0) * 20),
            "wildcard_rbac_rules": 0,
            "cluster_admin_bindings": 0,
            "rbac_binding_count": 1,
            "privileged_count": int(r.get("privileged", 0)),
            "root_execution_count": int(r.get("run_as_root", 0)),
            "host_path_count": int(r.get("host_path_volumes", 0)),
            "risky_capability_count": int(r.get("caps_added", 0)),
            "host_port_count": int(r.get("host_ports", 0)),
            "missing_network_policies": 1,
            "workload_count": int(r.get("num_containers", 1)),
            "falco_alert_count": int(r.get("privileged", 0) * 2 + r.get("host_pid", 0)),
            "falco_critical_count": int(r.get("privileged", 0)),
            "falco_warning_count": int(r.get("host_pid", 0)),
        }
        manifest_rows.append(score_row(c_row))
    return manifest_rows


def visible_dirs(parent):
    """Sub-directories of parent, ignoring hidden/in-progress ones."""
    return [
        entry for entry in sorted(parent.iterdir())
        if entry.is_dir() and not entry.name.startswith(".")
    ]


def discover():
    """Yield (folder, environment, snapshot_name) for every collection on disk."""
    # Latest one-off collection.
    for environment in ENVIRONMENTS:
        folder = paths.LATEST / environment
        if folder.exists():
            yield folder, environment, "latest"

    # Named snapshots (take_snapshot.sh), then periodic ones
    # (continuous_assessment.sh).
    for parent in (paths.SNAPSHOTS, paths.CONTINUOUS):
        if not parent.exists():
            continue
        for snapshot in visible_dirs(parent):
            for environment in ENVIRONMENTS:
                folder = snapshot / environment
                if folder.exists():
                    yield folder, environment, snapshot.name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--merge", nargs="*", default=[],
        help="Additional previously-saved dataset CSV(s) to fold in - useful "
             "when the raw snapshot folders are no longer available locally "
             "(e.g. to keep rows from an older export). Not needed normally: "
             "all folders under data/raw/ are re-read in full every run.",
    )
    parser.add_argument(
        "--rescore", metavar="CSV", default=None,
        help="Re-score an existing dataset CSV using the current scoring formula.",
    )
    parser.add_argument(
        "--report-input", metavar="CSV", default=None,
        help="Also write the 'latest' rows (both environments) to this CSV "
             "for generate_report.py.",
    )
    parser.add_argument(
        "--augment", type=int, default=0,
        help="Generate N diverse synthetic cluster assessments spanning High, Medium, Low risk.",
    )
    parser.add_argument(
        "--no-manifests", action="store_true", default=False,
        help="Skip ingesting workload manifests from kubernetes_security_dataset.csv.",
    )
    args = parser.parse_args()

    rows, skipped = [], []
    if not args.no_manifests and not args.rescore:
        manifest_rows = load_manifest_assessments()
        if manifest_rows:
            print(f"Ingesting {len(manifest_rows)} workload manifest assessment(s) into dataset...")
            rows.extend(manifest_rows)
    if args.augment > 0:
        print(f"Generating {args.augment} diverse synthetic cluster assessments...")
        rows.extend(generate_synthetic_rows(args.augment))
    if args.rescore:
        source_df = pd.read_csv(args.rescore)
        print(f"Re-scoring {len(source_df)} row(s) from {args.rescore}")
        for _, row in source_df.iterrows():
            rows.append(score_row(dict(row)))
    else:
        for folder, environment, name in discover():
            evidence, problem = load_collection(folder)
            if problem:
                skipped.append((str(folder), problem))
                print(f"WARNING: skipping {folder}: {problem}")
                continue
            rows.append(score_row({
                "snapshot": name,
                "environment": environment,
                **evidence,
            }))

    if skipped:
        print(f"\n{len(skipped)} incomplete collection folder(s) were skipped; "
              "re-run those snapshots to include them.")

    if not rows and not args.merge:
        raise SystemExit("No assessment data found")

    df = pd.DataFrame(rows)

    for path in args.merge:
        extra = pd.read_csv(path)
        print(f"Merging {len(extra)} row(s) from {path}")
        rescored_extra = [score_row(dict(r)) for _, r in extra.iterrows()]
        df = pd.concat([df, pd.DataFrame(rescored_extra)], ignore_index=True)

    df, report = clean_dataset(
        df,
        count_columns=COUNT_COLUMNS,
        bounded_columns={
            "kubescape_compliance": (0, 100),
            "security_score": (0, 100),
        },
        key_columns=["snapshot", "environment"],
        # Two genuinely distinct assessments (different snapshots, or the
        # secure vs. insecure side of the same snapshot) are never expected
        # to match on every single indicator - only treat a row as a
        # duplicate if snapshot+environment repeats, which means it's the
        # same assessment written twice (e.g. a snapshot name reused).
        dedup_subset=["snapshot", "environment"],
    )
    report.print(paths.CLUSTER_DATASET.name)

    paths.CLUSTER_DATASET.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(paths.CLUSTER_DATASET, index=False)

    print(f"Created {paths.rel(paths.CLUSTER_DATASET)} with {len(df)} rows")
    print()
    print(df[["snapshot", "environment", "security_score", "risk_level"]])

    if args.report_input:
        latest = df[df["snapshot"] == "latest"]
        if latest.empty:
            raise SystemExit(
                "No 'latest' rows in the dataset: data/raw/latest was "
                "incomplete. Check the warnings above."
            )
        out = Path(args.report_input)
        out.parent.mkdir(parents=True, exist_ok=True)
        latest.to_csv(out, index=False)


if __name__ == "__main__":
    main()
