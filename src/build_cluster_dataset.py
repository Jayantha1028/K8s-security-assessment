"""Build final_security_dataset.csv from every collected cluster assessment.

Reads data/raw/latest, data/raw/snapshots/* and data/raw/continuous_snapshots/*
(each holding a ``secure`` and an ``insecure`` collection), scores each one
and writes one row per (snapshot, environment).
"""

import argparse
import json
import re
from pathlib import Path

import pandas as pd

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
    """Transparent evidence-based baseline: the assessment target, not the ML prediction."""
    penalty = (
        max(0, 100 - row["kubescape_compliance"]) * 0.20
        + row["kubescape_critical"] * 7
        + row["kubescape_high"] * 4
        + row["critical_cve_count"] * 10
        + row["high_cve_count"] * 5
        + row["critical_misconfig_count"] * 6
        + row["high_misconfig_count"] * 3
        + row["secret_count"] * 4
        + row["rbac_risk_score"] * 0.15
        + row["service_account_permission_score"] * 0.10
        + row["risky_capability_count"] * 5
        + row["host_path_count"] * 5
        + row["missing_network_policies"] * 5
        + row["root_execution_count"] * 5
        + row["privileged_count"] * 5
        + row["host_port_count"] * 2
        + row["falco_alert_count"] * 0.5
    )

    row["security_score"] = round(max(0, min(100, 100 - penalty)), 2)

    if row["security_score"] < 40:
        row["risk_level"] = "High"
    elif row["security_score"] < 70:
        row["risk_level"] = "Medium"
    else:
        row["risk_level"] = "Low"
    return row


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
        "--report-input", metavar="CSV", default=None,
        help="Also write the 'latest' rows (both environments) to this CSV "
             "for generate_report.py.",
    )
    args = parser.parse_args()

    rows, skipped = [], []
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

    if not rows:
        raise SystemExit("No assessment data found")

    df = pd.DataFrame(rows)

    for path in args.merge:
        extra = pd.read_csv(path)
        print(f"Merging {len(extra)} row(s) from {path}")
        df = pd.concat([df, extra], ignore_index=True)

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
