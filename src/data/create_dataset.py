"""Build kubernetes_security_dataset.csv from generated manifests + Kubescape scans."""

import argparse

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
from k8s_features import extract_features, load_workloads
from scan_parser import parse_kubescape

# Count-style columns from k8s_features / scan_parser: must be
# non-negative integers, and a missing value here means "no finding
# reported", i.e. 0 - not an unknown quantity to be imputed.
COUNT_COLUMNS = [
    "host_path_volumes", "host_ports", "caps_added", "num_containers",
    "kubescape_failed", "kubescape_passed", "kubescape_skipped",
    "kubescape_critical", "kubescape_high", "kubescape_medium",
    "kubescape_low",
]


def collect_rows():
    yaml_files = sorted(paths.SAMPLES.rglob("*.yaml"))
    print("Found", len(yaml_files), "YAML files")

    rows = []
    for yaml_file in yaml_files:
        scan_file = paths.MANIFEST_SCANS / f"{yaml_file.stem}_scan.json"

        if not scan_file.exists():
            print("Skipping", yaml_file.name, "- scan result missing")
            continue

        try:
            workloads = load_workloads(yaml_file)

            if not workloads:
                print("Skipping", yaml_file.name, "- no workload found")
                continue

            # One manifest can contain multiple YAML documents/workloads.
            # Preserve each workload instead of silently assessing only the
            # first. The scan is parsed once per file, not once per workload.
            scan = parse_kubescape(scan_file)
            for workload_name, workload_doc in workloads:
                feats = extract_features(workload_doc)
                scores = {
                    "Resource": (
                        feats.get("privileged", 0) * 25
                        + feats.get("run_as_root", 0) * 10
                        + feats.get("host_path_volumes", 0) * 15
                        + feats.get("caps_added", 0) * 10
                        + feats.get("allow_priv_esc", 0) * 10
                    ),
                    "Access": (feats.get("automount_sa_token", 0) * 20),
                    "Network": (feats.get("host_network", 0) * 15 + feats.get("host_ports", 0) * 10),
                    "Vulnerability": (feats.get("image_latest", 0) * 15),
                }
                primary_vuln = max(scores, key=scores.get) if max(scores.values()) > 0 else "Hardened"
                active_vulns = [k for k, v in scores.items() if v > 0]

                rows.append({
                    "workload": f"{yaml_file.stem}:{workload_name}",
                    **feats,
                    **scan,
                    "vulnerability_type": primary_vuln,
                    "vulnerability_breakdown": ", ".join(active_vulns) if active_vulns else "Clean",
                })

        except Exception as error:
            print("Skipping", yaml_file.name, "-", error)

    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fresh", action="store_true",
        help=f"Ignore any existing {paths.MANIFEST_DATASET.name} and "
             "overwrite it, instead of merging new rows into it.",
    )
    args = parser.parse_args()

    rows = collect_rows()
    if not rows:
        raise SystemExit("No usable rows found")

    df = pd.DataFrame(rows)

    output = paths.MANIFEST_DATASET
    if not args.fresh and output.exists():
        existing = pd.read_csv(output)
        print(f"Found existing {output.name}: {len(existing)} row(s) - "
              "merging with newly processed data before cleansing")
        df = pd.concat([existing, df], ignore_index=True)

    df, report = clean_dataset(
        df,
        count_columns=COUNT_COLUMNS,
        bounded_columns={"kubescape_compliance": (0, 100)},
        key_columns=["workload"],
    )
    report.print(output.name)

    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)

    print()
    print("Dataset created successfully")
    print("Rows:", len(df))
    print("Columns:", len(df.columns))
    print("File:", paths.rel(output))
    print()
    print(df.head())


if __name__ == "__main__":
    main()
