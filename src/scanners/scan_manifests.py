"""
Scan every generated YAML manifest with Kubescape and write one JSON
report per file into data/raw/manifest_scans/.

This is the main latency bottleneck in the mid-semester pipeline: the
original version ran `kubescape scan` once per file, sequentially, and
each invocation pays its own process-startup/policy-load cost on top of
the actual scan. For N=100 sample manifests that cost is paid 100 times
in a row. Two changes fix that without changing what gets scanned:

1. Scans run concurrently (a thread pool), since each `kubescape scan`
   call is an independent external process — the bottleneck is wall
   clock spent waiting on subprocesses, not local CPU, so threads are
   enough and avoid multiprocessing overhead.
2. A file already scanned (output JSON already present) is skipped, so
   re-running the script after fixing one manifest, or after a partial
   failure, doesn't re-pay the cost for every other file. Use --force
   to disable this.

Usage:
    python3 src/scan_manifests.py [--workers N] [--force]
"""

import argparse
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ensure core and parent src are in sys.path
import sys
from pathlib import Path
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
    sys.path.insert(0, str(_CORE_DIR.parent))
import paths

SAMPLES_FOLDER = paths.SAMPLES
OUTPUT_FOLDER = paths.MANIFEST_SCANS
FRAMEWORK = "nsa"
DEFAULT_WORKERS = 8


def scan_one(yaml_file, force):
    output_file = OUTPUT_FOLDER / f"{yaml_file.stem}_scan.json"

    if output_file.exists() and not force:
        return yaml_file, "cached", None

    command = [
        "kubescape",
        "scan",
        "framework",
        FRAMEWORK,
        str(yaml_file),
        "--format", "json",
        "--format-version", "v2",
        "--output", str(output_file),
    ]

    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    if result.returncode != 0:
        return yaml_file, "failed", result.stderr.strip()

    return yaml_file, "scanned", None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS,
        help=f"Concurrent kubescape processes (default {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-scan files even if a cached report already exists",
    )
    args = parser.parse_args()

    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")
    if shutil.which("kubescape") is None:
        raise SystemExit(
            "Kubescape CLI was not found on PATH. Install Kubescape, then retry."
        )

    OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)

    yaml_files = sorted(SAMPLES_FOLDER.rglob("*.yaml"))

    if not yaml_files:
        raise SystemExit(f"No YAML files found in {paths.rel(SAMPLES_FOLDER)}/")

    # Output names are based on each manifest stem; reject collisions rather
    # than silently reusing/overwriting a different manifest's scan report.
    stems = {}
    for path in yaml_files:
        stems.setdefault(path.stem, []).append(path)
    collisions = [(stem, group) for stem, group in stems.items() if len(group) > 1]
    if collisions:
        details = "\n".join(
            f"  {stem}: " + ", ".join(str(p) for p in group)
            for stem, group in collisions
        )
        raise SystemExit("Manifest filename collisions would overwrite scan reports:\n" + details)

    print(f"Found {len(yaml_files)} YAML files")
    print(f"Scanning with {args.workers} concurrent workers")

    scanned = cached = failed = 0
    failures = []

    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(scan_one, yaml_file, args.force)
            for yaml_file in yaml_files
        ]

        for i, future in enumerate(as_completed(futures), start=1):
            yaml_file, status, error = future.result()

            if status == "scanned":
                scanned += 1
            elif status == "cached":
                cached += 1
            else:
                failed += 1
                failures.append((yaml_file, error))
                print(f"[{i}/{len(yaml_files)}] FAILED: {yaml_file}")

            if i % 20 == 0 or i == len(yaml_files):
                print(f"[{i}/{len(yaml_files)}] processed "
                      f"({scanned} scanned, {cached} cached, {failed} failed)")

    elapsed = time.time() - start

    print()
    print("Kubescape scanning completed.")
    print(f"Scanned: {scanned}  Cached: {cached}  Failed: {failed}")
    print(f"Elapsed: {elapsed:.1f}s")

    if failures:
        print("\nFailed scans:")
        for yaml_file, error in failures:
            print(f" - {yaml_file}: {error or 'unknown error'}")
        sys.exit(1)


if __name__ == "__main__":
    main()
