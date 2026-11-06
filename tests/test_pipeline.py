"""
Integration tests that run the real scripts against FAKE kubectl,
kubescape and trivy executables, so no cluster or scanner is needed.

They verify behaviour the unit tests cannot: failure paths, atomic
snapshots, incomplete-data handling, training and reporting end to end.
They do NOT prove compatibility with real Kubescape/Trivy releases.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

for _sub in ['core', 'data', 'scanners', 'models', 'evaluation', 'reporting', 'integrations']:
    _p = str(ROOT / 'src' / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))

KUBESCAPE_REPORT = {
    "summaryDetails": {
        "complianceScore": 70.5,
        "statusCounters": {"failed": 3, "passed": 7, "skipped": 0},
    },
    "results": [
        {"status": "failed", "baseScore": 9.1},
        {"status": "failed", "baseScore": 7.2},
        {"status": "failed", "baseScore": 5.0},
    ],
}

FAKE_KUBESCAPE = f"""#!/usr/bin/env python3
import json, os, sys
if os.environ.get("FAKE_KUBESCAPE_FAIL"):
    sys.stderr.write("kubescape boom\\n"); sys.exit(1)
out = sys.argv[sys.argv.index("--output") + 1]
open(out, "w").write({json.dumps(KUBESCAPE_REPORT)!r})
"""

FAKE_TRIVY = """#!/usr/bin/env python3
import json, os, sys
if os.environ.get("FAKE_TRIVY_FAIL"):
    sys.stderr.write("trivy boom\\n"); sys.exit(1)
out = sys.argv[sys.argv.index("--output") + 1]
doc = {"Resources": [{"Results": [
    {"Vulnerabilities": [{"Severity": "CRITICAL"}, {"Severity": "HIGH"}, {"Severity": "LOW"}],
     "Misconfigurations": [{"Severity": "HIGH", "Status": "FAIL"}, {"Severity": "HIGH", "Status": "PASS"}],
     "Secrets": [{"RuleID": "x"}]}]}]}
open(out, "w").write(json.dumps(doc))
"""

FALCO_LOG = (
    "Falco 0.38 starting\n"
    "Warning: Falco is running in a restricted mode\n"
    "08:00:01.123456789: Warning Sensitive file opened (user=root)\n"
    "2026-10-10T08:00:02.5+0000: Critical Shell spawned in container\n"
    '{"output":"x","priority":"Warning","rule":"r"}\n'
    "a plain log line mentioning Critical things\n"
)

FAKE_KUBECTL = f"""#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
if os.environ.get("FAKE_KUBECTL_FAIL"):
    sys.stderr.write("connection refused\\n"); sys.exit(1)
if "logs" in a:
    sys.stdout.write({FALCO_LOG!r}); sys.exit(0)
if "jsonpath={{.items[*].metadata.name}}" in a:
    print("" if os.environ.get("FAKE_NO_FALCO") else "falco-abc"); sys.exit(0)
if "get" not in a:
    sys.exit(0)
res = a[a.index("get") + 1:]
res = [x for x in res if not x.startswith("-")][0]
bare_pod = {{"kind": "Pod", "metadata": {{"name": "p", "namespace": "demo"}},
            "spec": {{"containers": [{{"name": "c", "image": "nginx",
                     "securityContext": {{"privileged": True}}}}]}}}}
owned_pod = {{"kind": "Pod", "metadata": {{"name": "o", "namespace": "demo",
             "ownerReferences": [{{"kind": "ReplicaSet"}}]}},
             "spec": {{"containers": [{{"name": "c", "image": "nginx",
                      "securityContext": {{"privileged": True}}}}]}}}}
deploy = {{"kind": "Deployment", "metadata": {{"name": "d", "namespace": "demo"}},
          "spec": {{"template": {{"spec": {{
              "volumes": [{{"name": "h", "hostPath": {{"path": "/"}}}}],
              "containers": [{{"name": "c", "image": "nginx",
                  "securityContext": {{"capabilities": {{"add": ["NET_ADMIN"]}}}},
                  "ports": [{{"hostPort": 80}}]}}]}}}}}}}}
role = {{"kind": "ClusterRole", "metadata": {{"name": "wide"}},
        "rules": [{{"resources": ["*"], "verbs": ["*"]}}]}}
binding = {{"kind": "ClusterRoleBinding", "metadata": {{"name": "b"}},
           "roleRef": {{"kind": "ClusterRole", "name": "wide"}},
           "subjects": [{{"kind": "ServiceAccount", "name": "app", "namespace": "demo"}}]}}
items = {{
    "deployments": [deploy], "pods": [bare_pod, owned_pod],
    "clusterroles": [role], "clusterrolebindings": [binding],
}}.get(res, [])
print(json.dumps({{"items": items}}))
"""


FAKE_KIND = """#!/usr/bin/env bash
if [ "$1" = "get" ]; then echo "ml-k8s-secure"; echo "ml-k8s-insecure"; fi
exit 0
"""

FAKE_NOOP = """#!/usr/bin/env bash
exit 0
"""


def make_bin(directory):
    directory.mkdir(parents=True, exist_ok=True)
    for name, body in (
        ("kubescape", FAKE_KUBESCAPE),
        ("trivy", FAKE_TRIVY),
        ("kubectl", FAKE_KUBECTL),
        ("kind", FAKE_KIND),
        ("helm", FAKE_NOOP),
        ("docker", FAKE_NOOP),
    ):
        path = directory / name
        path.write_text(body)
        path.chmod(0o755)


class PipelineCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.work = Path(self._tmp.name) / "work"
        self.work.mkdir()
        self.bin = Path(self._tmp.name) / "bin"
        make_bin(self.bin)
        # Only code and manifests: the real data/, models/ and reports/ must
        # not leak into (or be modified by) a test run.
        shutil.copy2(ROOT / "run.sh", self.work / "run.sh")
        for folder in ("src", "scripts", "manifests"):
            shutil.copytree(
                ROOT / folder, self.work / folder,
                ignore=shutil.ignore_patterns("__pycache__"),
            )

    def run_cmd(self, *cmd, env=None, check=False):
        full_env = dict(os.environ)
        full_env["PATH"] = f"{self.bin}{os.pathsep}{full_env['PATH']}"
        full_env["PYTHONDONTWRITEBYTECODE"] = "1"
        full_env.update(env or {})
        result = subprocess.run(
            list(cmd), cwd=self.work, env=full_env,
            capture_output=True, text=True, timeout=300,
        )
        if check and result.returncode != 0:
            self.fail(f"{cmd} failed:\n{result.stdout}\n{result.stderr}")
        return result

    def write_collection(self, folder, *, kubescape=True, trivy=True,
                         features=True, falco=True, empty_features=False):
        folder = self.work / folder
        folder.mkdir(parents=True, exist_ok=True)
        if kubescape:
            (folder / "kubescape.json").write_text(json.dumps(KUBESCAPE_REPORT))
        if trivy:
            (folder / "trivy.json").write_text("{}")
        if features:
            text = "" if empty_features else json.dumps({
                "rbac_risk_score": 0, "service_account_permission_score": 0,
                "wildcard_rbac_rules": 0, "cluster_admin_bindings": 0,
                "rbac_binding_count": 0, "privileged_count": 0,
                "root_execution_count": 0, "host_path_count": 0,
                "risky_capability_count": 0, "host_port_count": 0,
                "missing_network_policies": 0, "workload_count": 1,
            })
            (folder / "cluster_features.json").write_text(text)
        if falco:
            (folder / "falco.log").write_text("")


class ManifestPipelineTests(PipelineCase):
    def test_midsem_pipeline_end_to_end(self):
        result = self.run_cmd("./run.sh", "--manifests", "--fresh", check=True)
        import pandas as pd
        df = pd.read_csv(self.work / "data/processed/kubernetes_security_dataset.csv")
        self.assertEqual(len(df), 100)
        self.assertFalse(df.isna().any().any())

        # Incremental run adds rows instead of replacing them.
        self.run_cmd("./run.sh", "--manifests", check=True)
        df2 = pd.read_csv(self.work / "data/processed/kubernetes_security_dataset.csv")
        self.assertEqual(len(df2), 200)

    def test_run_writes_a_log_with_exit_status(self):
        self.run_cmd("./run.sh", "--manifests", "--fresh", check=True)
        logs = list((self.work / "logs").glob("*_manifests.log"))
        self.assertEqual(len(logs), 1, logs)
        text = logs[0].read_text()
        self.assertIn("# ./run.sh --manifests --fresh | started", text)
        self.assertIn("MANIFEST PIPELINE", text)
        self.assertIn("exit status 0", text)

    def test_failed_run_is_logged_and_keeps_exit_code(self):
        result = self.run_cmd("./run.sh", "--final", env={"FAKE_TRIVY_FAIL": "1"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        text = next((self.work / "logs").glob("*_final.log")).read_text()
        self.assertIn("trivy boom", text)
        self.assertIn("exit status 1", text)
        self.assertIn("Log saved: logs/", result.stdout)

    def test_old_logs_are_pruned_and_help_is_not_logged(self):
        logs = self.work / "logs"
        logs.mkdir()
        for i in range(35):
            f = logs / f"20200101_0000{i:02d}_old.log"
            f.write_text("x")
            os.utime(f, (1_000_000 + i, 1_000_000 + i))
        self.run_cmd("./run.sh", "--help", check=True)
        self.assertEqual(len(list(logs.glob("*.log"))), 35)  # --help writes nothing
        self.run_cmd("./run.sh", "--manifests", "--fresh", check=True)
        self.assertEqual(len(list(logs.glob("*.log"))), 30)

    def test_scan_failure_is_reported(self):
        self.run_cmd("python3", "src/data/generate_samples.py", "--count", "3", "--seed", "1", check=True)
        result = self.run_cmd("python3", "src/scanners/scan_manifests.py", env={"FAKE_KUBESCAPE_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("kubescape boom", result.stdout)

    def test_generate_samples_seed_reproducible_and_validated(self):
        a = self.run_cmd("python3", "src/data/generate_samples.py", "--count", "5", "--seed", "7",
                         "--output-dir", "a", check=True)
        self.run_cmd("python3", "src/data/generate_samples.py", "--count", "5", "--seed", "7",
                     "--output-dir", "b", check=True)
        for i in range(1, 6):
            self.assertEqual((self.work / "a" / f"sample-{i:04d}.yaml").read_text(),
                             (self.work / "b" / f"sample-{i:04d}.yaml").read_text())
        bad = self.run_cmd("python3", "src/data/generate_samples.py", "--count", "0")
        self.assertNotEqual(bad.returncode, 0)

    def test_all_generated_manifests_yield_features(self):
        self.run_cmd("python3", "src/data/generate_samples.py", "--count", "60", "--seed", "3", check=True)
        from k8s_features import extract_features, load_workloads, FEATURE_COLS
        for path in sorted((self.work / "data/raw/samples/synthetic").glob("*.yaml")):
            workloads = load_workloads(path)
            self.assertEqual(len(workloads), 1, path)
            features = extract_features(workloads[0][1])
            self.assertEqual(set(features), set(FEATURE_COLS))


class ClusterDatasetTests(PipelineCase):
    def build(self):
        return self.run_cmd("python3", "src/data/build_cluster_dataset.py")

    def test_complete_folder_becomes_row_and_counts_falco_correctly(self):
        self.write_collection("data/raw/snapshots/s1/secure")
        (self.work / "data/raw/snapshots/s1/secure/falco.log").write_text(
            "Warning: startup noise\n"
            "08:00:01.1: Warning real alert\n"
            "2026-10-10T08:00:02.5+0000: Critical real critical\n"
            '{"priority":"Warning"}\n'
            "Critical mention without timestamp\n"
        )
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        import pandas as pd
        row = pd.read_csv(self.work / "data/processed/final_security_dataset.csv").iloc[0]
        self.assertEqual(int(row["falco_critical_count"]), 1)
        self.assertEqual(int(row["falco_warning_count"]), 2)
        self.assertEqual(int(row["kubescape_critical"]), 1)

    def test_incomplete_folders_are_skipped_not_scored_as_zero(self):
        self.write_collection("data/raw/snapshots/good/secure")
        self.write_collection("data/raw/snapshots/no_trivy/secure", trivy=False)
        self.write_collection("data/raw/snapshots/no_features/secure", features=False)
        self.write_collection("data/raw/snapshots/empty_features/secure", empty_features=True)
        self.write_collection("data/raw/snapshots/no_falco/secure", falco=False)
        self.write_collection("data/raw/snapshots/.tmp-inprogress/secure")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        import pandas as pd
        df = pd.read_csv(self.work / "data/processed/final_security_dataset.csv")
        self.assertEqual(list(df["snapshot"]), ["good"])
        self.assertIn("WARNING: skipping", result.stdout)
        self.assertEqual(result.stdout.count("WARNING: skipping"), 4)

    def test_only_incomplete_data_fails_clearly(self):
        self.write_collection("data/raw/snapshots/bad/secure", trivy=False)
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No assessment data found", result.stdout + result.stderr)

    def test_report_input_contains_only_latest_rows(self):
        self.write_collection("data/raw/latest/secure")
        self.write_collection("data/raw/latest/insecure")
        self.write_collection("data/raw/snapshots/s1/secure")
        out = self.work / "ri.csv"
        result = self.run_cmd("python3", "src/data/build_cluster_dataset.py", "--report-input", str(out))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        import pandas as pd
        ri = pd.read_csv(out)
        self.assertEqual(sorted(ri["environment"]), ["insecure", "secure"])
        self.assertEqual(set(ri["snapshot"]), {"latest"})

    def test_report_input_fails_when_latest_missing(self):
        self.write_collection("data/raw/snapshots/s1/secure")
        result = self.run_cmd("python3", "src/data/build_cluster_dataset.py",
                              "--report-input", str(self.work / "ri.csv"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No 'latest' rows", result.stdout + result.stderr)

    def test_duplicate_snapshot_name_keeps_one_row(self):
        self.write_collection("data/raw/snapshots/s1/secure")
        self.write_collection("data/raw/latest/secure")
        self.build()
        import pandas as pd
        df = pd.read_csv(self.work / "data/processed/final_security_dataset.csv")
        self.assertEqual(sorted(df["snapshot"]), ["latest", "s1"])


class SnapshotScriptTests(PipelineCase):
    def test_successful_snapshot_is_saved_atomically(self):
        result = self.run_cmd("scripts/take_snapshot.sh", "snap_01")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for env in ("secure", "insecure"):
            for name in ("kubescape.json", "trivy.json", "cluster_features.json", "falco.log"):
                self.assertTrue((self.work / "data/raw/snapshots/snap_01" / env / name).is_file())
        self.assertEqual(list((self.work / "data/raw/snapshots").glob(".tmp-*")), [])
        import pandas as pd
        df = pd.read_csv(self.work / "data/processed/final_security_dataset.csv")
        self.assertEqual(sorted(df["environment"]), ["insecure", "secure"])

    def test_failed_scan_leaves_nothing_behind(self):
        for var in ("FAKE_TRIVY_FAIL", "FAKE_KUBESCAPE_FAIL", "FAKE_KUBECTL_FAIL"):
            with self.subTest(failure=var):
                result = self.run_cmd("scripts/take_snapshot.sh", "bad", env={var: "1"})
                self.assertNotEqual(result.returncode, 0)
                snaps = self.work / "data/raw/snapshots"
                self.assertFalse((snaps / "bad").exists())
                self.assertEqual(list(snaps.glob(".tmp-*")), [])
        self.assertFalse((self.work / "data/processed/final_security_dataset.csv").exists())

    def test_invalid_names_rejected(self):
        for name in ("../escape", "has space", "latest", ".hidden", "a/b"):
            with self.subTest(name=name):
                result = self.run_cmd("scripts/take_snapshot.sh", name)
                self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.work / "data/raw/snapshots").exists())

    def test_reusing_name_replaces_snapshot(self):
        self.run_cmd("scripts/take_snapshot.sh", "dup", check=True)
        self.run_cmd("scripts/take_snapshot.sh", "dup", check=True)
        import pandas as pd
        df = pd.read_csv(self.work / "data/processed/final_security_dataset.csv")
        self.assertEqual(len(df), 2)

    def test_build_dataset_can_be_deferred(self):
        # ./run.sh --all relies on this: snapshots are taken without rebuilding
        # the dataset each time, then it is rebuilt once at the end.
        result = self.run_cmd("scripts/take_snapshot.sh", "snap_01",
                              env={"BUILD_DATASET": "0"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.work / "data/raw/snapshots/snap_01/secure/falco.log").is_file())
        self.assertFalse((self.work / "data/processed/final_security_dataset.csv").exists())
        self.run_cmd("scripts/take_snapshot.sh", "snap_02", env={"BUILD_DATASET": "0"}, check=True)
        self.run_cmd("python3", "src/data/build_cluster_dataset.py", check=True)
        import pandas as pd
        df = pd.read_csv(self.work / "data/processed/final_security_dataset.csv")
        self.assertEqual(sorted(set(df["snapshot"])), ["snap_01", "snap_02"])

    def test_collect_cluster_reports_any_failed_collector(self):
        for var in ("FAKE_TRIVY_FAIL", "FAKE_KUBESCAPE_FAIL", "FAKE_KUBECTL_FAIL", "FAKE_NO_FALCO"):
            with self.subTest(failure=var):
                result = self.run_cmd("scripts/collect_cluster.sh", "ctx", "out", env={var: "1"})
                self.assertNotEqual(result.returncode, 0)
        ok = self.run_cmd("scripts/collect_cluster.sh", "ctx", "out_ok")
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        for name in ("kubescape.json", "trivy.json", "cluster_features.json", "falco.log"):
            self.assertTrue((self.work / "out_ok" / name).is_file(), name)

    def test_scripts_work_from_any_directory(self):
        elsewhere = Path(self._tmp.name) / "elsewhere"
        elsewhere.mkdir()
        full_env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        result = subprocess.run(
            [str(self.work / "scripts/take_snapshot.sh"), "far_away"],
            cwd=elsewhere, env=full_env, capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.work / "data/raw/snapshots/far_away").is_dir())
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_bad_interval_rejected(self):
        for value in ("abc", "0", "-5", "1.5"):
            with self.subTest(value=value):
                result = self.run_cmd("scripts/continuous_assessment.sh", env={"INTERVAL": value})
                self.assertEqual(result.returncode, 2, result.stderr)


class RunFinalTests(PipelineCase):
    def test_run_final_success(self):
        result = self.run_cmd("./run.sh", "--final")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        import pandas as pd
        df = pd.read_csv(self.work / "data/processed/final_security_dataset.csv")
        self.assertEqual(sorted(df["snapshot"]), ["latest", "latest"])
        report_input = pd.read_csv(self.work / "data/processed/report_input.csv")
        self.assertEqual(sorted(report_input["environment"]), ["insecure", "secure"])
        self.assertFalse((self.work / "data/raw/.latest.tmp").exists())
        self.assertTrue((self.work / "data/raw/latest/secure/falco.log").is_file())

    def test_run_final_failure_keeps_previous_collection(self):
        self.run_cmd("./run.sh", "--final", check=True)
        marker = self.work / "data/raw/latest/secure/kubescape.json"
        before = marker.read_text()
        result = self.run_cmd("./run.sh", "--final", env={"FAKE_TRIVY_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), before)
        self.assertFalse((self.work / "data/raw/.latest.tmp").exists())

    def test_missing_tool_reported(self):
        # Only a minimal PATH: python3 exists but docker/kind/etc. do not.
        result = self.run_cmd("/usr/bin/env", "bash", "run.sh", "--final",
                              env={"PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin"})
        self.assertEqual(result.returncode, 127, result.stdout + result.stderr)
        self.assertIn("Required command not found", result.stderr)


class RunAllTests(PipelineCase):
    def test_orchestration_and_weak_workload_restored(self):
        log = self.work / "kubectl.log"
        # Record every kubectl call so we can assert on the sequence.
        wrapper = self.bin / "kubectl"
        real = self.bin / "kubectl.real"
        wrapper.rename(real)
        wrapper.write_text(f"#!/usr/bin/env bash\necho \"$@\" >> {log}\nexec {real} \"$@\"\n")
        wrapper.chmod(0o755)

        result = self.run_cmd("./run.sh", "--all", env={"SNAPSHOTS": "5", "PAUSE": "0"})
        # Fake data gives one risk class only, so training must refuse
        # cleanly (exit 1 with guidance), not crash.
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Training did not run", result.stderr)
        snaps = sorted(p.name for p in (self.work / "data/raw/snapshots").iterdir())
        self.assertEqual(len(snaps), 10, snaps)
        calls = log.read_text()
        self.assertIn("medium-deployment.yaml", calls)
        # the weak workload is re-applied after the medium scenario
        self.assertGreater(calls.rindex("weak-deployment.yaml"),
                           calls.rindex("medium-deployment.yaml"))

    def test_weak_workload_restored_when_a_snapshot_fails(self):
        log = self.work / "kubectl.log"
        wrapper = self.bin / "kubectl"
        real = self.bin / "kubectl.real"
        wrapper.rename(real)
        # fail scans only once the medium workload has been applied
        wrapper.write_text(
            "#!/usr/bin/env bash\n"
            f"echo \"$@\" >> {log}\n"
            f"if grep -q medium-deployment.yaml {log} && [[ \"$*\" == *\" get \"* ]]; then "
            "echo boom >&2; exit 1; fi\n"
            f"exec {real} \"$@\"\n")
        wrapper.chmod(0o755)
        result = self.run_cmd("./run.sh", "--all", env={"SNAPSHOTS": "5", "PAUSE": "0"})
        self.assertNotEqual(result.returncode, 0)
        calls = log.read_text()
        self.assertGreater(calls.rindex("weak-deployment.yaml"),
                           calls.rindex("medium-deployment.yaml"))

    def test_bad_settings_rejected(self):
        for env in ({"SNAPSHOTS": "3"}, {"SNAPSHOTS": "x"}, {"PAUSE": "-1"}):
            with self.subTest(env=env):
                self.assertEqual(self.run_cmd("./run.sh", "--all", env=env).returncode, 2)


class CollectorTests(PipelineCase):
    def test_cluster_features(self):
        result = self.run_cmd("python3", "src/data/collect_cluster_features.py", "ctx", check=True)
        data = json.loads(result.stdout)
        # deployment (1) + bare pod (1); the owned pod is not double counted
        self.assertEqual(data["workload_count"], 2)
        self.assertEqual(data["privileged_count"], 1)
        self.assertEqual(data["host_path_count"], 1)
        self.assertEqual(data["risky_capability_count"], 1)
        self.assertEqual(data["host_port_count"], 1)
        self.assertEqual(data["wildcard_rbac_rules"], 1)
        self.assertEqual(data["missing_network_policies"], 1)

    def test_cluster_features_kubectl_failure_is_clean(self):
        result = self.run_cmd("python3", "src/data/collect_cluster_features.py", "ctx",
                              env={"FAKE_KUBECTL_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("connection refused", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_falco_collection_and_errors(self):
        out = self.work / "falco.log"
        self.run_cmd("python3", "src/data/collect_falco.py", "ctx", str(out), check=True)
        self.assertIn("Sensitive file opened", out.read_text())
        missing = self.run_cmd("python3", "src/data/collect_falco.py", "ctx", str(out),
                               env={"FAKE_NO_FALCO": "1"})
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("No Falco pod found", missing.stderr)
        self.assertNotIn("Traceback", missing.stderr)


class TrainAndReportTests(PipelineCase):
    def make_dataset(self, per_class_snapshots=7, classes=("Low", "Medium", "High")):
        import numpy as np
        import pandas as pd
        rng = np.random.default_rng(0)
        feats = ["kubescape_failed", "kubescape_critical", "kubescape_high",
                 "critical_cve_count", "high_cve_count", "critical_misconfig_count",
                 "high_misconfig_count", "secret_count", "rbac_risk_score",
                 "service_account_permission_score", "risky_capability_count",
                 "host_path_count", "missing_network_policies", "root_execution_count",
                 "falco_alert_count", "privileged_count", "host_port_count"]
        rows = []
        level = {"Low": 0, "Medium": 2, "High": 6}
        for cls in classes:
            for i in range(per_class_snapshots):
                row = {f: int(rng.integers(0, 3) + level[cls]) for f in feats}
                score = {"Low": 85, "Medium": 55, "High": 15}[cls] + float(rng.normal(0, 3))
                row.update(snapshot=f"{cls}_{i}", environment="secure",
                           security_score=round(score, 2), risk_level=cls)
                rows.append(row)
        (self.work / "data/processed").mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_csv(self.work / "data/processed/final_security_dataset.csv", index=False)
        return pd.DataFrame(rows)

    def test_train_then_report_for_multiple_rows(self):
        df = self.make_dataset()
        train = self.run_cmd("python3", "src/models/train_security_models.py")
        self.assertEqual(train.returncode, 0, train.stdout + train.stderr)
        self.assertIn("grouped 5-fold", train.stdout)
        self.assertTrue((self.work / "models/security_models.joblib").is_file())

        df.iloc[[0, -1]].to_csv(self.work / "report_input.csv", index=False)
        report = self.run_cmd("python3", "src/reporting/generate_report.py", "report_input.csv")
        self.assertEqual(report.returncode, 0, report.stdout + report.stderr)
        text = (self.work / "reports/security_report.txt").read_text()
        self.assertEqual(text.count("KUBERNETES SECURITY ASSESSMENT"), 2)
        self.assertIn("Low_0 / secure", text)
        self.assertIn("High_6 / secure", text)

    def test_train_refuses_too_little_data(self):
        self.make_dataset(per_class_snapshots=2)
        result = self.run_cmd("python3", "src/models/train_security_models.py")
        self.assertNotEqual(result.returncode, 0)

    def test_report_without_model_or_bad_input(self):
        self.make_dataset()
        result = self.run_cmd("python3", "src/reporting/generate_report.py", "data/processed/final_security_dataset.csv")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Model file not found", result.stderr)

        self.run_cmd("python3", "src/models/train_security_models.py", check=True)
        (self.work / "bad.csv").write_text("snapshot,environment\nx,secure\n")
        bad = self.run_cmd("python3", "src/reporting/generate_report.py", "bad.csv")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("missing model features", bad.stderr)


if __name__ == "__main__":
    unittest.main()
