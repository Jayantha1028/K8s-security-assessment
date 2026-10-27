#!/usr/bin/env python3
"""
Fetch authentic, real-world Kubernetes container manifests from top open-source projects.
Every manifest is saved with full source attribution, author credit, license, and repository URL.

Saves manifests into:
    data/raw/samples/real_world/real-0001.yaml to real-0100+.yaml
And outputs:
    data/raw/samples/real_world/MANIFEST_CATALOG.md
"""

import datetime
import json
import os
import re
import ssl
import sys
import urllib.request
from pathlib import Path
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import paths

OUTPUT_DIR = paths.SAMPLES / "real_world"
CATALOG_FILE = OUTPUT_DIR / "MANIFEST_CATALOG.md"

# SSL Context ignoring certificate verification issues on Python macOS
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

HEADERS = {"User-Agent": "Mozilla/5.0 (K8s-Security-Assessment-Research/1.0)"}


def fetch_url(url, timeout=12):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def fetch_bundle_workloads(source_info):
    """Fetch multi-workload YAML bundle and extract Deployments, Pods, DaemonSets, StatefulSets, Jobs."""
    try:
        content = fetch_url(source_info["url"])
        docs = list(yaml.safe_load_all(content))
        workloads = []
        for doc in docs:
            if not doc or not isinstance(doc, dict):
                continue
            kind = doc.get("kind")
            if kind in ["Deployment", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"]:
                workloads.append(doc)
        return workloads
    except Exception as exc:
        print(f"  [!] Failed {source_info['project']}: {exc}")
        return []


def get_k8s_examples_urls():
    """Fetch file paths from official kubernetes/examples repository."""
    api_url = "https://api.github.com/repos/kubernetes/examples/git/trees/master?recursive=1"
    raw_base = "https://raw.githubusercontent.com/kubernetes/examples/master/"
    try:
        content = fetch_url(api_url)
        data = json.loads(content)
        files = [
            item["path"]
            for item in data.get("tree", [])
            if (item["path"].endswith(".yaml") or item["path"].endswith(".yml"))
            and not item["path"].startswith("staging/volumes")
        ]
        return [(raw_base + p, p) for p in files]
    except Exception as exc:
        print(f"  [!] Could not query kubernetes/examples GitHub API: {exc}")
        return []


def get_k8s_goat_urls():
    """Fetch scenario manifest paths from madhuakula/kubernetes-goat repository."""
    api_url = "https://api.github.com/repos/madhuakula/kubernetes-goat/git/trees/master?recursive=1"
    raw_base = "https://raw.githubusercontent.com/madhuakula/kubernetes-goat/master/"
    try:
        content = fetch_url(api_url)
        data = json.loads(content)
        files = [
            item["path"]
            for item in data.get("tree", [])
            if (item["path"].endswith(".yaml") or item["path"].endswith(".yml"))
            and "scenario" in item["path"]
        ]
        return [(raw_base + p, p) for p in files]
    except Exception as exc:
        print(f"  [!] Could not query kubernetes-goat GitHub API: {exc}")
        return []


PRIMARY_SOURCES = [
    {
        "org": "Google Cloud Platform",
        "project": "Microservices Demo (Online Boutique)",
        "license": "Apache-2.0",
        "repo": "https://github.com/GoogleCloudPlatform/microservices-demo",
        "url": "https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/main/release/kubernetes-manifests.yaml",
        "category": "Hardened Enterprise Microservices",
    },
    {
        "org": "Istio Project (CNCF)",
        "project": "Istio Bookinfo Microservices",
        "license": "Apache-2.0",
        "repo": "https://github.com/istio/istio",
        "url": "https://raw.githubusercontent.com/istio/istio/master/samples/bookinfo/platform/kube/bookinfo.yaml",
        "category": "Service Mesh Demo",
    },
    {
        "org": "Argo Project (CNCF)",
        "project": "Argo CD GitOps Controller",
        "license": "Apache-2.0",
        "repo": "https://github.com/argoproj/argo-cd",
        "url": "https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml",
        "category": "Production GitOps Control Plane",
    },
    {
        "org": "Argo Project (CNCF)",
        "project": "Argo Workflows",
        "license": "Apache-2.0",
        "repo": "https://github.com/argoproj/argo-workflows",
        "url": "https://raw.githubusercontent.com/argoproj/argo-workflows/stable/manifests/quick-start-minimal.yaml",
        "category": "Cloud-Native Workflow Engine",
    },
    {
        "org": "Argo Project (CNCF)",
        "project": "Argo Rollouts",
        "license": "Apache-2.0",
        "repo": "https://github.com/argoproj/argo-rollouts",
        "url": "https://github.com/argoproj/argo-rollouts/releases/latest/download/install.yaml",
        "category": "Progressive Delivery Controller",
    },
    {
        "org": "Argo Project (CNCF)",
        "project": "Argo Events",
        "license": "Apache-2.0",
        "repo": "https://github.com/argoproj/argo-events",
        "url": "https://raw.githubusercontent.com/argoproj/argo-events/stable/manifests/install.yaml",
        "category": "Event-Driven Automation",
    },
    {
        "org": "Cert-Manager (CNCF)",
        "project": "cert-manager",
        "license": "Apache-2.0",
        "repo": "https://github.com/cert-manager/cert-manager",
        "url": "https://github.com/cert-manager/cert-manager/releases/download/v1.16.2/cert-manager.yaml",
        "category": "TLS Certificate Controller",
    },
    {
        "org": "Kubernetes SIGs",
        "project": "Ingress-Nginx Controller",
        "license": "Apache-2.0",
        "repo": "https://github.com/kubernetes/ingress-nginx",
        "url": "https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/cloud/deploy.yaml",
        "category": "Edge Ingress Proxy",
    },
    {
        "org": "Kubernetes SIGs",
        "project": "Metrics-Server",
        "license": "Apache-2.0",
        "repo": "https://github.com/kubernetes-sigs/metrics-server",
        "url": "https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml",
        "category": "Cluster Autoscaling & Telemetry",
    },
    {
        "org": "Kubernetes Project",
        "project": "Kubernetes Dashboard",
        "license": "Apache-2.0",
        "repo": "https://github.com/kubernetes/dashboard",
        "url": "https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml",
        "category": "Web Management Dashboard",
    },
    {
        "org": "Tektoncd (CD Foundation)",
        "project": "Tekton Pipelines",
        "license": "Apache-2.0",
        "repo": "https://github.com/tektoncd/pipeline",
        "url": "https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml",
        "category": "Cloud-Native CI/CD Pipeline",
    },
    {
        "org": "Knative Project (CNCF)",
        "project": "Knative Serving",
        "license": "Apache-2.0",
        "repo": "https://github.com/knative/serving",
        "url": "https://github.com/knative/serving/releases/download/knative-v1.15.2/serving-core.yaml",
        "category": "Serverless Container Runtime",
    },
    {
        "org": "MetalLB Project",
        "project": "MetalLB Bare-Metal LoadBalancer",
        "license": "Apache-2.0",
        "repo": "https://github.com/metallb/metallb",
        "url": "https://raw.githubusercontent.com/metallb/metallb/v0.14.8/config/manifests/metallb-native.yaml",
        "category": "Bare-Metal Load Balancer",
    },
    {
        "org": "Flannel Project (CNCF)",
        "project": "Flannel CNI",
        "license": "Apache-2.0",
        "repo": "https://github.com/flannel-io/flannel",
        "url": "https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml",
        "category": "Overlay Container Network",
    },
    {
        "org": "Project Calico (Tigera)",
        "project": "Calico CNI & Network Policy Engine",
        "license": "Apache-2.0",
        "repo": "https://github.com/projectcalico/calico",
        "url": "https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml",
        "category": "Zero-Trust Network Policy Engine",
    },
    {
        "org": "Envoy Gateway (CNCF)",
        "project": "Envoy Gateway",
        "license": "Apache-2.0",
        "repo": "https://github.com/envoyproxy/gateway",
        "url": "https://github.com/envoyproxy/gateway/releases/download/v1.1.2/install.yaml",
        "category": "API Gateway Controller",
    },
    {
        "org": "OpenTelemetry (CNCF)",
        "project": "OpenTelemetry Operator",
        "license": "Apache-2.0",
        "repo": "https://github.com/open-telemetry/opentelemetry-operator",
        "url": "https://github.com/open-telemetry/opentelemetry-operator/releases/download/v0.108.0/opentelemetry-operator.yaml",
        "category": "Observability Collector",
    },
    {
        "org": "Fluentd Project (CNCF)",
        "project": "Fluentd Kubernetes DaemonSet",
        "license": "Apache-2.0",
        "repo": "https://github.com/fluent/fluentd-kubernetes-daemonset",
        "url": "https://raw.githubusercontent.com/fluent/fluentd-kubernetes-daemonset/master/fluentd-daemonset-elasticsearch-rbac.yaml",
        "category": "Log Shipper DaemonSet",
    },
    {
        "org": "Dex IDP",
        "project": "Dex OIDC Identity Provider",
        "license": "Apache-2.0",
        "repo": "https://github.com/dexidp/dex",
        "url": "https://raw.githubusercontent.com/dexidp/dex/master/examples/k8s/dex.yaml",
        "category": "Authentication & Identity",
    },
]


def format_attributed_yaml(workload_dict, source_info, original_url, timestamp):
    """Prepend clean attribution and licensing metadata header to the workload YAML."""
    kind = workload_dict.get("kind", "Workload")
    name = workload_dict.get("metadata", {}).get("name", "unnamed")
    namespace = workload_dict.get("metadata", {}).get("namespace", "default")

    header = f"""# ==============================================================================
# REAL-WORLD KUBERNETES MANIFEST ATTRIBUTION & CREDIT
# ==============================================================================
# Source Project   : {source_info['project']}
# Organization     : {source_info['org']}
# License          : {source_info['license']}
# Repository URL   : {source_info['repo']}
# Source File URL  : {original_url}
# Workload Name    : {name}
# Workload Kind    : {kind}
# Category         : {source_info.get('category', 'Cloud-Native Container Workload')}
# Downloaded At    : {timestamp}
# Purpose          : Real-world empirical benchmark dataset for ML Security Evaluation
# ==============================================================================
"""
    yaml_body = yaml.dump(workload_dict, default_flow_style=False, sort_keys=False)
    return header + "\n" + yaml_body


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    print("================================================================================")
    print("      REAL-WORLD KUBERNETES MANIFEST FETCHER WITH FULL SOURCE CREDIT            ")
    print("================================================================================")
    print(f"Target Directory : {paths.rel(OUTPUT_DIR)}")
    print(f"Catalog File     : {paths.rel(CATALOG_FILE)}")
    print()

    collected = []
    seen_names = set()

    # 1. Fetch from curated primary bundles
    print("[1/3] Fetching top cloud-native and production enterprise bundles...")
    for source in PRIMARY_SOURCES:
        workloads = fetch_bundle_workloads(source)
        count = 0
        for w in workloads:
            kind = w.get("kind")
            name = w.get("metadata", {}).get("name", f"workload-{len(collected)+1}")
            key = f"{kind}:{name}"
            if key in seen_names:
                continue
            seen_names.add(key)
            collected.append((w, source, source["url"]))
            count += 1
        print(f"  ✓ {source['project']} ({source['org']}): {count} workloads extracted")

    # 2. Fetch from kubernetes-goat (Intentionally Vulnerable Scenarios)
    print("\n[2/3] Fetching real-world vulnerable scenarios from Kubernetes Goat...")
    goat_source = {
        "org": "Madhu Akula (Independent Security Researcher)",
        "project": "Kubernetes Goat (Vulnerable Cluster Scenarios)",
        "license": "Apache-2.0",
        "repo": "https://github.com/madhuakula/kubernetes-goat",
        "category": "Vulnerable Security Benchmark Scenario",
    }
    goat_files = get_k8s_goat_urls()
    goat_count = 0
    for file_url, rel_path in goat_files:
        try:
            content = fetch_url(file_url, timeout=8)
            docs = list(yaml.safe_load_all(content))
            for d in docs:
                if not d or not isinstance(d, dict):
                    continue
                if d.get("kind") in ["Deployment", "DaemonSet", "StatefulSet", "Pod", "Job"]:
                    name = d.get("metadata", {}).get("name", Path(rel_path).stem)
                    key = f"{d.get('kind')}:{name}"
                    if key in seen_names:
                        continue
                    seen_names.add(key)
                    collected.append((d, goat_source, file_url))
                    goat_count += 1
        except Exception:
            pass
    print(f"  ✓ Kubernetes Goat: {goat_count} vulnerable workloads extracted")

    # 3. Fetch from kubernetes/examples (Official Kubernetes Examples)
    print("\n[3/3] Fetching production & demo workloads from official kubernetes/examples...")
    k8s_source = {
        "org": "The Kubernetes Authors (CNCF)",
        "project": "Kubernetes Official Examples",
        "license": "Apache-2.0",
        "repo": "https://github.com/kubernetes/examples",
        "category": "Official Kubernetes Workload Example",
    }
    k8s_files = get_k8s_examples_urls()
    k8s_count = 0
    for file_url, rel_path in k8s_files:
        if len(collected) >= 115:
            break
        try:
            content = fetch_url(file_url, timeout=8)
            docs = list(yaml.safe_load_all(content))
            for d in docs:
                if not d or not isinstance(d, dict):
                    continue
                if d.get("kind") in ["Deployment", "DaemonSet", "StatefulSet", "Pod", "Job", "CronJob"]:
                    name = d.get("metadata", {}).get("name", Path(rel_path).stem)
                    key = f"{d.get('kind')}:{name}"
                    if key in seen_names:
                        continue
                    seen_names.add(key)
                    collected.append((d, k8s_source, file_url))
                    k8s_count += 1
                    if len(collected) >= 115:
                        break
        except Exception:
            pass
    print(f"  ✓ Kubernetes Examples: {k8s_count} workloads extracted")

    # 4. Write all attributed manifests to disk
    print(f"\nWriting {len(collected)} fully credited manifests to {paths.rel(OUTPUT_DIR)}...")
    catalog_rows = []

    for index, (workload, source, url) in enumerate(collected, 1):
        filename = f"real-{index:04d}.yaml"
        file_path = OUTPUT_DIR / filename
        attributed_content = format_attributed_yaml(workload, source, url, timestamp)
        file_path.write_text(attributed_content, encoding="utf-8")

        kind = workload.get("kind", "Workload")
        name = workload.get("metadata", {}).get("name", "unnamed")
        catalog_rows.append(
            f"| `{filename}` | **{name}** | `{kind}` | [{source['project']}]({source['repo']}) | {source['org']} | `{source['license']}` |"
        )

    # 5. Generate Markdown catalog file
    catalog_md = f"""# Real-World Kubernetes Container Manifest Dataset
## Source Attribution, Author Credits & License Catalog

> **Total Manifests Collected:** {len(collected)} authentic workloads  
> **Generation Date:** {timestamp}  
> **License Compliance:** All manifests are used under their respective open-source licenses (Apache-2.0, MIT).

---

### Dataset Summary by Source

| Organization / Author | Project Name | License | Focus Area |
|---|---|---|---|
| **Google Cloud Platform** | [Online Boutique (Microservices Demo)](https://github.com/GoogleCloudPlatform/microservices-demo) | Apache-2.0 | Multi-tier cloud e-commerce microservices |
| **CNCF / Istio Project** | [Istio Bookinfo](https://github.com/istio/istio) | Apache-2.0 | Microservices polyglot demo architecture |
| **CNCF / Argo Project** | [Argo CD, Workflows, Events, Rollouts](https://github.com/argoproj) | Apache-2.0 | Production GitOps controllers and runners |
| **The Kubernetes Authors (CNCF)**| [Kubernetes Official Examples](https://github.com/kubernetes/examples) | Apache-2.0 | Canonical production examples and AI workloads |
| **Madhu Akula** | [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) | Apache-2.0 | Intentionally vulnerable container escape & SSRF pods |
| **CNCF / Cert-Manager** | [cert-manager](https://github.com/cert-manager/cert-manager) | Apache-2.0 | TLS certificate automation controllers |
| **Kubernetes SIGs** | [Ingress-Nginx & Metrics-Server](https://github.com/kubernetes/ingress-nginx) | Apache-2.0 | Edge ingress routing and node telemetry |
| **Project Calico / Flannel** | [Calico & Flannel CNI](https://github.com/projectcalico/calico) | Apache-2.0 | Zero-trust networking and overlay controllers |
| **CD Foundation / Tekton** | [Tekton Pipelines](https://github.com/tektoncd/pipeline) | Apache-2.0 | Cloud-native CI/CD build controllers |
| **CNCF / Knative** | [Knative Serving](https://github.com/knative/serving) | Apache-2.0 | Serverless container workload management |

---

### Complete Workload Manifest Inventory

| File Name | Workload Name | Kind | Project | Organization / Credit | License |
|---|---|---|---|---|---|
""" + "\n".join(catalog_rows) + "\n"

    CATALOG_FILE.write_text(catalog_md, encoding="utf-8")
    print(f"\n✓ Successfully generated {len(collected)} attributed manifests.")
    print(f"✓ Catalog created at: {paths.rel(CATALOG_FILE)}")


if __name__ == "__main__":
    main()
