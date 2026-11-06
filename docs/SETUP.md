# Complete Platform Setup & Operations Guide (v2.0.0)

This guide covers setup and deployment instructions for macOS, Linux, and Windows (via WSL2).

---

## 1. Prerequisites & System Requirements

- **Python**: Python 3.10 or newer (`python3 --version`)
- **Docker**: Docker Desktop or Engine (Required for live container layer streaming; offline fallbacks available)
- **Kubernetes (Optional)**: Kind, Minikube, EKS, GKE, or AKS (for in-cluster admission controller testing)
- **Helm (Optional)**: Helm v3+ (`helm version`) for chart deployment

---

## 2. Python Environment & Standalone CLI Installation

```bash
# 1. Clone repository and navigate to root
git clone https://github.com/platform/k8s-security-assessment.git
cd K8S-security-assessment-main

# 2. Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Upgrade package installer and install platform dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install k8s-sec in editable development mode
pip install -e .

# 5. Verify CLI installation
k8s-sec version
```

You can also run the pre-packaged executable directly without pip installation:
```bash
./bin/k8s-sec version
```

---

## 3. Verify Complete Platform Test Suite

To verify that all 107 units, integration pipelines, statistical rigor gates, and chaos engineering suites pass:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
Expected output:
```text
Ran 107 tests in ~90s ... OK (100% Pass Rate)
```

---

## 4. Operational Workflows & CLI Capabilities

### A. Manifest Auditing & Shift-Left CI/CD Gate
Scan Kubernetes YAML manifests against the 56-rule taxonomy and Model 11 ML scoring:
```bash
# Scan a single manifest file
k8s-sec scan manifests/secure/hardened-deployment.yaml

# Scan with JSON output for automated pipelines
k8s-sec scan manifests/insecure/weak-deployment.yaml --output json

# Enforce Shift-Left CI Gate (exits with code 1 if score < 35.0)
k8s-sec scan manifests/insecure/weak-deployment.yaml --gate --threshold 35.0
```

### B. In-Memory Container Image Layer & SBOM Scanning
Stream Docker container images directly in memory (< 600 ms) and match exact CVEs against the embedded SQLite database:
```bash
# Scan local Docker image via in-memory stream
k8s-sec scan-image redis:7-alpine

# Scan exported OCI/Docker tarball
k8s-sec scan-image --tar /path/to/image_archive.tar
```

### C. 1-Click Manifest Auto-Remediation
Automatically patch insecure manifests with least-privilege securityContexts (`runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: ALL`):
```bash
# Display unified hardening diff
k8s-sec remediate manifests/insecure/weak-deployment.yaml

# Save remediated manifest directly to file
k8s-sec remediate manifests/insecure/weak-deployment.yaml --output manifests/remediated/hardened.yaml
```

### D. Self-Hosted Web Management Console
Launch the responsive, dark-mode real-time security dashboard:
```bash
# Start web console on port 8080
k8s-sec web --port 8080
```
Open `http://localhost:8080` in your browser to inspect fleet compliance scorecards, audit manifests in real time, and monitor runtime telemetry.

### E. Continuous Prometheus Anomaly Streaming Daemon
Run Model 12 continuous anomaly monitoring with online EMA baseline updates:
```bash
k8s-sec daemon --interval 15 --port 9197 --prometheus http://localhost:9090
```
Scrape live OpenMetrics security gauges at `http://localhost:9197/metrics`.

### F. Embedded SQLite CVE Threat Feed Synchronization
Query package CVE records or synchronize live delta advisories:
```bash
# View CVE database statistics
k8s-sec sync-cve --stats

# Query CVEs affecting an exact package in < 1 ms
k8s-sec sync-cve --query libssl3

# Sync delta CVE records from OSV.dev (aggregates NVD, GHSA, SecDB)
k8s-sec sync-cve --sync
```

---

## 5. In-Cluster Kubernetes Admission Controller Deployment

### Option 1: Turnkey Helm Deployment (Recommended)
```bash
# 1. Lint the Helm chart
helm lint charts/k8s-security

# 2. Deploy into cluster
helm install k8s-security-agent ./charts/k8s-security \
  --namespace k8s-security \
  --create-namespace \
  --set policy.riskThreshold=35.0 \
  --set policy.enableMutation=true
```

### Option 2: Plain Kubernetes Manifests
```bash
# 1. Generate webhook TLS certificates with proper SANs
./deploy/admission-controller/generate_certs.sh

# 2. Apply Kubernetes resources
kubectl apply -f deploy/admission-controller/namespace.yaml
kubectl apply -f deploy/admission-controller/serviceaccount.yaml
kubectl apply -f deploy/admission-controller/service.yaml
kubectl apply -f deploy/admission-controller/deployment.yaml
kubectl apply -f deploy/admission-controller/validating-webhook.yaml
kubectl apply -f deploy/admission-controller/mutating-webhook.yaml
```

### Verify Webhook Protection
Attempt to apply a privileged test pod:
```bash
kubectl apply -f manifests/insecure/weak-deployment.yaml
```
Expected output:
```text
Error from server (Forbidden): admission webhook "validate.k8s-security.platform" denied the request: 
[K8S-SECURITY VETO] Admission REJECTED for default/Deployment/weak-deployment. Score: 13.2/100 (Tier: High). 
Catastrophic Exploit Veto triggered: V01: Privileged Container Execution; V04: Host PID sharing.
```

---

## 6. Executive Compliance Audit Export (PDF & HTML)

Generate boardroom-ready 9-page executive compliance reports mapped to NIST SP 800-190, CIS Benchmark v2.0, and MITRE ATT&CK:
```bash
k8s-sec audit
```
Outputs:
- HTML Report: `reports/executive_compliance_audit.html`
- PDF Report: `reports/executive_compliance_audit.pdf`
