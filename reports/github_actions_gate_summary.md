## 🛡️ CDC-5 Kubernetes Security Gate Summary
**Audit Status:** ❌ **DEPLOYMENT BLOCKED**

### 📊 Workload Inferences & Security Posture
| Manifest File | Workload | Master Score | Risk Tier | GMM Posture | 56-Taxonomy Flags | Gate Status |
|---|---|---|---|---|---|:---:|
| `manifests/insecure/medium-deployment.yaml` | **medium-app** | `69.3/100` | **Low** | ANOMALY (Zero-Day Outlier) | 6 vectors | ✅ PASSED |
| `manifests/insecure/weak-deployment.yaml` | **vulnerable-app** | `45.0/100` | **Medium** | ANOMALY (Zero-Day Outlier) | 11 vectors | ❌ BLOCKED |
| `manifests/secure/hardened-deployment.yaml` | **secured-app** | `87.2/100` | **Low** | ANOMALY (Zero-Day Outlier) | Clean | ✅ PASSED |

### 🔍 Triggered Vulnerabilities & Actionable Remediation
#### ⚠️ `manifests/insecure/medium-deployment.yaml` (medium-app):
- **V03 (HIGH):** Privilege Escalation Allowed `[MITRE:T1548 | CIS 5.2.5 / C-0016]`
  - *Remediation:* Set securityContext.allowPrivilegeEscalation: false
- **V04 (MEDIUM):** Writable Root Filesystem `[MITRE:T1222 | CIS 5.2.12 / C-0017]`
  - *Remediation:* Set securityContext.readOnlyRootFilesystem: true and use emptyDir for temporary writes
- **V06 (HIGH):** Dangerous Capabilities CAP_NET_ADMIN/RAW Added `[MITRE:T1040 | MITRE T1040 / C-0046]`
  - *Remediation:* Remove CAP_NET_ADMIN and CAP_NET_RAW from capabilities.add
- **V08 (MEDIUM):** Capabilities Not Dropped (Missing drop: ALL) `[MITRE:T1611 | CIS 5.2.7 / C-0046]`
  - *Remediation:* Add securityContext.capabilities.drop: ['ALL']
- **V23 (MEDIUM):** Unnecessary Service Account Token Auto-Mount `[MITRE:T1078.004 | CIS 5.1.5 / C-0034]`
  - *Remediation:* Set automountServiceAccountToken: false
- **V33 (HIGH):** Direct hostPort Allocation `[MITRE:T1046 | CIS 5.2.10]`
  - *Remediation:* Use ClusterIP Services with Ingress controllers instead of hostPort
#### ⚠️ `manifests/insecure/weak-deployment.yaml` (vulnerable-app):
- **V01 (CRITICAL):** Privileged Container Execution `[MITRE:T1611 | CIS 5.2.1 / C-0057]`
  - *Remediation:* Set securityContext.privileged: false
- **V02 (HIGH):** Root User Execution (UID 0) `[MITRE:T1611 | CIS 5.2.6 / C-0013]`
  - *Remediation:* Set securityContext.runAsNonRoot: true and specify a non-zero runAsUser
- **V03 (HIGH):** Privilege Escalation Allowed `[MITRE:T1548 | CIS 5.2.5 / C-0016]`
  - *Remediation:* Set securityContext.allowPrivilegeEscalation: false
- **V04 (MEDIUM):** Writable Root Filesystem `[MITRE:T1222 | CIS 5.2.12 / C-0017]`
  - *Remediation:* Set securityContext.readOnlyRootFilesystem: true and use emptyDir for temporary writes
- **V08 (MEDIUM):** Capabilities Not Dropped (Missing drop: ALL) `[MITRE:T1611 | CIS 5.2.7 / C-0046]`
  - *Remediation:* Add securityContext.capabilities.drop: ['ALL']
- **V09 (HIGH):** Host Network Namespace Sharing (hostNetwork: true) `[MITRE:T1611 | CIS 5.2.4 / C-0041]`
  - *Remediation:* Set spec.hostNetwork: false
- **V10 (CRITICAL):** Host PID Namespace Sharing (hostPID: true) `[MITRE:T1611 | CIS 5.2.2 / C-0042]`
  - *Remediation:* Set spec.hostPID: false
- **V12 (MEDIUM):** Missing Seccomp Profile `[MITRE:T1059 | CIS 5.7.2 / C-0030]`
  - *Remediation:* Set securityContext.seccompProfile.type: RuntimeDefault
- **V13 (LOW):** Missing CPU Resource Limit `[MITRE:T1496 | CIS 5.2.13 / C-0009]`
  - *Remediation:* Define resources.limits.cpu
- **V14 (MEDIUM):** Missing Memory Resource Limit `[MITRE:T1496 | CIS 5.2.14 / C-0009]`
  - *Remediation:* Define resources.limits.memory
- **V23 (MEDIUM):** Unnecessary Service Account Token Auto-Mount `[MITRE:T1078.004 | CIS 5.1.5 / C-0034]`
  - *Remediation:* Set automountServiceAccountToken: false