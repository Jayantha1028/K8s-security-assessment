#!/usr/bin/env bash
# Switch the insecure cluster between 3 essential, uncovered security scenarios:
#
#   1. medium (default): Balanced Medium-Risk staging workload (scores ~55-65)
#   2. host_secrets: Host filesystem escape (/var/run/docker.sock, /) & plaintext secrets
#   3. runtime_attack: Dangerous Linux capabilities (SYS_ADMIN, SYS_PTRACE) & simulated live intrusion
#
# Usage:
#   scripts/apply_medium_scenario.sh [medium | host_secrets | runtime_attack]
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

SCENARIO="${1:-medium}"

echo "Cleaning previous insecure deployments in $INSECURE_CTX..."
kubectl --context "$INSECURE_CTX" delete deployment vulnerable-app \
  -n security-demo --ignore-not-found >/dev/null 2>&1 || true
kubectl --context "$INSECURE_CTX" delete deployment medium-app \
  -n security-demo --ignore-not-found >/dev/null 2>&1 || true

case "$SCENARIO" in
  medium|1)
    echo "=== Scenario 1: Balanced Medium-Risk Staging Workload ==="
    kubectl --context "$INSECURE_CTX" apply -f "$MEDIUM_MANIFEST"
    echo "Applied $MEDIUM_MANIFEST to $INSECURE_CTX"
    ;;

  host_secrets|secrets|2)
    echo "=== Scenario 2: Host Takeover & Exposed Plaintext Secrets ==="
    kubectl --context "$INSECURE_CTX" apply -f - <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: database-credentials
  namespace: security-demo
type: Opaque
stringData:
  DB_PASSWORD: "SuperSecretPassword123!"
  AWS_SECRET_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: medium-app
  namespace: security-demo
  labels:
    app: medium-app
    scenario: host-secrets
spec:
  replicas: 1
  selector:
    matchLabels:
      app: medium-app
  template:
    metadata:
      labels:
        app: medium-app
    spec:
      serviceAccountName: demo-app
      hostPID: true
      containers:
      - name: web
        image: redis:7.0-alpine
        env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: DB_PASSWORD
        - name: HARDCODED_API_KEY
          value: "sk-live-51M3948572938475928374"
        volumeMounts:
        - name: host-root
          mountPath: /host-fs
        - name: docker-socket
          mountPath: /var/run/docker.sock
      volumes:
      - name: host-root
        hostPath:
          path: /
      - name: docker-socket
        hostPath:
          path: /var/run/docker.sock
EOF
    echo "Applied HostPath and Plaintext Secret workload to $INSECURE_CTX"
    ;;

  runtime_attack|attack|3)
    echo "=== Scenario 3: Container Breakout Capabilities & Runtime Intrusion ==="
    kubectl --context "$INSECURE_CTX" apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: medium-app
  namespace: security-demo
  labels:
    app: medium-app
    scenario: runtime-attack
spec:
  replicas: 1
  selector:
    matchLabels:
      app: medium-app
  template:
    metadata:
      labels:
        app: medium-app
    spec:
      serviceAccountName: demo-app
      containers:
      - name: web
        image: alpine:3.18
        command: ["/bin/sh", "-c", "sleep 36000"]
        securityContext:
          allowPrivilegeEscalation: true
          capabilities:
            add:
            - SYS_ADMIN
            - SYS_PTRACE
            - NET_RAW
EOF
    echo "Applied dangerous capabilities workload to $INSECURE_CTX"
    echo "Waiting for pod rollout to trigger live Falco alerts..."
    kubectl --context "$INSECURE_CTX" rollout status deployment/medium-app \
      -n security-demo --timeout=60s || true

    # Simulate active runtime adversary techniques:
    pod=$(kubectl --context "$INSECURE_CTX" get pod -n security-demo \
      -l app=medium-app -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

    if [ -n "$pod" ]; then
      echo "Triggering live Falco detection: Spawning interactive shell..."
      kubectl --context "$INSECURE_CTX" exec -n security-demo "$pod" \
        -- /bin/sh -c "id; uname -a" >/dev/null 2>&1 || true
      echo "Triggering live Falco detection: Reading sensitive /etc/shadow..."
      kubectl --context "$INSECURE_CTX" exec -n security-demo "$pod" \
        -- /bin/sh -c "cat /etc/shadow" >/dev/null 2>&1 || true
      echo "Live runtime intrusion simulation completed."
    fi
    ;;

  *)
    echo "Unknown scenario: $SCENARIO" >&2
    echo "Options: medium (1), host_secrets (2), runtime_attack (3)" >&2
    exit 2
    ;;
esac

echo
echo "Take a snapshot for this scenario:"
echo "  scripts/take_snapshot.sh scenario_${SCENARIO}_01"
echo
echo "Restore the weak workload when done:"
echo "  kubectl --context $INSECURE_CTX apply -f $WEAK_MANIFEST"
