#!/usr/bin/env bash
# Create (or reuse) the secure and insecure Kind clusters, apply the demo
# manifests and install Falco on both.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_tools kind kubectl helm

SECURE="$SECURE_CLUSTER"
INSECURE="$INSECURE_CLUSTER"

create_cluster() {
  local name="$1"

  # Capture the list first: piping straight into `grep -q` can trip
  # pipefail (SIGPIPE) and wrongly report an existing cluster as missing.
  local existing
  existing="$(kind get clusters 2>/dev/null || true)"

  if ! grep -qx "$name" <<<"$existing"; then
    echo "Creating Kind cluster: $name"
    kind create cluster --name "$name" --wait 120s
  else
    echo "Kind cluster already exists: $name"
  fi
}

create_cluster "$SECURE"
create_cluster "$INSECURE"

echo "Applying secure configuration..."
kubectl --context "kind-$SECURE" apply -f "$MANIFEST_DIR/secure/secure-rbac.yaml"
kubectl --context "kind-$SECURE" apply -f "$MANIFEST_DIR/secure/secure-network-policy.yaml"
kubectl --context "kind-$SECURE" apply -f "$MANIFEST_DIR/secure/hardened-deployment.yaml"

echo "Applying insecure configuration..."
kubectl --context "kind-$INSECURE" apply -f "$MANIFEST_DIR/insecure/insecure-rbac.yaml"
kubectl --context "kind-$INSECURE" apply -f "$WEAK_MANIFEST"

# Helm remains a supported Falco deployment method.
helm repo add falcosecurity https://falcosecurity.github.io/charts \
  >/dev/null 2>&1 || true
helm repo update >/dev/null

for context in "kind-$SECURE" "kind-$INSECURE"; do

  if ! helm --kube-context "$context" status falco -n falco \
      >/dev/null 2>&1; then

    echo "Installing Falco in $context"

    helm --kube-context "$context" install falco \
      falcosecurity/falco \
      --namespace falco \
      --create-namespace \
      --set tty=true
  fi

  # Wait on the DaemonSet rollout rather than `wait pods --all`, which
  # errors with "no matching resources" if the pods have not been created
  # yet right after `helm install`.
  kubectl --context "$context" rollout status daemonset/falco \
    -n falco --timeout=300s

done

echo
echo "Secure cluster  : kind-$SECURE"
echo "Insecure cluster: kind-$INSECURE"
