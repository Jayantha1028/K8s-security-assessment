#!/usr/bin/env bash
# ==============================================================================
# generate_certs.sh
# Automates TLS Certificate generation for K8s Admission Webhook & patches caBundle
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/.certs"
NAMESPACE="k8s-security"
SERVICE_NAME="k8s-security-webhook"
SECRET_NAME="k8s-security-webhook-tls"

mkdir -p "${CERT_DIR}"
echo "==> [1/4] Generating Certificate Authority (CA)..."
openssl genrsa -out "${CERT_DIR}/ca.key" 2048
openssl req -x509 -new -nodes -key "${CERT_DIR}/ca.key" -subj "/CN=K8s-Security-CA" -days 3650 -out "${CERT_DIR}/ca.crt"

echo "==> [2/4] Generating Server Private Key and CSR with SANs..."
openssl genrsa -out "${CERT_DIR}/server.key" 2048

cat <<EOF > "${CERT_DIR}/csr.conf"
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE_NAME}
DNS.2 = ${SERVICE_NAME}.${NAMESPACE}
DNS.3 = ${SERVICE_NAME}.${NAMESPACE}.svc
DNS.4 = ${SERVICE_NAME}.${NAMESPACE}.svc.cluster.local
IP.1 = 127.0.0.1
EOF

openssl req -new -key "${CERT_DIR}/server.key" -subj "/CN=${SERVICE_NAME}.${NAMESPACE}.svc" -out "${CERT_DIR}/server.csr" -config "${CERT_DIR}/csr.conf"

echo "==> [3/4] Signing Server Certificate with CA..."
openssl x509 -req -in "${CERT_DIR}/server.csr" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial -out "${CERT_DIR}/server.crt" -days 365 -extensions v3_req -extfile "${CERT_DIR}/csr.conf"

CA_BUNDLE=$(base64 < "${CERT_DIR}/ca.crt" | tr -d '\n')

echo "==> [4/4] Outputting K8s Secret & Webhook Patch..."
echo "  • CA Certificate: ${CERT_DIR}/ca.crt"
echo "  • Server Cert   : ${CERT_DIR}/server.crt"
echo "  • Server Key    : ${CERT_DIR}/server.key"
echo "  • Base64 CA     : ${CA_BUNDLE:0:30}..."

# Create live k8s secret if kubectl is configured and connected
if command -v kubectl >/dev/null 2>&1 && kubectl get ns "${NAMESPACE}" >/dev/null 2>&1; then
    echo "==> In-cluster connection detected. Updating K8s secret ${SECRET_NAME}..."
    kubectl create secret tls "${SECRET_NAME}" \
      --cert="${CERT_DIR}/server.crt" \
      --key="${CERT_DIR}/server.key" \
      --namespace="${NAMESPACE}" \
      --dry-run=client -o yaml | kubectl apply -f -
fi

echo "✓ Certificate generation completed successfully."
