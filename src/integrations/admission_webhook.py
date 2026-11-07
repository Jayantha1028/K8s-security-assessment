#!/usr/bin/env python3
"""
admission_webhook.py
====================
In-Cluster Kubernetes Admission Controller Webhook.

Intercepts Kubernetes API Server requests (CREATE / UPDATE on Pods, Deployments,
DaemonSets, StatefulSets, and Jobs) and enforces real-time security gatekeeping:

1. ValidatingAdmissionWebhook (/validate):
   - Audits workload objects through NativeSecurityScanner (56-rule taxonomy)
   - Evaluates risk score using Model 11 Dynamic Stacking Ensemble
   - Enforces Catastrophic Exploit Veto (Privileged, Host namespaces, Cluster-Admin)
   - Returns AdmissionReview with allowed: false (HTTP 403) and detailed violations
     if the workload exceeds risk boundaries.

2. MutatingAdmissionWebhook (/mutate):
   - Generates RFC 6902 JSONPatch operations to automatically inject least-privilege
     securityContext (runAsNonRoot, readOnlyRootFilesystem, drop capabilities, seccomp).

3. Operations & Observability:
   - Built-in HTTPS/TLS server (RFC-compliant subjectAltNames)
   - Automatic pure-Python TLS certificate generation for zero-touch dev/testing
   - /healthz and /readyz probes
   - /metrics OpenMetrics admission counter endpoint
"""

import argparse
import base64
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path
import socketserver
import ssl
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Path resolution
_CORE_DIR = Path(__file__).resolve().parents[1] / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
    sys.path.insert(0, str(_CORE_DIR.parent))
import paths
from scanners.native_security_scanner import NativeSecurityScanner, ScanReport

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [ADMISSION-CONTROLLER] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("AdmissionController")

# Metrics state
METRICS = {
    "admissions_total": 0,
    "admissions_approved_total": 0,
    "admissions_rejected_total": 0,
    "admissions_mutated_total": 0,
}
METRICS_LOCK = threading.Lock()


def generate_self_signed_cert(
    cert_path: str,
    key_path: str,
    domain: str = "k8s-security-webhook.k8s-security.svc",
    valid_days: int = 365,
) -> Tuple[str, str]:
    """Generate self-signed TLS certificates with proper SANs for K8s API server."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        logger.info(f"Generating self-signed TLS certificates for domain: {domain}")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "K8s Security Assessment Platform"),
        ])

        san_list = [
            x509.DNSName("localhost"),
            x509.DNSName("k8s-security-webhook"),
            x509.DNSName("k8s-security-webhook.k8s-security"),
            x509.DNSName("k8s-security-webhook.k8s-security.svc"),
            x509.DNSName("k8s-security-webhook.k8s-security.svc.cluster.local"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=valid_days))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        p_cert = Path(cert_path)
        p_key = Path(key_path)
        p_cert.parent.mkdir(parents=True, exist_ok=True)
        p_key.parent.mkdir(parents=True, exist_ok=True)

        with open(p_cert, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(p_key, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        logger.info(f"Generated TLS certificate: {cert_path} and key: {key_path}")
        return cert_path, key_path
    except Exception as e:
        logger.error(f"Failed to generate self-signed cert via cryptography: {e}")
        raise


class AdmissionSecurityEngine:
    """
    Evaluates Kubernetes API AdmissionReview requests using NativeSecurityScanner
    and Model 11 Bayesian Stacking Ensemble.
    """

    def __init__(
        self,
        risk_threshold: float = 35.0,
        veto_rules: Optional[Set[str]] = None,
        enable_model_11: bool = True,
        enable_mutation: bool = True,
        enforcement_mode: str = "enforce",  # "enforce", "warn", "audit"
    ):
        self.risk_threshold = risk_threshold
        self.veto_rules = veto_rules or {"V01", "V02", "V03", "V04", "V14", "V26"}
        self.enable_mutation = enable_mutation
        self.enforcement_mode = enforcement_mode.lower()
        self.scanner = NativeSecurityScanner()

        # Load Model 11 if requested
        self.model_bundle = None
        self.model = None
        self.feature_names = []
        if enable_model_11:
            self._load_model_11()

    def _load_model_11(self):
        try:
            from models.model_loader import load_master_model
            bundle = load_master_model()
            if bundle is not None:
                self.model_bundle = bundle
                self.model = bundle.model
                self.feature_names = bundle.features
                logger.info(f"Loaded Model 11 Master Ensemble from {bundle.bundle_path}")
            else:
                logger.warning("Model 11 bundle not found. Using Native AST scoring.")
        except Exception as e:
            logger.warning(f"Failed to load Model 11 bundle: {e}. Falling back to Native AST scoring.")

    def evaluate_workload(self, obj: Dict[str, Any], workload_name: str) -> Tuple[bool, float, str, List[str]]:
        """
        Evaluate a single workload object.
        Returns: (allowed, score, risk_tier, reasons)
        """
        report: ScanReport = self.scanner.scan_dict(obj, source_name=workload_name)
        score = report.compliance_score
        risk_tier = report.risk_tier
        reasons = []

        # 1. Catastrophic Exploit Veto Check
        triggered_veto_rules = sorted(list(self.veto_rules.intersection(report.detected_vuln_ids)))
        if triggered_veto_rules:
            findings_map = {f.vuln_id: f.title for f in report.findings}
            veto_descs = [f"{vid}: {findings_map.get(vid, 'Exploit detected')}" for vid in triggered_veto_rules]
            reasons.append(f"Catastrophic Exploit Veto triggered: {'; '.join(veto_descs)}")
            score = min(score, 35.0)
            risk_tier = "High"
            return False, score, risk_tier, reasons

        # 2. Model 11 ML Prediction (if available)
        if self.model is not None and self.feature_names:
            try:
                import pandas as pd
                feat_dict = {f: float(report.features.get(f, 0.0)) for f in self.feature_names}
                df = pd.DataFrame([feat_dict])
                ml_scores = self.model.predict_score(df)
                ml_risks = self.model.predict_risk(df)
                score = round(float(ml_scores[0]), 2)
                risk_tier = str(ml_risks[0])
            except Exception as e:
                logger.debug(f"Model 11 inference fallback: {e}")

        # 3. Threshold Gate
        if score < self.risk_threshold or risk_tier == "High":
            high_findings = [f"{f.vuln_id} ({f.title})" for f in report.findings if f.severity in ("CRITICAL", "HIGH")]
            if high_findings:
                reasons.append(f"High-risk violations detected: {', '.join(high_findings[:5])}")
            else:
                reasons.append(f"Calculated security score ({score:.1f}/100) below threshold ({self.risk_threshold:.1f})")
            return False, score, risk_tier, reasons

        return True, score, risk_tier, []

    def handle_validation(self, review_request: Dict[str, Any]) -> Dict[str, Any]:
        """Process K8s ValidatingAdmissionWebhook request."""
        uid = review_request.get("uid", "")
        obj = review_request.get("object", {})
        kind = review_request.get("kind", {}).get("kind", obj.get("kind", "Unknown"))
        namespace = review_request.get("namespace", obj.get("metadata", {}).get("namespace", "default"))
        name = obj.get("metadata", {}).get("name", "unnamed")
        target_name = f"{namespace}/{kind}/{name}"

        # Update metrics
        with METRICS_LOCK:
            METRICS["admissions_total"] += 1

        # Non-workload objects (e.g. ConfigMaps, Namespaces) pass through
        workload_kinds = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "ReplicaSet"}
        if kind not in workload_kinds:
            with METRICS_LOCK:
                METRICS["admissions_approved_total"] += 1
            return {
                "uid": uid,
                "allowed": True,
                "status": {"code": 200, "message": f"Object kind '{kind}' bypassed security gate."},
            }

        allowed, score, risk_tier, reasons = self.evaluate_workload(obj, target_name)

        if not allowed:
            if self.enforcement_mode in ("warn", "audit"):
                with METRICS_LOCK:
                    METRICS["admissions_approved_total"] += 1
                warn_msg = f"[k8s-sec WARN] Workload {target_name} security score {score:.1f}/100 below threshold ({self.risk_threshold:.1f}). Violations: {'; '.join(reasons)}"
                logger.warning(warn_msg)
                return {
                    "uid": uid,
                    "allowed": True,
                    "warnings": [warn_msg],
                    "status": {
                        "code": 200,
                        "message": warn_msg,
                    },
                }
            else:
                with METRICS_LOCK:
                    METRICS["admissions_rejected_total"] += 1
                msg = f"[K8S-SECURITY VETO] Admission REJECTED for {target_name}. Score: {score:.1f}/100 (Tier: {risk_tier}). { ' | '.join(reasons) }"
                logger.warning(msg)
                return {
                    "uid": uid,
                    "allowed": False,
                    "status": {
                        "code": 403,
                        "message": msg,
                    },
                }

        with METRICS_LOCK:
            METRICS["admissions_approved_total"] += 1
        logger.info(f"Admission APPROVED for {target_name}. Score: {score:.1f}/100 (Tier: {risk_tier}).")
        return {
            "uid": uid,
            "allowed": True,
            "status": {
                "code": 200,
                "message": f"Workload passed security assessment. Score: {score:.1f}/100 (Tier: {risk_tier}).",
            },
        }

    def handle_mutation(self, review_request: Dict[str, Any]) -> Dict[str, Any]:
        """Process K8s MutatingAdmissionWebhook request and generate RFC 6902 JSONPatch."""
        uid = review_request.get("uid", "")
        obj = review_request.get("object", {})
        kind = review_request.get("kind", {}).get("kind", obj.get("kind", "Unknown"))
        namespace = review_request.get("namespace", "default")
        name = obj.get("metadata", {}).get("name", "unnamed")

        with METRICS_LOCK:
            METRICS["admissions_total"] += 1

        if not self.enable_mutation:
            return {"uid": uid, "allowed": True}

        patches = self._generate_json_patches(obj)
        if patches:
            patch_bytes = json.dumps(patches).encode("utf-8")
            patch_b64 = base64.b64encode(patch_bytes).decode("utf-8")
            with METRICS_LOCK:
                METRICS["admissions_mutated_total"] += 1
            logger.info(f"Auto-Remediated {namespace}/{kind}/{name}: Injected {len(patches)} security patches.")
            return {
                "uid": uid,
                "allowed": True,
                "patchType": "JSONPatch",
                "patch": patch_b64,
            }

        return {"uid": uid, "allowed": True}

    @staticmethod
    def _generate_json_patches(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate RFC 6902 JSONPatch array for least-privilege security hardening."""
        kind = obj.get("kind", "")
        patches = []

        # Determine path prefix to pod spec
        if kind == "Pod":
            prefix = "/spec"
        elif kind in ("Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet"):
            prefix = "/spec/template/spec"
        elif kind == "CronJob":
            prefix = "/spec/jobTemplate/spec/template/spec"
        else:
            return []

        # Navigate to pod spec in dictionary
        parts = [p for p in prefix.split("/") if p]
        curr = obj
        for p in parts:
            if isinstance(curr, dict):
                curr = curr.get(p)
            else:
                curr = None
                break

        if not isinstance(curr, dict):
            return []

        # 1. Pod-level securityContext
        pod_sec = curr.get("securityContext")
        if pod_sec is None:
            patches.append({
                "op": "add",
                "path": f"{prefix}/securityContext",
                "value": {
                    "runAsNonRoot": True,
                    "runAsUser": 10001,
                    "runAsGroup": 10001,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            })
        else:
            if not pod_sec.get("runAsNonRoot"):
                patches.append({"op": "add", "path": f"{prefix}/securityContext/runAsNonRoot", "value": True})
                patches.append({"op": "add", "path": f"{prefix}/securityContext/runAsUser", "value": 10001})
            if "seccompProfile" not in pod_sec:
                patches.append({
                    "op": "add",
                    "path": f"{prefix}/securityContext/seccompProfile",
                    "value": {"type": "RuntimeDefault"},
                })

        # 2. Host namespaces removal
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if curr.get(field):
                patches.append({"op": "remove", "path": f"{prefix}/{field}"})

        # 3. Container-level hardening
        containers = curr.get("containers") or []
        for idx, c in enumerate(containers):
            c_prefix = f"{prefix}/containers/{idx}"
            c_sec = c.get("securityContext")
            if c_sec is None:
                patches.append({
                    "op": "add",
                    "path": f"{c_prefix}/securityContext",
                    "value": {
                        "allowPrivilegeEscalation": False,
                        "privileged": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                })
            else:
                if c_sec.get("privileged"):
                    patches.append({"op": "replace", "path": f"{c_prefix}/securityContext/privileged", "value": False})
                if c_sec.get("allowPrivilegeEscalation") is not False:
                    patches.append({"op": "add", "path": f"{c_prefix}/securityContext/allowPrivilegeEscalation", "value": False})
                if not c_sec.get("readOnlyRootFilesystem"):
                    patches.append({"op": "add", "path": f"{c_prefix}/securityContext/readOnlyRootFilesystem", "value": True})
                caps = c_sec.get("capabilities")
                if caps is None:
                    patches.append({"op": "add", "path": f"{c_prefix}/securityContext/capabilities", "value": {"drop": ["ALL"]}})
                elif "ALL" not in caps.get("drop", []):
                    patches.append({"op": "add", "path": f"{c_prefix}/securityContext/capabilities/drop", "value": ["ALL"]})

        return patches


class AdmissionRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for Kubernetes Admission Review protocol."""

    engine: AdmissionSecurityEngine = None  # Injected by server

    def do_GET(self):
        """Handle health, readiness, and metrics endpoints."""
        if self.path in ("/healthz", "/readyz", "/livez"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "status": "healthy",
                "service": "k8s-security-admission-controller",
                "model_11_loaded": self.engine.model is not None,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))

        elif self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            with METRICS_LOCK:
                lines = [
                    "# HELP k8s_security_admissions_total Total admission requests received.",
                    "# TYPE k8s_security_admissions_total counter",
                    f"k8s_security_admissions_total {METRICS['admissions_total']}",
                    "# HELP k8s_security_admissions_approved_total Total admission requests approved.",
                    "# TYPE k8s_security_admissions_approved_total counter",
                    f"k8s_security_admissions_approved_total {METRICS['admissions_approved_total']}",
                    "# HELP k8s_security_admissions_rejected_total Total admission requests rejected by security gate.",
                    "# TYPE k8s_security_admissions_rejected_total counter",
                    f"k8s_security_admissions_rejected_total {METRICS['admissions_rejected_total']}",
                    "# HELP k8s_security_admissions_mutated_total Total admission requests auto-remediated.",
                    "# TYPE k8s_security_admissions_mutated_total counter",
                    f"k8s_security_admissions_mutated_total {METRICS['admissions_mutated_total']}",
                ]
            self.wfile.write("\n".join(lines).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handle /validate and /mutate AdmissionReview requests."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_response(400)
            self.end_headers()
            return

        body = self.rfile.read(content_length)
        try:
            review = json.loads(body.decode("utf-8"))
        except Exception as e:
            logger.error(f"Failed to parse incoming AdmissionReview JSON: {e}")
            self.send_response(400)
            self.end_headers()
            return

        req = review.get("request", {})
        api_version = review.get("apiVersion", "admission.k8s.io/v1")
        kind = review.get("kind", "AdmissionReview")

        if self.path == "/validate":
            resp_data = self.engine.handle_validation(req)
        elif self.path == "/mutate":
            resp_data = self.engine.handle_mutation(req)
        else:
            self.send_response(404)
            self.end_headers()
            return

        out_review = {
            "apiVersion": api_version,
            "kind": kind,
            "response": resp_data,
        }

        resp_bytes = json.dumps(out_review).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)

    def log_message(self, format, *args):
        # Override default stderr logger to keep terminal clean
        logger.debug(f"{self.address_string()} - {format % args}")


class ThreadedAdmissionServer(socketserver.ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP(S) Server for handling concurrent AdmissionReview requests."""
    daemon_threads = True


def start_admission_server(
    host: str = "0.0.0.0",
    port: int = 8443,
    cert_file: Optional[str] = None,
    key_file: Optional[str] = None,
    use_tls: bool = True,
    risk_threshold: float = 35.0,
    enable_mutation: bool = True,
    enable_model_11: bool = True,
    enforcement_mode: str = "enforce",
) -> ThreadedAdmissionServer:
    """Start and return the Admission Controller Server."""
    engine = AdmissionSecurityEngine(
        risk_threshold=risk_threshold,
        enable_model_11=enable_model_11,
        enable_mutation=enable_mutation,
        enforcement_mode=enforcement_mode,
    )
    AdmissionRequestHandler.engine = engine

    server = ThreadedAdmissionServer((host, port), AdmissionRequestHandler)

    if use_tls:
        if not cert_file or not key_file or not os.path.exists(cert_file) or not os.path.exists(key_file):
            # Auto-generate self-signed certs in .certs directory
            default_cert_dir = paths.ROOT / ".certs"
            c_file, k_file = generate_self_signed_cert(
                cert_path=str(default_cert_dir / "webhook-server-cert.pem"),
                key_path=str(default_cert_dir / "webhook-server-key.pem"),
            )
            cert_file = c_file
            key_file = k_file

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        proto = "HTTPS"
    else:
        proto = "HTTP"

    logger.info(f"Admission Controller listening on {proto}://{host}:{port}")
    logger.info(f"  • Endpoints: /validate, /mutate, /healthz, /readyz, /metrics")
    logger.info(f"  • Policy Threshold: Score >= {risk_threshold:.1f} (Veto: V01, V02, V03, V04, V14, V26)")
    logger.info(f"  • Auto-Remediation Mutation: {'ENABLED' if enable_mutation else 'DISABLED'}")
    return server


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Dynamic Admission Webhook Controller")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8443, help="Port to listen on (default: 8443)")
    parser.add_argument("--cert", default=None, help="Path to TLS certificate file")
    parser.add_argument("--key", default=None, help="Path to TLS private key file")
    parser.add_argument("--insecure-http", action="store_true", help="Run without TLS (for local testing/curl)")
    parser.add_argument("--risk-threshold", type=float, default=35.0, help="Minimum score to permit admission")
    parser.add_argument("--no-mutation", action="store_true", help="Disable auto-remediation mutating webhook")
    parser.add_argument("--no-model-11", action="store_true", help="Disable Model 11 ML inference (use AST rules only)")

    args = parser.parse_args()

    server = start_admission_server(
        host=args.host,
        port=args.port,
        cert_file=args.cert,
        key_file=args.key,
        use_tls=not args.insecure_http,
        risk_threshold=args.risk_threshold,
        enable_mutation=not args.no_mutation,
        enable_model_11=not args.no_model_11,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping Admission Controller server...")
        server.server_close()
        logger.info("Shutdown complete.")


if __name__ == "__main__":
    main()
