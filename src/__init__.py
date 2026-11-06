"""Kubernetes Security Assessment Platform (v2.0.0)

Unified Architecture:
  - scanners: NativeSecurityScanner, HybridContainerLayerScanner, CVEDatabaseEngine, auto-remediation
  - models: Master Stacking Ensemble (Model 11), Prometheus Unsupervised Detector (Model 12)
  - integrations: Dynamic Admission Webhook (/validate, /mutate), Streaming Telemetry Daemon
  - reporting: Executive Compliance Audit (PDF/HTML), Self-Hosted Web Management Console
  - evaluation: 12 Statistical Rigor Gates, 6 Chaos Engineering Scenarios, CI/CD Gate
  - cli: Unified `k8s-sec` entry point
"""

import sys
from pathlib import Path

# Bootstrap sys.path for subpackages and core
_PKG_DIR = Path(__file__).resolve().parent
_CORE_DIR = _PKG_DIR / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
if str(_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_PKG_DIR))

import paths
sys.modules.setdefault("paths", paths)

# Module aliases for serialized ML models and backward compatibility
try:
    import models.train_11_models as train_11_models
    sys.modules.setdefault("train_11_models", train_11_models)
except ImportError:
    pass

try:
    import models.xgb_wrapper as xgb_wrapper
    sys.modules.setdefault("xgb_wrapper", xgb_wrapper)
except ImportError:
    pass

# Primary API Exports
from scanners.native_security_scanner import NativeSecurityScanner, ScanReport, Finding
from scanners.container_layer_scanner import HybridContainerLayerScanner, SBOMScanReport
from scanners.cve_sync_engine import CVEDatabaseEngine
from scanners.auto_remediate import remediate_manifest, remediate_workload_dict, remediate_yaml_string
from models.model_loader import load_master_model, MasterModelBundle, get_model_inventory
from models.prometheus_unsupervised_model import PrometheusUnsupervisedDetector
from integrations.admission_webhook import start_admission_server, AdmissionSecurityEngine
from integrations.run_prometheus_daemon import run_continuous_daemon
from reporting.web_dashboard import start_web_console
from reporting.generate_executive_audit import generate_compliance_reports

__all__ = [
    "NativeSecurityScanner",
    "ScanReport",
    "Finding",
    "HybridContainerLayerScanner",
    "SBOMScanReport",
    "CVEDatabaseEngine",
    "remediate_manifest",
    "remediate_workload_dict",
    "remediate_yaml_string",
    "load_master_model",
    "MasterModelBundle",
    "get_model_inventory",
    "PrometheusUnsupervisedDetector",
    "start_admission_server",
    "AdmissionSecurityEngine",
    "run_continuous_daemon",
    "start_web_console",
    "generate_compliance_reports",
]
