"""
Models Package - Kubernetes Security Assessment Platform.

Exported Modules:
  - load_master_model: In-memory cached loader for Model 11 Master Ensemble
  - MasterModelBundle: Thread-safe inference container for Model 11
  - get_model_inventory: Status and metadata for all serialized model joblibs
  - PrometheusUnsupervisedDetector: Model 12 Isolation Forest + GMM anomaly model
  - FinalMasterModel: Dynamic Ridge stacking meta-ensemble architecture
"""

from .model_loader import load_master_model, MasterModelBundle, get_model_inventory
from .prometheus_unsupervised_model import PrometheusUnsupervisedDetector
from .train_11_models import FinalMasterModel

__all__ = [
    "load_master_model",
    "MasterModelBundle",
    "get_model_inventory",
    "PrometheusUnsupervisedDetector",
    "FinalMasterModel",
]
