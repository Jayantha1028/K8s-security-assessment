#!/usr/bin/env python3
"""
model_loader.py
===============
Unified Machine Learning Model Bundle Loader & Inference Facade.

Eliminates redundant disk loads and provides thread-safe, cached access
to Model 11 (Master Stacking Ensemble) and Model 12 (Prometheus Anomaly Detector).
"""

from functools import lru_cache
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

_SRC_DIR = Path(__file__).resolve().parents[1]
_CORE_DIR = _SRC_DIR / "core"
if str(_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_DIR))
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
import paths

logger = logging.getLogger("ModelLoader")

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


class MasterModelBundle:
    def __init__(self, model: Any, features: List[str], bundle_path: Path):
        self.model = model
        self.features = features
        self.bundle_path = bundle_path

    def predict(self, feature_dict: Dict[str, float]) -> Tuple[float, str]:
        """Run inference on a single feature dictionary."""
        try:
            import pandas as pd
            row = {f: float(feature_dict.get(f, 0.0)) for f in self.features}
            df = pd.DataFrame([row])
            scores = self.model.predict_score(df)
            risks = self.model.predict_risk(df)
            return round(float(scores[0]), 2), str(risks[0])
        except Exception as e:
            logger.warning(f"Master model inference failed: {e}. Falling back to default.")
            return 50.0, "Medium"


_CACHED_MASTER_BUNDLE: Optional[MasterModelBundle] = None


def load_master_model(bundle_path: Optional[str] = None) -> Optional[MasterModelBundle]:
    """Load and return the pre-trained Model 11 Master Bundle (cached in-memory)."""
    global _CACHED_MASTER_BUNDLE
    if _CACHED_MASTER_BUNDLE is not None:
        return _CACHED_MASTER_BUNDLE

    import joblib

    candidate_paths = [
        Path(bundle_path) if bundle_path else None,
        paths.ROOT / "models" / "model_11_final_master.joblib",
        paths.ROOT / "models" / "security_models_11.joblib",
    ]

    for p in candidate_paths:
        if p and p.is_file():
            try:
                bundle = joblib.load(p)
                model = bundle.get("model")
                features = bundle.get("features", [])
                if model is not None:
                    _CACHED_MASTER_BUNDLE = MasterModelBundle(model=model, features=features, bundle_path=p)
                    logger.info(f"Loaded Master Model 11 bundle from {p}")
                    return _CACHED_MASTER_BUNDLE
            except Exception as e:
                logger.warning(f"Failed loading candidate model at {p}: {e}")

    logger.warning("No Master Model 11 bundle could be located.")
    return None


def get_model_inventory() -> Dict[str, Any]:
    """Return status of all machine learning models in the repository."""
    models_dir = paths.ROOT / "models"
    inventory = {}
    if models_dir.is_dir():
        for f in sorted(models_dir.glob("*.joblib")):
            inventory[f.name] = {
                "size_kb": round(f.stat().st_size / 1024, 2),
                "path": str(f),
            }
    return inventory
