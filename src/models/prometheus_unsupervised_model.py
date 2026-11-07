#!/usr/bin/env python3
"""
prometheus_unsupervised_model.py
================================
Purely Unsupervised Anomaly Detection Architecture for Kubernetes Runtime Telemetry.

Combines an Isolation Forest with a Gaussian Mixture Model (GMM) density estimator
to detect runtime security anomalies (Cryptomining, C2 Exfiltration, Exploit Crashloops,
and API Server Reconnaissance) without requiring labeled attack data.

Key Architecture:
1. Feature Preprocessing: StandardScaler with robust clipping.
2. Isolation Forest: Partitions multidimensional feature space to isolate outliers.
3. Gaussian Mixture Model: Estimates continuous multivariate log-likelihood density p(x).
4. Calibrated Threat Scoring: Converts isolation path lengths and log-densities into a
   standardized 0.0 to 100.0 Runtime Anomaly Score.
5. Explainable Driver Attribution: Computes per-feature z-score contributions so SREs
   know exactly which metric (CPU, Network Tx, Restarts, 403s) triggered the alert.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator
from sklearn.ensemble import IsolationForest
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler

PROMETHEUS_FEATURES = [
    "cpu_usage_cores",
    "memory_working_set_mb",
    "restart_rate_per_hour",
    "network_tx_kbps",
    "network_rx_kbps",
    "falco_alerts_rate",
    "apiserver_403_rate",
]


class PrometheusUnsupervisedDetector(BaseEstimator):
    """
    Purely Unsupervised Anomaly Detection Model for Prometheus Kubernetes Telemetry.
    Learns strictly from normal baseline operational metrics with zero attack labels.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 150,
        n_components: int = 4,
        anomaly_score_threshold: float = 40.0,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.n_components = n_components
        self.anomaly_score_threshold = anomaly_score_threshold
        self.random_state = random_state

        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.gmm = GaussianMixture(
            n_components=n_components,
            covariance_type="diag",
            random_state=random_state,
            max_iter=200,
        )

        self.is_fitted = False
        self.baseline_densities_min = -100.0
        self.baseline_densities_median = 0.0
        self.iso_threshold = 0.0
        self.feature_means = np.zeros(len(PROMETHEUS_FEATURES))
        self.feature_stds = np.ones(len(PROMETHEUS_FEATURES))
        self.rolling_buffer: List[np.ndarray] = []
        self.max_buffer_size: int = 500

    def _prepare_X(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        if isinstance(X, pd.DataFrame):
            cols = [c for c in PROMETHEUS_FEATURES if c in X.columns]
            if len(cols) != len(PROMETHEUS_FEATURES):
                # Fallback to reindex with zero fill
                X_df = X.reindex(columns=PROMETHEUS_FEATURES, fill_value=0.0)
                return X_df.values.astype(float)
            return X[PROMETHEUS_FEATURES].values.astype(float)
        return np.asarray(X, dtype=float)

    def fit(self, X: Union[pd.DataFrame, np.ndarray], y: Optional[Any] = None) -> "PrometheusUnsupervisedDetector":
        """
        Fit unsupervised model on unlabeled normal baseline telemetry.
        """
        X_arr = self._prepare_X(X)
        X_scaled = self.scaler.fit_transform(X_arr)

        # Record feature statistics for threat driver attribution
        self.feature_means = np.mean(X_arr, axis=0)
        self.feature_stds = np.std(X_arr, axis=0)
        self.feature_stds[self.feature_stds == 0] = 1.0  # prevent div by zero
        self.initial_feature_means = np.copy(self.feature_means)
        self.initial_feature_stds = np.copy(self.feature_stds)

        # Fit Isolation Forest and GMM density
        self.isolation_forest.fit(X_scaled)
        self.gmm.fit(X_scaled)

        # Baseline calibration
        densities = self.gmm.score_samples(X_scaled)
        self.baseline_densities_min = float(np.percentile(densities, self.contamination * 100))
        self.baseline_densities_median = float(np.median(densities))

        iso_scores = self.isolation_forest.decision_function(X_scaled)
        self.iso_threshold = float(np.percentile(iso_scores, self.contamination * 100))

        self.rolling_buffer = list(X_arr[-self.max_buffer_size:])
        self.is_fitted = True
        return self

    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """
        Predict binary anomaly status:
        +1 = Normal (within baseline bounds)
        -1 = Anomaly (Zero-Day Outlier / Breach)
        """
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted. Call fit() first.")
        scores = self.score_anomaly(X)
        return np.where(scores >= self.anomaly_score_threshold, -1, 1)

    def score_anomaly(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """
        Compute continuous Runtime Anomaly Score (0.0 to 100.0).
        0.0 - 30.0  : Healthy Normal
        30.0 - 60.0 : Elevated Activity / Warning
        60.0 - 100.0: Critical Anomaly / Attack Vector
        """
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted. Call fit() first.")
        X_arr = self._prepare_X(X)
        X_scaled = self.scaler.transform(X_arr)

        # 1. Isolation Forest component (decision_function < 0 means outlier)
        iso_scores = self.isolation_forest.decision_function(X_scaled)
        # Shift and scale: normal values (~0.1 to 0.3) -> low anomaly; negative values -> high anomaly
        iso_anomaly = np.clip((self.iso_threshold - iso_scores) * 200.0 + 35.0, 0.0, 100.0)

        # 2. GMM Log-Likelihood component
        densities = self.gmm.score_samples(X_scaled)
        spread = max(abs(self.baseline_densities_median - self.baseline_densities_min), 1e-4)
        gmm_anomaly = np.clip((self.baseline_densities_median - densities) / spread * 35.0, 0.0, 100.0)

        # Ensemble weighting (55% Isolation Forest + 45% Density log-likelihood)
        combined_scores = 0.55 * iso_anomaly + 0.45 * gmm_anomaly
        return np.round(np.clip(combined_scores, 0.0, 100.0), 2)

    def attribute_threat_drivers(
        self, row: Union[pd.Series, Dict[str, float], np.ndarray]
    ) -> List[Dict[str, Any]]:
        """
        Attribute which specific Prometheus metrics are driving the anomaly.
        Computes normalized z-score deviations from the learned healthy baseline.
        """
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted. Call fit() first.")

        if isinstance(row, pd.Series):
            vals = [float(row.get(f, 0.0)) for f in PROMETHEUS_FEATURES]
        elif isinstance(row, dict):
            vals = [float(row.get(f, 0.0)) for f in PROMETHEUS_FEATURES]
        else:
            vals = list(np.asarray(row, dtype=float).flatten()[: len(PROMETHEUS_FEATURES)])

        drivers = []
        for i, feat in enumerate(PROMETHEUS_FEATURES):
            val = vals[i]
            mean = self.feature_means[i]
            std = self.feature_stds[i]
            z_score = (val - mean) / std
            if z_score > 1.5:  # Significant upward deviation
                drivers.append(
                    {
                        "metric": feat,
                        "observed_value": round(val, 2),
                        "baseline_mean": round(mean, 2),
                        "z_deviation": round(z_score, 2),
                        "threat_indication": self._map_metric_threat(feat, val),
                    }
                )

        drivers.sort(key=lambda d: d["z_deviation"], reverse=True)
        return drivers

    @staticmethod
    def _map_metric_threat(metric: str, val: float) -> str:
        if metric == "cpu_usage_cores" and val > 1.0:
            return "Suspected Cryptomining / CPU Exhaustion (MITRE T1496)"
        if metric == "network_tx_kbps" and val > 500.0:
            return "Potential C2 Data Exfiltration / Egress Spike (MITRE T1048)"
        if metric == "restart_rate_per_hour" and val > 2.0:
            return "Exploit-Induced Crash-Loop / Segfault Attack"
        if metric == "falco_alerts_rate" and val > 0.1:
            return "Kernel Syscall Security Violation (eBPF Alert)"
        if metric == "apiserver_403_rate" and val > 0.1:
            return "Kubernetes API RBAC Probing / Reconnaissance"
        return "Elevated Operational Anomaly"

    def update_online_baseline(
        self,
        X: Union[pd.DataFrame, np.ndarray],
        alpha: float = 0.05,
        max_anomaly_threshold: float = 30.0,
        max_drift_multiplier: float = 2.5,
    ) -> Dict[str, Any]:
        """
        Continuous Online Learning: Updates the running baseline manifold as containers run.

        Anti-Poisoning Guardrails:
        1. Filters out any telemetry with score_anomaly >= max_anomaly_threshold.
        2. Bounded Robust Statistics: Hard ceiling prevents "Boiling Frog" baseline poisoning
           by capping learned means at max_drift_multiplier * initial_feature_means.
        """
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted. Call fit() first.")

        X_arr = self._prepare_X(X)
        if len(X_arr) == 0:
            return {"learned_samples": 0, "poisonous_rejected": 0, "status": "EMPTY_BATCH"}

        scores = self.score_anomaly(X_arr)
        clean_mask = scores < max_anomaly_threshold
        poison_count = int(np.sum(~clean_mask))
        clean_count = int(np.sum(clean_mask))

        if clean_count == 0:
            return {
                "learned_samples": 0,
                "poisonous_rejected": poison_count,
                "status": "ALL_VETOED_BY_GUARDRAIL",
            }

        clean_X = X_arr[clean_mask]
        for row in clean_X:
            self.rolling_buffer.append(row)

        if len(self.rolling_buffer) > self.max_buffer_size:
            self.rolling_buffer = self.rolling_buffer[-self.max_buffer_size:]

        # Update running baseline statistics via EMA for threat driver attribution
        batch_mean = np.mean(clean_X, axis=0)
        batch_std = np.std(clean_X, axis=0)
        batch_std[batch_std == 0] = 1.0

        new_means = (1.0 - alpha) * self.feature_means + alpha * batch_mean
        new_stds = (1.0 - alpha) * self.feature_stds + alpha * batch_std

        # Apply Bounded Robust Statistics ceiling
        if hasattr(self, "initial_feature_means") and self.initial_feature_means is not None:
            max_allowed = np.maximum(self.initial_feature_means * max_drift_multiplier, 1e-4)
            new_means = np.minimum(new_means, max_allowed)

        self.feature_means = new_means
        self.feature_stds = new_stds

        return {
            "learned_samples": clean_count,
            "poisonous_rejected": poison_count,
            "status": "BASELINE_UPDATED",
            "buffer_size": len(self.rolling_buffer),
            "updated_means": {
                feat: round(float(self.feature_means[i]), 3)
                for i, feat in enumerate(PROMETHEUS_FEATURES)
            },
        }
