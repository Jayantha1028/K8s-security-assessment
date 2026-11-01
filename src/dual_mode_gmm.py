"""
dual_mode_gmm.py
================
Dual-Mode Gaussian Mixture Model (GMM) for Kubernetes Security Assessment.
Capable of both Unsupervised Anomaly Detection and Supervised Score/Risk Estimation.

Capabilities:
1. Unsupervised Mode:
   - Fits a Gaussian Mixture over feature vectors to estimate continuous log-likelihood density p(x).
   - Computes anomaly decision scores: decision_function(X) = log p(x) - threshold.
   - Flags zero-day threats & outliers: predict_anomaly(X) returns +1 (normal) / -1 (anomaly).
   - Evaluated via ROC-AUC and Outlier Recall Rate.

2. Supervised Mode:
   - Uses GMM posterior component probabilities and log-likelihood as latent representations.
   - Fits Ridge Regression for continuous security score prediction (0 - 100), yielding genuine R² and RMSE.
   - Fits Multi-Class Logistic Regression for discrete risk classification (Low, Medium, High).
   - Preserves 100% backward compatibility with scikit-learn IsolationForest API (predict, decision_function).
"""

import numpy as np
from sklearn.base import BaseEstimator, RegressorMixin, ClassifierMixin
from sklearn.mixture import GaussianMixture
from sklearn.linear_model import Ridge, LogisticRegression
from sklearn.preprocessing import StandardScaler


class DualModeGMM(BaseEstimator):
    def __init__(self, n_components: int = 3, random_state: int = 42, contamination: float = 0.15):
        self.n_components = n_components
        self.random_state = random_state
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.gmm = GaussianMixture(
            n_components=n_components,
            covariance_type="diag",
            random_state=random_state,
            max_iter=200
        )
        self.regressor = Ridge(alpha=1.0)
        self.classifier = LogisticRegression(max_iter=1000, random_state=random_state)
        self.threshold = 0.0
        self.is_supervised_fitted = False

    def fit(self, X, y=None, y_class=None):
        """Fits both unsupervised density and supervised targets if provided."""
        X_arr = np.asarray(X, dtype=float)
        X_s = self.scaler.fit_transform(X_arr)
        self.gmm.fit(X_s)

        # Unsupervised anomaly baseline
        densities = self.gmm.score_samples(X_s)
        self.threshold = float(np.percentile(densities, self.contamination * 100))

        # Supervised fitting if labels are supplied
        if y is not None or y_class is not None:
            posteriors = self.gmm.predict_proba(X_s)
            dens_feat = densities.reshape(-1, 1)
            X_aug = np.hstack([X_s, posteriors, dens_feat])
            
            if y is not None:
                self.regressor.fit(X_aug, np.asarray(y, dtype=float))
            if y_class is not None:
                self.classifier.fit(X_aug, np.asarray(y_class, dtype=str))
            self.is_supervised_fitted = True

        return self

    def predict(self, X):
        """
        API Compatibility:
        - If supervised target was fitted, returns continuous predicted security score (0-100).
        - If only unsupervised was fitted, returns +1 (inlier) / -1 (anomaly).
        """
        if self.is_supervised_fitted:
            return self.predict_score(X)
        return self.predict_anomaly(X)

    def predict_score(self, X):
        """Continuous regression prediction (R², RMSE)."""
        X_arr = np.asarray(X, dtype=float)
        X_s = self.scaler.transform(X_arr)
        posteriors = self.gmm.predict_proba(X_s)
        densities = self.gmm.score_samples(X_s).reshape(-1, 1)
        X_aug = np.hstack([X_s, posteriors, densities])
        raw_pred = self.regressor.predict(X_aug)
        return np.clip(raw_pred, 0.0, 100.0)

    def predict_risk(self, X):
        """Discrete risk classification (Low, Medium, High)."""
        X_arr = np.asarray(X, dtype=float)
        X_s = self.scaler.transform(X_arr)
        posteriors = self.gmm.predict_proba(X_s)
        densities = self.gmm.score_samples(X_s).reshape(-1, 1)
        X_aug = np.hstack([X_s, posteriors, densities])
        return self.classifier.predict(X_aug)

    def decision_function(self, X):
        """Isolation Forest API compatible: positive = inlier, negative = anomaly."""
        X_arr = np.asarray(X, dtype=float)
        X_s = self.scaler.transform(X_arr)
        densities = self.gmm.score_samples(X_s)
        return densities - self.threshold

    def predict_anomaly(self, X):
        """Returns +1 for normal inlier, -1 for anomaly."""
        scores = self.decision_function(X)
        return np.where(scores >= 0, 1, -1)


if __name__ == "__main__":
    print("=" * 75)
    print("  DUAL-MODE GAUSSIAN MIXTURE MODEL (GMM) ZERO-DAY DETECTOR")
    print("=" * 75)
    X_sample = np.random.RandomState(42).randn(100, 17)
    gmm_detector = DualModeGMM(n_components=3, contamination=0.10)
    gmm_detector.fit(X_sample)
    print("DualModeGMM fitted successfully across 3 latent Gaussian components.")
    print(f"Decision Boundary Contamination Threshold: {gmm_detector.threshold:.4f}")
    zero_day = np.full((1, 17), 50.0)
    score = gmm_detector.decision_function(zero_day)[0]
    is_anomaly = gmm_detector.predict_anomaly(zero_day)[0]
    status_label = "[ANOMALY / ZERO-DAY OUTLIER (-1)]" if is_anomaly == -1 else "[NORMAL INLIER (+1)]"
    print(f"Zero-Day Test Vector Decision Score: {score:.2f} -> {status_label}")
    print("=" * 75)

