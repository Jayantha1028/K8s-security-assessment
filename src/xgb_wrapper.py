"""XGBoost wrapper to provide scikit-learn compatible string classification.

Standard XGBClassifier requires target labels encoded as integer [0, num_classes-1].
XGBoostSecurityClassifier wraps XGBClassifier with a fitted LabelEncoder so that
input string targets (e.g., 'Low', 'Medium', 'High') and string predictions work
seamlessly across pipelines and serialization without breaking existing code.
"""

from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb


class XGBoostSecurityClassifier(BaseEstimator, ClassifierMixin):
    def __init__(
        self,
        n_estimators=100,
        max_depth=4,
        learning_rate=0.05,
        min_child_weight=0,
        random_state=42,
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.learning_rate = learning_rate
        self.min_child_weight = min_child_weight
        self.random_state = random_state
        self.classes_ = None
        self._model = None
        self._encoder = None

    def fit(self, X, y):
        self._encoder = LabelEncoder()
        y_encoded = self._encoder.fit_transform(y)
        self.classes_ = self._encoder.classes_
        self._model = xgb.XGBClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            learning_rate=self.learning_rate,
            min_child_weight=self.min_child_weight,
            random_state=self.random_state,
            eval_metric="mlogloss",
        )
        self._model.fit(X, y_encoded)
        return self

    def predict(self, X):
        if self._model is None or self._encoder is None:
            raise RuntimeError("XGBoostSecurityClassifier is not fitted yet.")
        y_pred = self._model.predict(X)
        return self._encoder.inverse_transform(y_pred)

    def predict_proba(self, X):
        if self._model is None:
            raise RuntimeError("XGBoostSecurityClassifier is not fitted yet.")
        return self._model.predict_proba(X)

    @property
    def feature_importances_(self):
        if self._model is None:
            raise RuntimeError("XGBoostSecurityClassifier is not fitted yet.")
        return self._model.feature_importances_
