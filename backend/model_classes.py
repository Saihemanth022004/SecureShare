"""
model_classes.py
────────────────
Custom model classes that must be importable at unpickle time.
The generic_model.pkl was serialised with EnsembleAnomalyDetector
defined in __main__, so we re-create it here.
"""

import numpy as np


class EnsembleAnomalyDetector:
    """
    Ensemble of IsolationForest + OneClassSVM.

    Both underlying models use scikit-learn's convention:
        predict()  →  +1  (inlier / SAFE)
                      -1  (outlier / MALWARE)

    We expose a standard classifier interface so scanner.py can
    use predict() and decision_function() without special-casing.
    """

    def __init__(self, iso=None, ocsvm=None):
        self.iso   = iso
        self.ocsvm = ocsvm

    # ── prediction ───────────────────────────────────────────────
    def predict(self, X):
        """
        Returns array of 0 (SAFE) or 1 (MALWARE).
        A sample is MALWARE only when BOTH sub-models flag it as an outlier.
        """
        preds = np.zeros(len(X), dtype=int)

        iso_pred   = self.iso.predict(X)   if self.iso   else np.ones(len(X))
        ocsvm_pred = self.ocsvm.predict(X) if self.ocsvm else np.ones(len(X))

        # −1 means outlier; require both to agree for a MALWARE verdict
        for i in range(len(X)):
            if iso_pred[i] == -1 and ocsvm_pred[i] == -1:
                preds[i] = 1   # MALWARE

        return preds

    def predict_proba(self, X):
        """
        Returns [[safe_prob, malware_prob], ...] suitable for
        scanner.py's standard predict_proba path.

        IsolationForest.score_samples → values near 0 = normal,
        more negative = anomalous.  We map with a tuned sigmoid.
        OneClassSVM.decision_function → positive = inlier (safe),
        negative = outlier (malware).
        """
        n = len(X)

        if self.iso is not None:
            iso_s = self.iso.score_samples(X)          # shape (n,)
            # Typical range: [-1, 0].  Shift+scale so 0 = normal, 1 = anomaly
            mal_iso = 1.0 / (1.0 + np.exp(10.0 * iso_s + 5.0))
        else:
            mal_iso = np.full(n, 0.5)

        if self.ocsvm is not None:
            ocsvm_s = self.ocsvm.decision_function(X)  # pos = safe, neg = malware
            mal_ocsvm = 1.0 / (1.0 + np.exp(ocsvm_s))
        else:
            mal_ocsvm = np.full(n, 0.5)

        mal_prob  = (mal_iso + mal_ocsvm) / 2.0
        safe_prob = 1.0 - mal_prob
        return np.column_stack([safe_prob, mal_prob])

    def decision_function(self, X):
        """
        Returns per-sample anomaly scores (used as fallback).
        Returns raw IsolationForest offset score (not normalised).
        """
        if self.iso is not None:
            return -self.iso.score_samples(X)   # higher = more anomalous
        if self.ocsvm is not None:
            return -self.ocsvm.decision_function(X)
        return np.zeros(len(X))

    # ── sklearn compatibility ────────────────────────────────────
    def fit(self, X, y=None):
        return self

    def get_params(self, deep=True):
        return {'iso': self.iso, 'ocsvm': self.ocsvm}

    def set_params(self, **params):
        for k, v in params.items():
            setattr(self, k, v)
        return self
