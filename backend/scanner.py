import hashlib
import os

import numpy as np
import pandas as pd
import requests

from feature_extractor import extract_features
from model_loader import get_model, get_scaler, get_features

_THREAT_KEY = os.getenv('THREAT_API_KEY', '')

# File-extension → logical type
EXT_MAP = {
    '.exe':  'exe',
    '.dll':  'exe',
    '.sys':  'exe',
    '.pdf':  'pdf',
    '.doc':  'doc',
    '.docx': 'docx',
    '.docm': 'docx',   # macro-enabled DOCX -> docx model
    '.dot':  'doc',
    '.dotm': 'docx',
    '.xls':  'doc',    # reuse doc/VotingClassifier for Office files
    '.xlsx': 'docx',
    '.xlsm': 'docx',
    '.ppt':  'doc',
    '.pptx': 'docx',
}


def detect_file_type(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    return EXT_MAP.get(ext, 'generic')


def _map_prediction(raw) -> str:
    """
    Normalise any model output to 'SAFE' or 'MALWARE'.
    Classifiers  : 0 = SAFE, 1 = MALWARE
    Anomaly mdls : -1 = outlier (MALWARE), +1 = inlier (SAFE)
    EnsembleAnomalyDetector.predict() already returns 0/1.
    """
    if isinstance(raw, (int, float, np.integer, np.floating)):
        v = int(raw)
        if v == -1:
            return 'MALWARE'     # raw IsolationForest / OneClassSVM output
        return 'MALWARE' if v == 1 else 'SAFE'
    val = str(raw).strip().lower()
    if val in ('1', 'malware', 'malicious', 'threat'):
        return 'MALWARE'
    return 'SAFE'


def _heuristic_scan(file_type: str, features: dict) -> tuple:
    """Rule-based fallback when no trained model is available."""
    prediction = 'SAFE'
    confidence = 0.55

    # EXE: use generic entropy feature (F9 in EMBER layout ≈ overall entropy)
    entropy = (
        features.get('entropy', 0)
        or features.get('entropy_score', 0)
        or features.get('F9', 0) * 8.0     # F9 normalised
    )

    if file_type == 'exe':
        score = 0
        if entropy > 7.2:
            score += 2
        if features.get('F5', 0) > 0.5:   # suspicious_api proxy via entropy histogram
            score += 1
        if score >= 3:
            prediction = 'MALWARE'
            confidence = min(0.5 + score * 0.07, 0.92)

    elif file_type == 'pdf':
        score = 0
        if features.get('JS', 0) > 0 or features.get('Javascript', 0) > 0:
            score += 2
        if features.get('Launch', 0) > 0:
            score += 2
        if features.get('OpenAction', 0) > 0 and (features.get('JS', 0) > 0 or features.get('Javascript', 0) > 0):
            score += 2
        if score >= 3:
            prediction = 'MALWARE'
            confidence = min(0.5 + score * 0.07, 0.92)

    elif file_type in ('doc', 'docx'):
        if features.get('macro_present', 0) and features.get('autoexec_macro', 0):
            prediction = 'MALWARE'
            confidence = 0.82
        elif features.get('powershell_usage', 0):
            prediction = 'MALWARE'
            confidence = 0.78

    else:
        if entropy > 7.8:
            prediction = 'MALWARE'
            confidence = 0.65

    return prediction, round(confidence, 4)


def _check_threat_db(filepath: str) -> dict | None:
    """Hash-based lookup against external threat intelligence."""
    if not _THREAT_KEY:
        return None
    try:
        with open(filepath, 'rb') as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        resp = requests.get(
            f'https://www.virustotal.com/api/v3/files/{sha}',
            headers={'x-apikey': _THREAT_KEY},
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
        total = sum(stats.values()) or 1
        if malicious >= 3:
            return {'prediction': 'MALWARE', 'confidence': round(min(0.5 + malicious / total, 0.99), 4)}
        return {'prediction': 'SAFE', 'confidence': round(max(1.0 - malicious / total, 0.75), 4)}
    except Exception:
        return None


def scan_file(filepath: str, filename: str) -> dict:
    result = {
        'filename': filename,
        'type': 'unknown',
        'prediction': 'SAFE',
        'confidence': 0.5,
        'features': {},
        'error': None,
    }

    try:
        file_type = detect_file_type(filename)
        result['type'] = file_type

        # ── Primary: hash-based threat lookup ────────────────────────────────
        api = _check_threat_db(filepath)
        if api:
            result['prediction'] = api['prediction']
            result['confidence'] = api['confidence']
            return result

        # ── Fallback: ML scan ────────────────────────────────────────────────
        raw_features = extract_features(filepath, file_type)
        result['features'] = raw_features

        model        = get_model(file_type)
        scaler       = get_scaler(file_type)
        feature_list = get_features(file_type)

        if model is None:
            prediction, confidence = _heuristic_scan(file_type, raw_features)
            result['prediction']  = prediction
            result['confidence']  = confidence
            result['error']       = 'Model not available – heuristic scan used'
            return result

        df = pd.DataFrame([raw_features])
        if feature_list:
            for col in feature_list:
                if col not in df.columns:
                    df[col] = 0.0
            df = df[feature_list]

        X = scaler.transform(df) if scaler is not None else df.values

        raw_pred   = model.predict(X)[0]
        prediction = _map_prediction(raw_pred)

        confidence = 0.5
        if hasattr(model, 'predict_proba'):
            proba      = model.predict_proba(X)[0]
            confidence = float(max(proba))
        elif hasattr(model, 'decision_function'):
            score      = float(model.decision_function(X)[0])
            confidence = float(1.0 / (1.0 + np.exp(-abs(score))))

        result['prediction'] = prediction
        result['confidence'] = round(confidence, 4)

    except Exception as exc:
        result['error']      = str(exc)
        result['prediction'] = 'SAFE'
        result['confidence'] = 0.5
        print(f"[Scanner] Error scanning '{filename}': {exc}")

    return result
