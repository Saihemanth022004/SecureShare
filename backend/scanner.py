import hashlib
import math
import os
import time

import numpy as np
import pandas as pd
import requests

from feature_extractor import extract_features
from model_loader import get_model, get_scaler, get_features

_THREAT_KEY = os.getenv('THREAT_API_KEY', '')
_VT_BASE = 'https://www.virustotal.com/api/v3'
_VT_UPLOAD_MAX = 32 * 1024 * 1024  # 32 MB
_VT_POLL_TIMEOUT = 60              # seconds to wait for scan results
_VT_POLL_INTERVAL = 10             # seconds between polls

# File-extension → logical type
EXT_MAP = {
    '.exe':  'exe',
    '.dll':  'exe',
    '.sys':  'exe',
    '.pdf':  'pdf',
    '.doc':  'doc',
    '.docx': 'docx',
    '.docm': 'docx',
    '.dot':  'doc',
    '.dotm': 'docx',
    '.xls':  'doc',
    '.xlsx': 'docx',
    '.xlsm': 'docx',
    '.ppt':  'doc',
    '.pptx': 'docx',
}

LOW_RISK_EXTENSIONS = {
    '.txt', '.csv', '.json', '.xml', '.yaml', '.yml', '.toml', '.ini', '.cfg',
    '.md', '.rst', '.log', '.html', '.htm', '.css',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg', '.ico', '.tiff',
    '.mp3', '.wav', '.ogg', '.flac', '.aac',
    '.mp4', '.mkv', '.avi', '.mov', '.webm',
    '.zip', '.tar', '.gz', '.7z', '.rar',
    '.ttf', '.otf', '.woff', '.woff2',
}

ENTROPY_SAFE_THRESHOLD = 7.0


def detect_file_type(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    return EXT_MAP.get(ext, 'generic')


def _is_low_risk(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in LOW_RISK_EXTENSIONS


def _get_file_entropy(filepath: str) -> float:
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        return -sum(
            (c / length) * math.log2(c / length)
            for c in freq if c > 0
        )
    except Exception:
        return 0.0


def _map_prediction(raw) -> str:
    if isinstance(raw, (int, float, np.integer, np.floating)):
        v = int(raw)
        if v == -1:
            return 'MALWARE'
        return 'MALWARE' if v == 1 else 'SAFE'
    val = str(raw).strip().lower()
    if val in ('1', 'malware', 'malicious', 'threat'):
        return 'MALWARE'
    return 'SAFE'


def _parse_vt_stats(stats: dict) -> dict | None:
    """Convert VirusTotal analysis_stats into a prediction + confidence."""
    if not stats:
        return None
    malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
    total = sum(stats.values()) or 1
    if malicious >= 3:
        return {
            'prediction': 'MALWARE',
            'confidence': round(min(0.5 + malicious / total, 0.99), 4),
        }
    return {
        'prediction': 'SAFE',
        'confidence': round(max(1.0 - malicious / total, 0.75), 4),
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Tier 1: Hash Lookup (instant, no upload)
# ═══════════════════════════════════════════════════════════════════════════════

def _vt_hash_lookup(filepath: str) -> dict | None:
    if not _THREAT_KEY:
        return None
    try:
        with open(filepath, 'rb') as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        print(f"[VT] Hash lookup: {sha[:16]}...")
        resp = requests.get(
            f'{_VT_BASE}/files/{sha}',
            headers={'x-apikey': _THREAT_KEY},
            timeout=15,
        )
        if resp.status_code != 200:
            print(f"[VT] Hash not found (status {resp.status_code})")
            return None
        stats = (resp.json()
                 .get('data', {})
                 .get('attributes', {})
                 .get('last_analysis_stats', {}))
        result = _parse_vt_stats(stats)
        if result:
            print(f"[VT] Hash lookup → {result['prediction']}")
        return result
    except Exception as exc:
        print(f"[VT] Hash lookup error: {exc}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Tier 2: Upload file for full scan (70+ engines)
# ═══════════════════════════════════════════════════════════════════════════════

def _vt_upload_scan(filepath: str) -> dict | None:
    if not _THREAT_KEY:
        return None
    try:
        file_size = os.path.getsize(filepath)
        if file_size > _VT_UPLOAD_MAX:
            print(f"[VT] File too large for upload ({file_size} bytes), skipping")
            return None

        print(f"[VT] Uploading file for scan ({file_size} bytes)...")
        with open(filepath, 'rb') as f:
            resp = requests.post(
                f'{_VT_BASE}/files',
                headers={'x-apikey': _THREAT_KEY},
                files={'file': ('scan_file', f)},
                timeout=30,
            )

        if resp.status_code not in (200, 201):
            print(f"[VT] Upload failed (status {resp.status_code})")
            return None

        analysis_id = (resp.json()
                       .get('data', {})
                       .get('id', ''))
        if not analysis_id:
            print("[VT] No analysis ID returned")
            return None

        print(f"[VT] Upload OK, polling analysis {analysis_id[:20]}...")

        deadline = time.time() + _VT_POLL_TIMEOUT
        while time.time() < deadline:
            time.sleep(_VT_POLL_INTERVAL)
            poll = requests.get(
                f'{_VT_BASE}/analyses/{analysis_id}',
                headers={'x-apikey': _THREAT_KEY},
                timeout=15,
            )
            if poll.status_code != 200:
                continue

            attrs = poll.json().get('data', {}).get('attributes', {})
            status = attrs.get('status', '')

            if status == 'completed':
                stats = attrs.get('stats', {})
                result = _parse_vt_stats(stats)
                if result:
                    print(f"[VT] Scan complete → {result['prediction']}")
                return result

            print(f"[VT] Still scanning (status={status})...")

        print("[VT] Scan timed out, falling back")
        return None

    except Exception as exc:
        print(f"[VT] Upload scan error: {exc}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Tier 3: Heuristic + ML fallback
# ═══════════════════════════════════════════════════════════════════════════════

def _heuristic_scan(file_type: str, features: dict) -> tuple:
    """Rule-based fallback when no trained model is available."""
    prediction = 'SAFE'
    confidence = 0.55

    entropy = (
        features.get('entropy', 0)
        or features.get('entropy_score', 0)
        or features.get('F9', 0) * 8.0
    )

    if file_type == 'exe':
        score = 0
        if entropy > 7.2:
            score += 2
        if features.get('F5', 0) > 0.5:
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


# ═══════════════════════════════════════════════════════════════════════════════
#  Main scan entry point — 3-tier pipeline
# ═══════════════════════════════════════════════════════════════════════════════

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

        # ── Tier 1: instant hash lookup ───────────────────────────────────────
        vt = _vt_hash_lookup(filepath)
        if vt:
            result['prediction'] = vt['prediction']
            result['confidence'] = vt['confidence']
            print(f"[Scanner] '{filename}' → Tier 1 (hash) → {vt['prediction']}")
            return result

        # ── Tier 2: upload file for full VirusTotal scan ──────────────────────
        vt = _vt_upload_scan(filepath)
        if vt:
            result['prediction'] = vt['prediction']
            result['confidence'] = vt['confidence']
            print(f"[Scanner] '{filename}' → Tier 2 (upload) → {vt['prediction']}")
            return result

        # ── Tier 3: local heuristic + ML fallback ─────────────────────────────
        print(f"[Scanner] '{filename}' → Tier 3 (local scan)")

        # Low-risk file types with normal entropy are almost certainly safe
        if _is_low_risk(filename) and file_type == 'generic':
            entropy = _get_file_entropy(filepath)
            if entropy < ENTROPY_SAFE_THRESHOLD:
                result['prediction'] = 'SAFE'
                result['confidence'] = round(max(0.85, 1.0 - entropy / 10.0), 4)
                print(f"[Scanner] '{filename}' → Low-risk ext, entropy={entropy:.2f} → SAFE")
                return result
            print(f"[Scanner] '{filename}' → Low-risk ext but high entropy={entropy:.2f}, running ML")

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

        # Generic files: require high ML confidence to flag as malware
        if file_type == 'generic' and prediction == 'MALWARE' and confidence < 0.85:
            print(f"[Scanner] '{filename}' → ML said MALWARE but low confidence ({confidence:.4f}), overriding to SAFE")
            prediction = 'SAFE'
            confidence = max(0.6, 1.0 - confidence)

        result['prediction'] = prediction
        result['confidence'] = round(confidence, 4)
        print(f"[Scanner] '{filename}' → Tier 3 ML → {prediction} ({confidence:.2%})")

    except Exception as exc:
        result['error']      = str(exc)
        result['prediction'] = 'SAFE'
        result['confidence'] = 0.5
        print(f"[Scanner] Error scanning '{filename}': {exc}")

    return result
