import hashlib
import math
import os
import time

import numpy as np
import pandas as pd
import requests

from feature_extractor import extract_features
from model_loader import get_model, get_scaler, get_features

# MetaDefender-class cloud scan via Filescan.io (https://www.filescan.io)
_FILESCAN_KEY = os.getenv('FILESCAN_API_KEY', '') or os.getenv('METADEFENDER_API_KEY', '')
_FILESCAN_BASE = os.getenv('FILESCAN_BASE_URL', 'https://www.filescan.io').rstrip('/')
_FILESCAN_UPLOAD_MAX = 50 * 1024 * 1024  # match app upload cap
_FILESCAN_POLL_TIMEOUT = 90
_FILESCAN_POLL_INTERVAL = 2

# Filescan.io API — same filter list as official CLI (filescanio/fsio-cli)
_FILESCAN_REPORT_FILTERS = [
    'general', 'allSignalGroups', 'allTags', 'overallState',
    'positionInQueue', 'taskReference', 'subtaskReferences',
    'finalVerdict', 'fd:fileDownloadResults', 'fd:extractedUrls',
    'dr:domainResolveResults', 'v:visualizedSample.compressedBase64',
    'v:renderedImages', 'wi:whoisLookupResults', 'f:all', 'o:all',
]
_FILESCAN_REPORT_SORTS = [
    'allSignalGroups(description:asc,allMitreTechniques:desc,averageSignalStrength:desc)',
    'allOsintTags(tag.name:asc)',
    'f:disassemblySections(levelOfInformation:desc)',
    'f:extendedData.importsEx(module.suspicious:desc)',
]

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

# File types that are inherently safe — skip ML entirely.
# These are non-executable formats where high entropy is NORMAL
# (e.g. JPEG uses DCT compression → entropy ~7.5-7.9).
ALWAYS_SAFE_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg', '.ico', '.tiff',
    '.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a', '.wma',
    '.mp4', '.mkv', '.avi', '.mov', '.webm', '.flv', '.wmv',
    '.txt', '.csv', '.json', '.xml', '.yaml', '.yml', '.md', '.rst', '.log',
    '.ttf', '.otf', '.woff', '.woff2',
    '.html', '.htm', '.css',
}

ENTROPY_SAFE_THRESHOLD = 7.5

# In-memory scan cache: SHA-256 → result dict
# Ensures identical files always get the same scan result
_scan_cache = {}


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


def _filescan_report_query_params() -> list[tuple[str, str]]:
    """Build query string for GET /api/scan/{id}/report (multi-value filter/sort)."""
    params: list[tuple[str, str]] = []
    for f in _FILESCAN_REPORT_FILTERS:
        params.append(('filter', f))
    for s in _FILESCAN_REPORT_SORTS:
        params.append(('sort', s))
    return params


def _filescan_verdict_from_report(rep: dict) -> dict | None:
    """Map a single Filescan report object to prediction + confidence."""
    if rep.get('overallState') != 'success':
        return None
    verdict_raw = rep.get('verdict')
    if verdict_raw is None and isinstance(rep.get('finalVerdict'), dict):
        verdict_raw = rep['finalVerdict'].get('verdict', '')
    v = str(verdict_raw).lower().strip()
    if v in ('malicious', 'likely_malicious'):
        return {'prediction': 'MALWARE', 'confidence': 0.92}
    if v == 'suspicious':
        return {'prediction': 'MALWARE', 'confidence': 0.78}
    if v == 'unknown':
        return {'prediction': 'SAFE', 'confidence': 0.62}
    if v in ('', 'clean', 'safe', 'benign', 'no_threats', 'not_malicious'):
        return {'prediction': 'SAFE', 'confidence': 0.88}
    return {'prediction': 'SAFE', 'confidence': 0.75}


def _filescan_aggregate_scan_reports(scan_report: dict) -> dict | None:
    """Combine per-file reports; any MALWARE wins."""
    reports = scan_report.get('reports') or {}
    if not reports:
        return None
    if not scan_report.get('allFinished'):
        return None
    merged: dict | None = None
    for rep in reports.values():
        one = _filescan_verdict_from_report(rep)
        if one is None:
            continue
        if merged is None:
            merged = one
            continue
        if one['prediction'] == 'MALWARE' or merged['prediction'] == 'MALWARE':
            merged = {
                'prediction': 'MALWARE',
                'confidence': round(max(merged['confidence'], one['confidence']), 4),
            }
        else:
            merged = {
                'prediction': 'SAFE',
                'confidence': round(min(merged['confidence'], one['confidence']), 4),
            }
    return merged


# ═══════════════════════════════════════════════════════════════════════════════
#  Cloud: Filescan.io (MetaDefender-class) — upload + poll
# ═══════════════════════════════════════════════════════════════════════════════

def _filescan_upload_scan(filepath: str, filename: str) -> dict | None:
    if not _FILESCAN_KEY:
        return None
    try:
        size = os.path.getsize(filepath)
        if size > _FILESCAN_UPLOAD_MAX:
            print(f"[Filescan] File too large ({size} bytes), skipping")
            return None

        url = f'{_FILESCAN_BASE}/api/scan/file'
        headers = {
            'X-Api-Key': _FILESCAN_KEY,
            'accept': 'application/json',
            'User-Agent': 'SecureShare/1.0',
        }
        print(f"[Filescan] Uploading {filename!r} ({size} bytes)...")
        with open(filepath, 'rb') as fh:
            resp = requests.post(
                url,
                headers=headers,
                files={'file': (filename, fh, 'application/octet-stream')},
                timeout=120,
            )
        if resp.status_code not in (200, 201):
            detail = resp.text[:500]
            print(f"[Filescan] Upload failed HTTP {resp.status_code}: {detail}")
            return None

        body = resp.json()
        flow_id = body.get('flow_id') or body.get('flowId')
        if not flow_id:
            print(f"[Filescan] No flow_id in response: {body!r}")
            return None

        report_url = f'{_FILESCAN_BASE}/api/scan/{flow_id}/report'
        params = _filescan_report_query_params()
        deadline = time.time() + _FILESCAN_POLL_TIMEOUT

        while time.time() < deadline:
            time.sleep(_FILESCAN_POLL_INTERVAL)
            poll = requests.get(
                report_url,
                headers=headers,
                params=params,
                timeout=60,
            )
            if poll.status_code != 200:
                print(f"[Filescan] Poll HTTP {poll.status_code}")
                continue

            scan_report = poll.json()
            if scan_report.get('allFinished'):
                result = _filescan_aggregate_scan_reports(scan_report)
                if result:
                    print(f"[Filescan] Scan complete -> {result['prediction']}")
                    return result
                print('[Filescan] Scan finished but verdict not available, falling back')
                return None

        print('[Filescan] Poll timed out, falling back')
        return None

    except Exception as exc:
        print(f"[Filescan] Error: {exc}")
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Local: Heuristic + ML fallback
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
        if features.get('F9', 0) > 0.85:
            score += 1
        if score >= 4:
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
        if features.get('EmbeddedFile', 0) > 0:
            score += 1
        if score >= 4:
            prediction = 'MALWARE'
            confidence = min(0.5 + score * 0.07, 0.92)

    elif file_type in ('doc', 'docx'):
        # Require macro + autoexec + at least one suspicious indicator
        has_sus = (
            features.get('powershell_usage', 0)
            or features.get('shell_commands', 0)
            or features.get('external_connections', 0)
            or features.get('downloadfile_calls', 0)
            or features.get('createobject_calls', 0)
            or features.get('obfuscation_score', 0) > 5
        )
        if features.get('macro_present', 0) and features.get('autoexec_macro', 0) and has_sus:
            prediction = 'MALWARE'
            confidence = 0.82
        elif features.get('powershell_usage', 0) and features.get('macro_present', 0):
            prediction = 'MALWARE'
            confidence = 0.78

    else:
        if entropy > 7.95:
            prediction = 'MALWARE'
            confidence = 0.60

    return prediction, round(confidence, 4)


# ═══════════════════════════════════════════════════════════════════════════════
#  Main scan entry point: safe-list / cache / MetaDefender (Filescan) / local ML
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

        # ── Tier 0: inherently safe file types ────────────────────────────────
        ext = os.path.splitext(filename)[1].lower()
        if ext in ALWAYS_SAFE_EXTENSIONS:
            result['prediction'] = 'SAFE'
            result['confidence'] = 0.99
            print(f"[Scanner] '{filename}' -> Always-safe extension ({ext}) -> SAFE")
            return result

        # ── Hash-based cache lookup ───────────────────────────────────────────
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        if file_hash in _scan_cache:
            cached = _scan_cache[file_hash]
            result['prediction'] = cached['prediction']
            result['confidence'] = cached['confidence']
            print(f"[Scanner] '{filename}' -> Cache hit (hash={file_hash[:12]}) -> {cached['prediction']}")
            return result

        # ── Tier 1: MetaDefender (Filescan.io cloud) ───────────────────────────
        if _FILESCAN_KEY:
            fs = _filescan_upload_scan(filepath, filename)
            if fs:
                result['prediction'] = fs['prediction']
                result['confidence'] = fs['confidence']
                print(f"[Scanner] '{filename}' -> Tier 1 (MetaDefender/Filescan) -> {fs['prediction']}")
                _scan_cache[file_hash] = {
                    'prediction': fs['prediction'],
                    'confidence': fs['confidence'],
                }
                return result

        # ── Tier 2: local heuristic + ML fallback ─────────────────────────────
        print(f"[Scanner] '{filename}' -> Tier 2 (local scan)")

        # Low-risk file types with normal entropy are almost certainly safe
        if _is_low_risk(filename) and file_type == 'generic':
            entropy = _get_file_entropy(filepath)
            if entropy < ENTROPY_SAFE_THRESHOLD:
                result['prediction'] = 'SAFE'
                result['confidence'] = round(max(0.85, 1.0 - entropy / 10.0), 4)
                print(f"[Scanner] '{filename}' -> Low-risk ext, entropy={entropy:.2f} -> SAFE")
                return result
            print(f"[Scanner] '{filename}' -> Low-risk ext but high entropy={entropy:.2f}, running ML")

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

        # Require minimum confidence per file type before flagging as malware
        MALWARE_CONFIDENCE_THRESHOLDS = {
            'exe':     0.75,
            'pdf':     0.72,
            'doc':     0.72,
            'docx':    0.72,
            'generic': 0.88,
        }
        min_conf = MALWARE_CONFIDENCE_THRESHOLDS.get(file_type, 0.88)
        if prediction == 'MALWARE' and confidence < min_conf:
            print(f"[Scanner] '{filename}' -> ML said MALWARE but confidence ({confidence:.4f}) < threshold ({min_conf}), overriding to SAFE")
            prediction = 'SAFE'
            confidence = max(0.6, 1.0 - confidence)

        result['prediction'] = prediction
        result['confidence'] = round(confidence, 4)
        _scan_cache[file_hash] = {'prediction': prediction, 'confidence': round(confidence, 4)}
        print(f"[Scanner] '{filename}' -> Tier 2 ML -> {prediction} ({confidence:.2%})")

    except Exception as exc:
        result['error']      = str(exc)
        result['prediction'] = 'SAFE'
        result['confidence'] = 0.5
        print(f"[Scanner] Error scanning '{filename}': {exc}")

    return result
