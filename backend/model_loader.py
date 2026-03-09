"""
model_loader.py
───────────────
Loads all ML artifacts (models, scalers, feature lists) at startup.

Special handling:
  generic_model.pkl  – uses EnsembleAnomalyDetector saved from __main__;
                       a custom Unpickler re-maps it to model_classes.py.
"""

import os
import sys
import pickle
import joblib
import warnings

# Suppress sklearn version mismatch warnings (models were trained on 1.6.1)
warnings.filterwarnings('ignore', category=UserWarning)

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR   = os.path.join(BASE_DIR, 'models')
SCALERS_DIR  = os.path.join(BASE_DIR, 'scalers')
FEATURES_DIR = os.path.join(BASE_DIR, 'features')

_models   = {}
_scalers  = {}
_features = {}
_loaded   = False

_MODEL_FILES = {
    'exe':     'exe_model.pkl',
    'pdf':     'pdf_model.pkl',
    'doc':     'doc_model.pkl',
    'docx':    'doc_model.pkl',
    'generic': 'generic_model.pkl',
}
_SCALER_FILES = {
    'exe':     'scaler_exe.pkl',
    'pdf':     'scaler_pdf.pkl',
    'doc':     'scaler_docx.pkl',
    'docx':    'scaler_docx.pkl',
    'generic': 'scaler_generic.pkl',
}
_FEATURE_FILES = {
    'exe':     'exe_features.pkl',
    'pdf':     'pdf_features.pkl',
    'doc':     'docx_features.pkl',
    'docx':    'docx_features.pkl',
    'generic': 'gen_features.pkl',
}


# ── Custom unpickler ─────────────────────────────────────────────────────────

class _CustomUnpickler(pickle.Unpickler):
    """Re-maps __main__.EnsembleAnomalyDetector to model_classes module."""

    def find_class(self, module, name):
        if name == 'EnsembleAnomalyDetector':
            from model_classes import EnsembleAnomalyDetector
            return EnsembleAnomalyDetector
        return super().find_class(module, name)


def _load_generic_model(path: str):
    """Load generic_model.pkl with the custom unpickler via joblib."""
    # joblib uses pickle internally; we need to patch __main__ so joblib
    # can resolve the class, then restore it afterwards.
    import model_classes
    sentinel = object()
    old = getattr(sys.modules.get('__main__'), 'EnsembleAnomalyDetector', sentinel)
    sys.modules['__main__'].EnsembleAnomalyDetector = model_classes.EnsembleAnomalyDetector
    try:
        model = joblib.load(path)
    finally:
        if old is sentinel:
            try:
                delattr(sys.modules['__main__'], 'EnsembleAnomalyDetector')
            except AttributeError:
                pass
        else:
            sys.modules['__main__'].EnsembleAnomalyDetector = old
    return model


# ── Public load function ─────────────────────────────────────────────────────

def load_all():
    global _models, _scalers, _features, _loaded

    # ── Models ─────────────────────────────────────────────────────
    loaded_model_files = set()  # avoid loading same file twice
    for ftype, fname in _MODEL_FILES.items():
        if fname in loaded_model_files:
            # Re-use already loaded model (e.g. doc/docx share doc_model.pkl)
            src = next(k for k, v in _MODEL_FILES.items() if v == fname and k in _models)
            _models[ftype] = _models[src]
            continue

        path = os.path.join(MODELS_DIR, fname)
        if not os.path.exists(path):
            print(f'[ModelLoader] Missing model : {path}')
            continue

        try:
            if fname == 'generic_model.pkl':
                model = _load_generic_model(path)
            else:
                model = joblib.load(path)
            _models[ftype] = model
            loaded_model_files.add(fname)
            print(f'[ModelLoader] Loaded model  : {ftype:8s} <- {fname}  ({type(model).__name__})')
        except Exception as exc:
            print(f'[ModelLoader] Failed model  : {ftype} — {exc}')

    # ── Scalers ────────────────────────────────────────────────────
    loaded_scaler_files = set()
    for ftype, fname in _SCALER_FILES.items():
        if fname in loaded_scaler_files:
            src = next(k for k, v in _SCALER_FILES.items() if v == fname and k in _scalers)
            _scalers[ftype] = _scalers[src]
            continue
        path = os.path.join(SCALERS_DIR, fname)
        if not os.path.exists(path):
            continue
        try:
            _scalers[ftype] = joblib.load(path)
            loaded_scaler_files.add(fname)
            print(f'[ModelLoader] Loaded scaler : {ftype:8s} <- {fname}')
        except Exception as exc:
            print(f'[ModelLoader] Failed scaler : {ftype} — {exc}')

    # ── Feature lists ──────────────────────────────────────────────
    loaded_feat_files = set()
    for ftype, fname in _FEATURE_FILES.items():
        if fname in loaded_feat_files:
            src = next(k for k, v in _FEATURE_FILES.items() if v == fname and k in _features)
            _features[ftype] = _features[src]
            continue
        path = os.path.join(FEATURES_DIR, fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path, 'rb') as fh:
                _features[ftype] = pickle.load(fh)
            loaded_feat_files.add(fname)
            print(f'[ModelLoader] Loaded feats  : {ftype:8s} <- {fname}  ({len(_features[ftype])} features)')
        except Exception as exc:
            print(f'[ModelLoader] Failed feats  : {ftype} — {exc}')

    _loaded = True
    print(f'[ModelLoader] Ready — {len(_models)} models loaded')


# ── Accessors ────────────────────────────────────────────────────────────────

def _ensure_loaded():
    if not _loaded:
        load_all()


def get_model(file_type: str):
    _ensure_loaded()
    return _models.get(file_type) or _models.get('generic')


def get_scaler(file_type: str):
    _ensure_loaded()
    return _scalers.get(file_type) or _scalers.get('generic')


def get_features(file_type: str):
    _ensure_loaded()
    return _features.get(file_type) or _features.get('generic')


def models_available() -> bool:
    _ensure_loaded()
    return bool(_models)
