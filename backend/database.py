from datetime import datetime
from typing import Any, Dict, List, Optional

from firebase_admin import firestore

from firebase_service import get_db as _firebase_get_db


def get_db():
    return _firebase_get_db()


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


def _doc_to_dict(doc) -> Dict[str, Any]:
    data = doc.to_dict() or {}
    if 'id' not in data:
        data['id'] = doc.id
    return data


def init_db():
    # Firestore is schema-less; this verifies connectivity.
    get_db().collection('_health').document('init').set({'ts': _now_iso()}, merge=True)


def add_file(filename, original_filename, file_hash, file_type, file_size, filepath, owner_uid=None):
    db = get_db()
    payload = {
        'filename': filename,
        'original_filename': original_filename,
        'upload_time': _now_iso(),
        'file_hash': file_hash,
        'file_type': file_type,
        'file_size': file_size,
        'scan_result': None,
        'confidence': None,
        'filepath': filepath,
        'owner_uid': owner_uid,
    }
    ref = db.collection('files').document()
    payload['id'] = ref.id
    ref.set(payload)
    return ref.id


def get_scan_result_by_hash(file_hash):
    """Look up if a file with this hash was previously scanned as SAFE."""
    try:
        docs = (get_db().collection('files')
                .where('file_hash', '==', file_hash)
                .where('scan_result', '==', 'SAFE')
                .limit(1)
                .stream())
        for doc in docs:
            data = doc.to_dict()
            return {
                'prediction': data.get('scan_result', 'SAFE'),
                'confidence': data.get('confidence', 0.95),
                'type': data.get('file_type', 'generic'),
                'cached': True,
            }
    except Exception:
        pass
    return None


def update_scan_result(file_id, scan_result, confidence):
    get_db().collection('files').document(str(file_id)).set(
        {'scan_result': scan_result, 'confidence': confidence},
        merge=True,
    )


def update_file_path(file_id, filepath):
    get_db().collection('files').document(str(file_id)).set({'filepath': filepath}, merge=True)


def get_file(file_id):
    doc = get_db().collection('files').document(str(file_id)).get()
    return _doc_to_dict(doc) if doc.exists else None


def get_all_files(owner_uid: Optional[str] = None) -> List[Dict[str, Any]]:
    db = get_db()
    query = db.collection('files')
    if owner_uid:
        query = query.where(filter=firestore.FieldFilter('owner_uid', '==', owner_uid))
    docs = query.stream()
    rows = [_doc_to_dict(d) for d in docs]
    rows.sort(key=lambda x: x.get('upload_time', ''), reverse=True)
    return rows


def delete_file(file_id: str, owner_uid: str) -> bool:
    """Delete a file document and its associated share_link. Returns True if deleted."""
    db = get_db()
    doc_ref = db.collection('files').document(str(file_id))
    doc = doc_ref.get()
    if not doc.exists:
        return False
    data = _doc_to_dict(doc)
    if data.get('owner_uid') != owner_uid:
        return False

    # Delete associated share_links
    share_docs = db.collection('share_links').where(
        filter=firestore.FieldFilter('file_id', '==', str(file_id))
    ).stream()
    for sd in share_docs:
        sd.reference.delete()

    doc_ref.delete()
    return True


def add_share_link(file_id, share_code, qr_path, expires_at=None, password_hash: Optional[str] = None):
    payload = {
        'file_id': str(file_id),
        'share_code': share_code,
        'qr_path': qr_path,
        'created_at': _now_iso(),
        'expires_at': expires_at.isoformat() if hasattr(expires_at, 'isoformat') else expires_at,
        'download_count': 0,
        'password_hash': password_hash,
    }
    get_db().collection('share_links').document(str(share_code)).set(payload)


def get_share_link(share_code):
    db = get_db()
    link_doc = db.collection('share_links').document(str(share_code)).get()
    if not link_doc.exists:
        return None

    link = _doc_to_dict(link_doc)
    file_doc = db.collection('files').document(str(link.get('file_id'))).get()
    if not file_doc.exists:
        return link

    f = _doc_to_dict(file_doc)
    link.update({
        'filename': f.get('filename'),
        'original_filename': f.get('original_filename'),
        'filepath': f.get('filepath'),
        'scan_result': f.get('scan_result'),
        'file_type': f.get('file_type'),
        'file_size': f.get('file_size'),
        'confidence': f.get('confidence'),
        'upload_time': f.get('upload_time'),
        'owner_uid': f.get('owner_uid'),
    })
    return link


def increment_download_count(share_code):
    get_db().collection('share_links').document(str(share_code)).set(
        {'download_count': firestore.Increment(1)},
        merge=True,
    )


def get_dashboard_stats(owner_uid: Optional[str] = None):
    files = get_all_files(owner_uid=owner_uid)
    total = len(files)
    malware = len([f for f in files if f.get('scan_result') == 'MALWARE'])
    safe = len([f for f in files if f.get('scan_result') == 'SAFE'])

    db = get_db()
    share_docs = db.collection('share_links').stream()
    share_by_file = {}
    for doc in share_docs:
        s = _doc_to_dict(doc)
        share_by_file[s.get('file_id')] = s

    recent = []
    for f in files[:10]:
        sl = share_by_file.get(str(f.get('id'))) or {}
        recent.append({
            'id': f.get('id'),
            'original_filename': f.get('original_filename'),
            'file_type': f.get('file_type'),
            'scan_result': f.get('scan_result'),
            'confidence': f.get('confidence'),
            'upload_time': f.get('upload_time'),
            'file_size': f.get('file_size'),
            'share_code': sl.get('share_code'),
            'download_count': sl.get('download_count', 0),
            'expires_at': sl.get('expires_at'),
            'password_protected': bool(sl.get('password_hash')),
        })

    return {
        'total_scanned': total,
        'malware_blocked': malware,
        'safe_shared': safe,
        'recent_uploads': recent,
    }


def get_storage_stats(owner_uid: Optional[str] = None) -> Dict[str, Any]:
    """Return total file count and bytes used for the given owner."""
    files = get_all_files(owner_uid=owner_uid)
    total_bytes = sum(f.get('file_size', 0) or 0 for f in files)
    return {
        'file_count': len(files),
        'total_bytes': total_bytes,
    }
