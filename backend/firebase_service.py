import json
import os
from typing import Any, Dict, Optional

import firebase_admin
from firebase_admin import auth, credentials, firestore, storage


_APP = None


def _load_credentials():
    service_path = os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH')
    if service_path:
        return credentials.Certificate(service_path)

    project_id = os.getenv('FIREBASE_PROJECT_ID')
    private_key = os.getenv('FIREBASE_PRIVATE_KEY')
    client_email = os.getenv('FIREBASE_CLIENT_EMAIL')

    if project_id and private_key and client_email:
        info = {
            'type': 'service_account',
            'project_id': project_id,
            'private_key_id': os.getenv('FIREBASE_PRIVATE_KEY_ID'),
            'private_key': private_key.replace('\\n', '\n'),
            'client_email': client_email,
            'client_id': os.getenv('FIREBASE_CLIENT_ID'),
            'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
            'token_uri': 'https://oauth2.googleapis.com/token',
            'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
            'client_x509_cert_url': os.getenv('FIREBASE_CLIENT_CERT_URL'),
        }
        return credentials.Certificate(info)

    raw_json = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON')
    if raw_json:
        info = json.loads(raw_json)
        if 'private_key' in info:
            info['private_key'] = info['private_key'].replace('\\n', '\n')
        return credentials.Certificate(info)

    raise RuntimeError(
        'Firebase credentials not found. Set FIREBASE_SERVICE_ACCOUNT_PATH '
        'or FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_* service account env vars.'
    )


def init_firebase():
    global _APP
    if _APP is not None:
        return _APP

    cred = _load_credentials()
    bucket_name = os.getenv('FIREBASE_STORAGE_BUCKET')
    options: Dict[str, Any] = {}
    if bucket_name:
        options['storageBucket'] = bucket_name

    _APP = firebase_admin.initialize_app(cred, options=options)
    return _APP


def get_db():
    init_firebase()
    return firestore.client()


def get_bucket():
    init_firebase()
    return storage.bucket()


def verify_id_token(id_token: str) -> Dict[str, Any]:
    init_firebase()
    return auth.verify_id_token(id_token)


def upload_bytes(storage_path: str, data: bytes, content_type: Optional[str] = None):
    blob = get_bucket().blob(storage_path)
    blob.upload_from_string(data, content_type=content_type)


def download_bytes(storage_path: str) -> bytes:
    blob = get_bucket().blob(storage_path)
    if not blob.exists():
        raise FileNotFoundError(storage_path)
    return blob.download_as_bytes()


def delete_blob(storage_path: str):
    blob = get_bucket().blob(storage_path)
    blob.delete()

