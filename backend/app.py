import os
import sys
import tempfile
import uuid
from datetime import datetime
from functools import wraps
from io import BytesIO

# Load environment variables from .env file automatically
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

import bcrypt
from flask import (
    Flask,
    abort,
    jsonify,
    request,
    send_file,
    send_from_directory,
)
from flask_compress import Compress
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database
import model_loader
import scanner
import utils
from firebase_service import download_bytes, init_firebase, upload_bytes, verify_id_token



BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_FOLDER = os.path.join(BASE_DIR, 'frontend')
MAX_FILE_SIZE = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    'exe', 'dll', 'pdf', 'doc', 'docx', 'txt', 'zip', 'rar',
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',
    'xlsx', 'xls', 'csv', 'pptx', 'ppt',
    'mp3', 'mp4', 'avi', 'mkv',
    'py', 'js', 'ts', 'html', 'css', 'json', 'xml',
    '7z', 'tar', 'gz',
}

EXPIRY_OPTIONS = {
    '1h': 1,
    '24h': 24,
    '7d': 168,
    '30d': 720,
    'never': None,
}

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path='')
Compress(app)
CORS(app)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 3600

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri='memory://',
)

init_firebase()
database.init_db()
model_loader.load_all()


def allowed_file(filename: str) -> bool:
    return ('.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS)


def _require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401

        token = auth_header.split(' ', 1)[1].strip()
        if not token:
            return jsonify({'error': 'Unauthorized'}), 401

        try:
            decoded = verify_id_token(token)
            request.user = decoded
        except Exception:
            return jsonify({'error': 'Invalid auth token'}), 401
        return fn(*args, **kwargs)

    return wrapper


# ── Static pages (no-cache so browsers always get latest HTML) ────────────────
def _serve_html(filename):
    resp = send_from_directory(FRONTEND_FOLDER, filename)
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp

@app.route('/health')
def health_check():
    return 'OK', 200

@app.route('/')
def index():
    return _serve_html('index.html')

@app.route('/login')
def login_page():
    return _serve_html('login.html')

@app.route('/upload')
def upload_page():
    return _serve_html('upload.html')

@app.route('/download')
def download_page():
    return _serve_html('download.html')

@app.route('/dashboard')
def dashboard_page():
    return _serve_html('dashboard.html')

@app.route('/profile')
def profile_page():
    return _serve_html('profile.html')

@app.route('/result')
def result_page():
    return _serve_html('result.html')

@app.route('/css/<path:filename>')
def serve_css(filename):
    resp = send_from_directory(os.path.join(FRONTEND_FOLDER, 'css'), filename)
    resp.headers['Cache-Control'] = 'no-cache, must-revalidate'
    return resp

@app.route('/js/<path:filename>')
def serve_js(filename):
    resp = send_from_directory(os.path.join(FRONTEND_FOLDER, 'js'), filename)
    resp.headers['Cache-Control'] = 'no-cache, must-revalidate'
    return resp


# ── Firebase config (served to frontend) ─────────────────────────────────────
@app.route('/api/firebase-config', methods=['GET'])
def firebase_config():
    cfg = {
        'apiKey':            os.getenv('FIREBASE_WEB_API_KEY', ''),
        'authDomain':        os.getenv('FIREBASE_WEB_AUTH_DOMAIN', ''),
        'projectId':         os.getenv('FIREBASE_WEB_PROJECT_ID', ''),
        'storageBucket':     os.getenv('FIREBASE_WEB_STORAGE_BUCKET', ''),
        'messagingSenderId': os.getenv('FIREBASE_WEB_MESSAGING_SENDER_ID', ''),
        'appId':             os.getenv('FIREBASE_WEB_APP_ID', ''),
    }
    resp = jsonify(cfg)
    resp.headers['Cache-Control'] = 'public, max-age=86400'
    return resp, 200


# ── Auth ──────────────────────────────────────────────────────────────────────
@app.route('/api/auth/me', methods=['GET'])
@_require_auth
def auth_me():
    user = request.user
    return jsonify({
        'uid':   user.get('uid'),
        'email': user.get('email'),
        'name':  user.get('name'),
    }), 200


# ── Upload (supports multiple files) ─────────────────────────────────────────
@app.route('/api/upload', methods=['POST'])
@_require_auth
@limiter.limit('15 per minute')
def upload_file():
    files = request.files.getlist('file')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No file provided'}), 400

    # Parse options (shared across all files in the batch)
    expiry_key  = request.form.get('expiry', '24h')
    expiry_hours = EXPIRY_OPTIONS.get(expiry_key, 24)
    password    = request.form.get('password', '').strip()
    password_hash: bytes | None = bcrypt.hashpw(password.encode(), bcrypt.gensalt()) if password else None

    owner_uid = request.user.get('uid')
    results = []

    for file in files:
        if not file or file.filename == '':
            continue
        if not allowed_file(file.filename):
            results.append({'file': file.filename, 'error': 'File type not allowed'})
            continue

        original_filename = file.filename
        safe_name   = secure_filename(original_filename)
        unique_name = f"{uuid.uuid4().hex}_{safe_name}"
        suffix      = os.path.splitext(safe_name)[1]
        tmp_path    = None

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp_path = tmp.name
                file.save(tmp.name)

            file_size = os.path.getsize(tmp_path)
            if file_size > MAX_FILE_SIZE:
                results.append({'file': original_filename, 'error': 'File exceeds 50 MB limit'})
                continue

            file_hash   = utils.generate_sha256(tmp_path)
            file_type   = scanner.detect_file_type(original_filename)

            # Reuse scan result if same file was previously scanned as SAFE
            cached_result = database.get_scan_result_by_hash(file_hash)
            if cached_result:
                scan_result = {
                    'filename': original_filename,
                    'type': cached_result['type'],
                    'prediction': cached_result['prediction'],
                    'confidence': cached_result['confidence'],
                    'features': {},
                    'error': None,
                }
                print(f"[Upload] '{original_filename}' → Reusing previous SAFE result (hash match)")
            else:
                scan_result = scanner.scan_file(tmp_path, original_filename)

            file_id = database.add_file(
                filename=unique_name,
                original_filename=original_filename,
                file_hash=file_hash,
                file_type=file_type,
                file_size=file_size,
                filepath='',
                owner_uid=owner_uid,
            )
            database.update_scan_result(file_id, scan_result['prediction'], scan_result['confidence'])

            if scan_result['prediction'] == 'MALWARE':
                results.append({
                    'status': 'BLOCKED',
                    'message': 'File blocked: malware detected',
                    'file': original_filename,
                    'file_id': file_id,
                    'type': scan_result['type'],
                    'prediction': 'MALWARE',
                    'confidence': scan_result['confidence'],
                })
                continue


            storage_path = f"uploads/{owner_uid}/{unique_name}"
            with open(tmp_path, 'rb') as fh:
                upload_bytes(storage_path, fh.read(), content_type=file.mimetype or 'application/octet-stream')

            database.update_file_path(file_id, storage_path)

            share_code = utils.generate_share_code()
            for _ in range(10):
                if not database.get_share_link(share_code):
                    break
                share_code = utils.generate_share_code()

            base_url = request.host_url.rstrip('/')
            qr_bytes, dl_url = utils.generate_qr_code(share_code, base_url)
            qr_storage_path = f"qr_codes/qr_{share_code}.png"
            upload_bytes(qr_storage_path, qr_bytes, content_type='image/png')

            expires_at = utils.get_expiry_time(hours=expiry_hours) if expiry_hours else None
            ph_str = password_hash.decode() if password_hash else None
            database.add_share_link(file_id, share_code, qr_storage_path, expires_at, password_hash=ph_str)

            results.append({
                'status': 'SAFE',
                'message': 'File scanned and uploaded successfully',
                'file_id': file_id,
                'file': original_filename,
                'type': scan_result['type'],
                'prediction': 'SAFE',
                'confidence': scan_result['confidence'],
                'share_code': share_code,
                'qr_code_url': f'/qr/{share_code}',
                'download_url': dl_url,
                'expires_at': expires_at.isoformat() if expires_at else None,
                'file_size': file_size,
                'password_protected': bool(password),
            })

        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    if not results:
        return jsonify({'error': 'No valid files processed'}), 400

    # If single file, return flat object for backward-compatibility
    if len(results) == 1:
        return jsonify(results[0]), 200

    return jsonify({'results': results}), 200


# ── Files list ────────────────────────────────────────────────────────────────
@app.route('/api/files', methods=['GET'])
@_require_auth
def get_files():
    owner_uid = request.user.get('uid')
    return jsonify(database.get_all_files(owner_uid=owner_uid)), 200


# ── Delete a file ─────────────────────────────────────────────────────────────
@app.route('/api/files/<file_id>', methods=['DELETE'])
@_require_auth
@limiter.limit('30 per minute')
def delete_file(file_id):
    owner_uid = request.user.get('uid')
    info = database.get_file(file_id)
    if not info:
        return jsonify({'error': 'File not found'}), 404
    if info.get('owner_uid') != owner_uid:
        return jsonify({'error': 'Forbidden'}), 403

    # Delete from Firebase Storage
    fpath = info.get('filepath')
    if fpath:
        try:
            from firebase_service import delete_blob
            delete_blob(fpath)
        except Exception:
            pass  # Storage object may already be gone

    deleted = database.delete_file(file_id, owner_uid)
    if not deleted:
        return jsonify({'error': 'Delete failed'}), 500

    return jsonify({'success': True}), 200


# ── Scan result ───────────────────────────────────────────────────────────────
@app.route('/api/scan-result/<file_id>', methods=['GET'])
@_require_auth
def get_scan_result(file_id):
    info = database.get_file(file_id)
    if not info:
        return jsonify({'error': 'File not found'}), 404
    if info.get('owner_uid') != request.user.get('uid'):
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify(info), 200


# ── Dashboard stats ───────────────────────────────────────────────────────────
@app.route('/api/dashboard-stats', methods=['GET'])
@_require_auth
def dashboard_stats():
    owner_uid = request.user.get('uid')
    return jsonify(database.get_dashboard_stats(owner_uid=owner_uid)), 200


# ── Storage stats ─────────────────────────────────────────────────────────────
@app.route('/api/storage-stats', methods=['GET'])
@_require_auth
def storage_stats():
    owner_uid = request.user.get('uid')
    return jsonify(database.get_storage_stats(owner_uid=owner_uid)), 200


# ── Check share code (with optional password) ─────────────────────────────────
@app.route('/api/check-code/<share_code>', methods=['GET'])
@limiter.limit('20 per minute')
def check_code(share_code):
    info = database.get_share_link(share_code)
    if not info:
        return jsonify({'valid': False, 'error': 'Invalid code'}), 404

    if info.get('expires_at'):
        try:
            exp = datetime.fromisoformat(info['expires_at'])
            if datetime.utcnow() > exp:
                return jsonify({'valid': False, 'error': 'Link has expired'}), 410
        except Exception:
            pass

    # If file is password-protected, check password
    password_hash = info.get('password_hash')
    if password_hash:
        provided = request.args.get('password', '')
        if not provided:
            return jsonify({
                'valid': True,
                'password_required': True,
                'filename': info.get('original_filename'),
                'file_type': info.get('file_type'),
            }), 200
        if not bcrypt.checkpw(provided.encode(), password_hash.encode()):
            return jsonify({'valid': False, 'error': 'Incorrect password'}), 403

    return jsonify({
        'valid': True,
        'password_required': False,
        'filename': info.get('original_filename'),
        'file_type': info.get('file_type'),
        'file_size': info.get('file_size'),
        'download_url': f'/download/{share_code}',
    }), 200


# ── QR code ───────────────────────────────────────────────────────────────────
@app.route('/qr/<code_or_file>')
def serve_qr(code_or_file):
    share_code = code_or_file
    if code_or_file.startswith('qr_') and '.' in code_or_file:
        share_code = code_or_file[3:].split('.', 1)[0]

    info = database.get_share_link(share_code)
    if not info or not info.get('qr_path'):
        abort(404)

    try:
        data = download_bytes(info['qr_path'])
    except FileNotFoundError:
        abort(404)
    return send_file(BytesIO(data), mimetype='image/png')


# ── Download file ─────────────────────────────────────────────────────────────
@app.route('/download/<share_code>', methods=['GET'])
@limiter.limit('30 per minute')
def download_file(share_code):
    info = database.get_share_link(share_code)
    if not info:
        abort(404)

    if info.get('expires_at'):
        try:
            exp = datetime.fromisoformat(info['expires_at'])
            if datetime.utcnow() > exp:
                return jsonify({'error': 'Download link has expired'}), 410
        except Exception:
            pass

    # Password check on direct download
    password_hash = info.get('password_hash')
    if password_hash:
        provided = request.args.get('password', '')
        if not provided or not bcrypt.checkpw(provided.encode(), password_hash.encode()):
            return jsonify({'error': 'Password required or incorrect'}), 403

    fpath = info.get('filepath')
    if not fpath:
        return jsonify({'error': 'File not found on server'}), 404

    try:
        data = download_bytes(fpath)
    except FileNotFoundError:
        return jsonify({'error': 'File not found on server'}), 404

    database.increment_download_count(share_code)
    return send_file(
        BytesIO(data),
        as_attachment=True,
        download_name=info.get('original_filename', 'download.bin'),
        mimetype='application/octet-stream',
    )


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(_):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(413)
def too_large(_):
    return jsonify({'error': 'File too large – max 50 MB'}), 413

@app.errorhandler(429)
def rate_limited(_):
    return jsonify({'error': 'Too many requests – please slow down'}), 429

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': f'Server error: {e}'}), 500


if __name__ == '__main__':
    print('=' * 60)
    print('  SecureShare  –  Firebase + AI Secure File Sharing')
    print('  http://localhost:5000')
    print('=' * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
