import hashlib
import random
import string
from datetime import datetime, timedelta
from io import BytesIO

import qrcode


def generate_sha256(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as fh:
        for chunk in iter(lambda: fh.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_share_code(length: int = 6) -> str:
    """Return a random numeric string of `length` digits."""
    return ''.join(random.choices(string.digits, k=length))


def generate_qr_code(share_code: str, base_url: str = 'http://localhost:5000') -> tuple:
    """
    Generate QR PNG bytes for the given share code.
    Returns (png_bytes, download_url).
    """
    download_url = f"{base_url.rstrip('/')}/download/{share_code}"

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(download_url)
    qr.make(fit=True)

    img = qr.make_image(fill_color='#1e293b', back_color='white')
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue(), download_url


def get_expiry_time(hours: int = 24) -> datetime:
    return datetime.utcnow() + timedelta(hours=hours)


def format_bytes(size: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
