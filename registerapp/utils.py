import base64
import hashlib

from django.conf import settings


def encrypt(value):
    """Encrypts a string value using SHA256, Base64, and a secret key."""
    value = str(value).encode('utf-8')
    key = settings.SECRET_KEY.encode('utf-8')
    hashed = hashlib.sha256(key + value).digest()
    return base64.b64encode(hashed).decode('utf-8')


def decrypt(value):
    """Decrypts an encrypted string value."""
    raise NotImplementedError('Decryption is not supported.')
