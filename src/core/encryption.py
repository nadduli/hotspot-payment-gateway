import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken


class DecryptionError(Exception):
    pass


def _get_key() -> bytes:
    secret = os.getenv("ENCRYPTION_KEY")
    if not secret:
        raise RuntimeError("ENCRYPTION_KEY environment variable must be set for encryption/decryption")
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_value(value: str | None) -> str | None:
    if value is None:
        return None
    f = Fernet(_get_key())
    return f.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_value(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        f = Fernet(_get_key())
        plaintext = f.decrypt(value.encode("ascii"))
        return plaintext.decode("utf-8")
    except (base64.binascii.Error, ValueError, UnicodeDecodeError, InvalidToken) as exc:
        raise DecryptionError("Encrypted value is invalid or corrupted") from exc
