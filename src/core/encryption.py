import base64
import hashlib
import os


def _get_key() -> bytes:
    secret = os.getenv("ENCRYPTION_KEY", "default-encryption-key")
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _keystream(nonce: bytes, length: int) -> bytes:
    key = _get_key()
    output = bytearray()
    counter = 0
    while len(output) < length:
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def encrypt_value(value: str | None) -> str | None:
    if value is None:
        return None
    plaintext = value.encode("utf-8")
    nonce = os.urandom(16)
    keystream = _keystream(nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_value(value: str | None) -> str | None:
    if value is None:
        return None
    decoded = base64.urlsafe_b64decode(value.encode("ascii"))
    nonce = decoded[:16]
    ciphertext = decoded[16:]
    keystream = _keystream(nonce, len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
    return plaintext.decode("utf-8")
