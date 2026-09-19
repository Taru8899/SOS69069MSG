"""
Cryptographic helpers: shared-secret derivation, HKDF, simple encryption.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
import hashlib


def derive_material(shared_secret: bytes, info: bytes, length: int = 64) -> bytes:
    """HKDF-SHA256 derivation used for D, signer seeds, etc."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_secret)


def encrypt_message(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt a short message that will later fit into 64-char metadata."""
    # key must be 32 bytes
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_message(ciphertext: bytes, key: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    nonce, ct = ciphertext[:12], ciphertext[12:]
    return aead.decrypt(nonce, ct, None)


def random_payload_hash() -> bytes:
    return os.urandom(32)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
