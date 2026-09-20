"""
Cryptographic helpers: HKDF and compact authenticated encryption that fits
into the contract's 64-byte metadata field.

Envelope layout (all inside ONE metadata string):
    metadata = base64url( ChaCha20-Poly1305(plaintext) )   # no padding
    nonce    = payloadHash[:12]   (payloadHash is random and public on-chain,
                                   so the nonce needs no extra bytes)
    aad      = payloadHash

    64 chars of base64 = 48 bytes = 32 bytes plaintext + 16 bytes tag.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_METADATA_BYTES = 64
TAG_BYTES = 16
# 64 base64 chars -> 48 raw bytes -> minus tag
MAX_PLAINTEXT_BYTES = (MAX_METADATA_BYTES // 4) * 3 - TAG_BYTES  # 32


def derive_material(shared_secret: bytes, info: bytes, length: int = 64) -> bytes:
    """HKDF-SHA256 derivation used for D, message keys, etc."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(shared_secret)


def random_payload_hash() -> bytes:
    return os.urandom(32)


def seal_message(plaintext: bytes, key: bytes, payload_hash: bytes) -> str:
    """Encrypt into a <=64-char metadata string. Raises if it does not fit."""
    if len(payload_hash) != 32:
        raise ValueError("payload_hash must be 32 bytes")
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ValueError(
            f"Encrypted messages are limited to {MAX_PLAINTEXT_BYTES} bytes "
            f"(got {len(plaintext)}). Split it across several records."
        )
    ct = ChaCha20Poly1305(key).encrypt(payload_hash[:12], plaintext, payload_hash)
    metadata = base64.urlsafe_b64encode(ct).decode("ascii").rstrip("=")
    assert len(metadata) <= MAX_METADATA_BYTES
    return metadata


def open_message(metadata: str, key: bytes, payload_hash: bytes) -> bytes:
    """Inverse of seal_message. Raises cryptography.exceptions.InvalidTag
    if the record was not produced with this key (e.g. spam sent to D)."""
    padded = metadata + "=" * (-len(metadata) % 4)
    ct = base64.urlsafe_b64decode(padded.encode("ascii"))
    return ChaCha20Poly1305(key).decrypt(payload_hash[:12], ct, payload_hash)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
