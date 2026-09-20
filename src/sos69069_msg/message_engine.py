"""Turns a human message into (payloadHash, metadata, signature), and back."""

from typing import Tuple

from .config import MAX_METADATA_LENGTH
from .crypto_utils import derive_material, open_message, random_payload_hash, seal_message
from .eip712 import sign_record
from .ethcrypto import KeyPair


def _msg_key(shared_secret: bytes) -> bytes:
    return derive_material(shared_secret, b"sos69069/msg-key", 32)


def prepare_and_sign(
    key: KeyPair,
    intended_to: str,          # D
    plaintext: str,
    shared_secret: bytes,
    use_encryption: bool = True,
) -> Tuple[bytes, str, bytes]:
    """Returns (payload_hash, metadata, signature). Never truncates."""
    payload_hash = random_payload_hash()
    data = plaintext.encode("utf-8")
    if use_encryption:
        metadata = seal_message(data, _msg_key(shared_secret), payload_hash)
    else:
        if len(data) > MAX_METADATA_LENGTH:
            raise ValueError(f"Plain message limited to {MAX_METADATA_LENGTH} bytes (got {len(data)})")
        metadata = plaintext
    return payload_hash, metadata, sign_record(key, intended_to, payload_hash, metadata)


def read_record(metadata: str, payload_hash: bytes, shared_secret: bytes) -> str:
    """Decrypt a record from a SignatureRecorded event on D (InvalidTag if not ours)."""
    return open_message(metadata, _msg_key(shared_secret), payload_hash).decode("utf-8")
