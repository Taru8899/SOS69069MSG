"""Plain public messages only — metadata carries the raw ≤64-char text."""

from typing import Tuple

from .config import MAX_METADATA_LENGTH
from .crypto_utils import random_payload_hash
from .eip712 import sign_record
from .ethcrypto import KeyPair


def prepare_and_sign(
    key: KeyPair,
    intended_to: str,          # D
    plaintext: str,
    reply_code: str = "",
) -> Tuple[bytes, str, bytes]:
    """
    Returns (payload_hash, metadata, signature).
    metadata = optional "#XXXX " prefix + plain text, total ≤ 64 characters.
    No encryption.
    """
    text = plaintext.strip()
    code = (reply_code or "").strip().lstrip("#")
    if code:
        prefix = f"#{code[:4].upper()} "
        metadata = (prefix + text)[:MAX_METADATA_LENGTH]
    else:
        metadata = text[:MAX_METADATA_LENGTH]

    if len(metadata.encode("utf-8")) > MAX_METADATA_LENGTH:
        raise ValueError(f"Message limited to {MAX_METADATA_LENGTH} characters")

    payload_hash = random_payload_hash()
    signature = sign_record(key, intended_to, payload_hash, metadata)
    return payload_hash, metadata, signature


def short_code(payload_hash_hex: str) -> str:
    """Visible short code shown next to every message (first 4 hex chars)."""
    h = payload_hash_hex.removeprefix("0x")
    return h[:4].upper()
