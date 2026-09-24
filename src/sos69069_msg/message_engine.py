"""Plain public self-posts — metadata = raw ≤64-char text.

Signer always posts intendedTo = their own address so on-chain there is
no link between conversation partners.
"""

from typing import Tuple

from .config import MAX_METADATA_LENGTH
from .crypto_utils import random_payload_hash
from .eip712 import sign_record
from .ethcrypto import KeyPair


def prepare_and_sign(
    key: KeyPair,
    plaintext: str,
    reply_code: str = "",
) -> Tuple[bytes, str, bytes]:
    """
    Sign a self-post: intendedTo = key.address.
    Returns (payload_hash, metadata, signature).
    """
    text = plaintext.strip()
    code = (reply_code or "").strip().lstrip("#")
    if code:
        metadata = (f"#{code[:4].upper()} " + text)
    else:
        metadata = text

    if len(metadata.encode("utf-8")) > MAX_METADATA_LENGTH:
        raise ValueError(f"Message limited to {MAX_METADATA_LENGTH} characters")

    payload_hash = random_payload_hash()
    # Self-post: intendedTo == signer
    signature = sign_record(key, key.address, payload_hash, metadata)
    return payload_hash, metadata, signature


def short_code(payload_hash_hex: str) -> str:
    h = payload_hash_hex.removeprefix("0x")
    return h[:4].upper()
