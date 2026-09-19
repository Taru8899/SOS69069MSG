"""
Turns a human message into a ≤64-char metadata field + payloadHash
and produces a ready-to-submit signed Record.
"""

from typing import Tuple
from eth_account import Account
from crypto_utils import random_payload_hash, encrypt_message, derive_material
from eip712 import sign_record
from config import MAX_METADATA_LENGTH


def prepare_and_sign(
    account: Account,
    signer_address: str,
    intended_to: str,          # D
    plaintext: str,
    shared_secret: bytes,
    use_encryption: bool = True,
) -> Tuple[bytes, str, bytes]:
    """
    Returns (payload_hash, metadata, signature)
    metadata is the actual message carrier (≤ 64 chars).
    """
    if use_encryption:
        key = derive_material(shared_secret, b"msg-key", 32)
        ct = encrypt_message(plaintext.encode("utf-8"), key)
        # For demo we store a short hex representation.
        # In production you would use a more compact encoding
        # or split long messages across multiple records.
        metadata = ct.hex()[:MAX_METADATA_LENGTH]
    else:
        metadata = plaintext[:MAX_METADATA_LENGTH]

    if len(metadata.encode("utf-8")) > MAX_METADATA_LENGTH:
        raise ValueError("Message does not fit into 64-character metadata field")

    payload_hash = random_payload_hash()
    signature = sign_record(account, signer_address, intended_to, payload_hash, metadata)
    return payload_hash, metadata, signature
