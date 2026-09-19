"""
Helpers that prepare the call data for recordSignature / recordSignatureOne.
Actual broadcasting is left to the relayer or the reciprocal-credit payer.
"""

from typing import List, Dict, Any
from eth_utils import to_checksum_address
from config import CONTRACT_ADDRESS


def build_record_signature_call(
    signer: str,
    intended_to: str,
    payload_hash: bytes,
    signature: bytes,
    metadata: str,
) -> Dict[str, Any]:
    """Ready-to-send transaction dict for a single record."""
    return {
        "to": to_checksum_address(CONTRACT_ADDRESS),
        "function": "recordSignature",
        "args": [
            to_checksum_address(signer),
            to_checksum_address(intended_to),
            payload_hash,
            signature,
            metadata,
        ],
    }


def build_record_signature_one_call(
    signer: str,
    intended_to: str,
    payload_hashes: List[bytes],
    signatures: List[bytes],
    metadatas: List[str],
) -> Dict[str, Any]:
    """Ready-to-send transaction dict for a batch from one signer to one D."""
    return {
        "to": to_checksum_address(CONTRACT_ADDRESS),
        "function": "recordSignatureOne",
        "args": [
            to_checksum_address(signer),
            to_checksum_address(intended_to),
            payload_hashes,
            signatures,
            metadatas,
        ],
    }
