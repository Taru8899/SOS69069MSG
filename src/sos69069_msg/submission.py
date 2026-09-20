"""Call-data helpers for recordSignature / recordSignatureOne (broadcast is up to a relayer)."""

from typing import Any, Dict, List

from .config import CONTRACT_ADDRESS
from .ethcrypto import normalize_address


def build_record_signature_call(signer: str, intended_to: str, payload_hash: bytes,
                                signature: bytes, metadata: str) -> Dict[str, Any]:
    return {
        "to": normalize_address(CONTRACT_ADDRESS),
        "function": "recordSignature",
        "args": [normalize_address(signer), normalize_address(intended_to),
                 payload_hash, signature, metadata],
    }


def build_record_signature_one_call(signer: str, intended_to: str, payload_hashes: List[bytes],
                                    signatures: List[bytes], metadatas: List[str]) -> Dict[str, Any]:
    return {
        "to": normalize_address(CONTRACT_ADDRESS),
        "function": "recordSignatureOne",
        "args": [normalize_address(signer), normalize_address(intended_to),
                 payload_hashes, signatures, metadatas],
    }
