"""
Exact EIP-712 construction matching the SOS 69069 contract.
"""

from eth_account.messages import encode_typed_data
from eth_utils import keccak, to_checksum_address
from typing import Dict, Any
from config import CONTRACT_ADDRESS, EIP712_NAME, EIP712_VERSION, CHAIN_ID

RECORD_TYPEHASH = keccak(
    text="Record(address signer,address intendedTo,bytes32 payloadHash,bytes32 metadataHash)"
)


def build_typed_data(
    signer: str,
    intended_to: str,
    payload_hash: bytes,
    metadata: str,
) -> Dict[str, Any]:
    """
    Build the exact typed-data dict that the contract expects.
    metadata MUST be ≤ 64 characters.
    """
    if len(metadata.encode("utf-8")) > 64:
        raise ValueError("metadata exceeds 64-byte limit of SOS 69069")

    metadata_hash = keccak(text=metadata)

    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Record": [
                {"name": "signer", "type": "address"},
                {"name": "intendedTo", "type": "address"},
                {"name": "payloadHash", "type": "bytes32"},
                {"name": "metadataHash", "type": "bytes32"},
            ],
        },
        "primaryType": "Record",
        "domain": {
            "name": EIP712_NAME,
            "version": EIP712_VERSION,
            "chainId": CHAIN_ID,
            "verifyingContract": to_checksum_address(CONTRACT_ADDRESS),
        },
        "message": {
            "signer": to_checksum_address(signer),
            "intendedTo": to_checksum_address(intended_to),
            "payloadHash": payload_hash,
            "metadataHash": metadata_hash,
        },
    }


def sign_record(account, signer: str, intended_to: str, payload_hash: bytes, metadata: str):
    """Sign a Record and return the 65-byte signature."""
    typed = build_typed_data(signer, intended_to, payload_hash, metadata)
    signable = encode_typed_data(full_message=typed)
    signed = account.sign_message(signable)
    return signed.signature
