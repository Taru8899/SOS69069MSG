"""
EIP-712 construction matching the SOS 69069 contract:

    Record(address signer,address intendedTo,bytes32 payloadHash,bytes32 metadataHash)
    domain = {name:"69069", version:"1", chainId, verifyingContract}

metadataHash = keccak256(bytes(metadata)) (UTF-8), exactly as in the contract.
"""

from typing import Any, Dict

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak, to_checksum_address

from config import CHAIN_ID, CONTRACT_ADDRESS, EIP712_NAME, EIP712_VERSION, MAX_METADATA_LENGTH


def build_typed_data(signer: str, intended_to: str, payload_hash: bytes, metadata: str) -> Dict[str, Any]:
    if len(payload_hash) != 32:
        raise ValueError("payload_hash must be exactly 32 bytes")
    raw = metadata.encode("utf-8")
    if len(raw) > MAX_METADATA_LENGTH:
        raise ValueError("metadata exceeds the 64-byte limit of SOS 69069")

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
            "metadataHash": keccak(raw),
        },
    }


def sign_record(account, signer: str, intended_to: str, payload_hash: bytes, metadata: str) -> bytes:
    """Return the 65-byte (r||s||v) signature the contract expects."""
    signable = encode_typed_data(full_message=build_typed_data(signer, intended_to, payload_hash, metadata))
    sig = bytes(account.sign_message(signable).signature)
    assert len(sig) == 65
    return sig


def verify_record(signer: str, intended_to: str, payload_hash: bytes, metadata: str, signature: bytes) -> bool:
    """Local check that mirrors the contract's ecrecover, before anyone pays gas."""
    signable = encode_typed_data(full_message=build_typed_data(signer, intended_to, payload_hash, metadata))
    return Account.recover_message(signable, signature=signature) == to_checksum_address(signer)
