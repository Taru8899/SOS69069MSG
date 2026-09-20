"""
EIP-712 for the SOS 69069 contract, hand-rolled for its single fixed type:

    Record(address signer,address intendedTo,bytes32 payloadHash,bytes32 metadataHash)
    domain = {name:"69069", version:"1", chainId, verifyingContract}

This mirrors the contract's _verifySignature / recordStructHash exactly.
"""

from .config import (
    CHAIN_ID, CONTRACT_ADDRESS, EIP712_NAME, EIP712_VERSION, MAX_METADATA_LENGTH,
)
from .ethcrypto import (
    HALF_N, KeyPair, keccak256, normalize_address, parse_address, recover_address,
)

DOMAIN_TYPEHASH = keccak256(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)
RECORD_TYPEHASH = keccak256(
    b"Record(address signer,address intendedTo,bytes32 payloadHash,bytes32 metadataHash)"
)


def _addr32(addr: str) -> bytes:
    return parse_address(addr).rjust(32, b"\x00")


def domain_separator(chain_id: int = CHAIN_ID, contract: str = CONTRACT_ADDRESS) -> bytes:
    return keccak256(
        DOMAIN_TYPEHASH
        + keccak256(EIP712_NAME.encode())
        + keccak256(EIP712_VERSION.encode())
        + chain_id.to_bytes(32, "big")
        + _addr32(contract)
    )


def eip712_digest(domain_sep: bytes, struct_hash: bytes) -> bytes:
    return keccak256(b"\x19\x01" + domain_sep + struct_hash)


def record_struct_hash(signer: str, intended_to: str, payload_hash: bytes, metadata: str) -> bytes:
    """Equals the contract's recordStructHash(); also its dedup key."""
    if len(payload_hash) != 32:
        raise ValueError("payload_hash must be exactly 32 bytes")
    raw = metadata.encode("utf-8")
    if len(raw) > MAX_METADATA_LENGTH:
        raise ValueError("metadata exceeds the 64-byte limit of SOS 69069")
    return keccak256(
        RECORD_TYPEHASH + _addr32(signer) + _addr32(intended_to) + payload_hash + keccak256(raw)
    )


def record_digest(signer: str, intended_to: str, payload_hash: bytes, metadata: str,
                  chain_id: int = CHAIN_ID) -> bytes:
    return eip712_digest(
        domain_separator(chain_id), record_struct_hash(signer, intended_to, payload_hash, metadata)
    )


def sign_record(key: KeyPair, intended_to: str, payload_hash: bytes, metadata: str) -> bytes:
    """65-byte r||s||v signature the contract will accept (signer = key.address)."""
    return key.sign_digest(record_digest(key.address, intended_to, payload_hash, metadata))


def verify_record(signer: str, intended_to: str, payload_hash: bytes, metadata: str,
                  signature: bytes) -> bool:
    """Local mirror of the contract's checks, so nobody pays gas for a bad record."""
    if len(signature) != 65:
        return False
    if int.from_bytes(signature[32:64], "big") > HALF_N:
        return False
    digest = record_digest(signer, intended_to, payload_hash, metadata)
    return recover_address(digest, signature) == normalize_address(signer)
