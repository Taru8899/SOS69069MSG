"""Just enough ABI for the SOS 69069 contract."""

from typing import Tuple

from .ethcrypto import keccak256, parse_address

RECORD_SIGNATURE_SELECTOR = keccak256(
    b"recordSignature(address,address,bytes32,bytes,string)")[:4]

# SignatureRecorded(address indexed signer, address indexed intendedTo, bytes32 payloadHash,
#                   bytes signature, address indexed submitter, uint256 timestamp, string metadata)
SIGNATURE_RECORDED_TOPIC = keccak256(
    b"SignatureRecorded(address,address,bytes32,bytes,address,uint256,string)")


def _w(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _pad(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 32)


def _dyn(b: bytes) -> bytes:
    return _w(len(b)) + _pad(b)


def encode_record_signature(signer: str, intended_to: str, payload_hash: bytes,
                            signature: bytes, metadata: str) -> bytes:
    """Calldata for recordSignature(signer, intendedTo, payloadHash, signature, metadata)."""
    if len(payload_hash) != 32:
        raise ValueError("payload_hash must be 32 bytes")
    sig_enc = _dyn(signature)
    meta_enc = _dyn(metadata.encode("utf-8"))
    off_sig = 5 * 32
    off_meta = off_sig + len(sig_enc)
    return (RECORD_SIGNATURE_SELECTOR
            + parse_address(signer).rjust(32, b"\x00")
            + parse_address(intended_to).rjust(32, b"\x00")
            + payload_hash + _w(off_sig) + _w(off_meta) + sig_enc + meta_enc)


def _read_dyn(data: bytes, offset: int) -> bytes:
    if offset + 32 > len(data):
        raise ValueError("bad offset")
    n = int.from_bytes(data[offset:offset + 32], "big")
    if offset + 32 + n > len(data):
        raise ValueError("bad length")
    return data[offset + 32: offset + 32 + n]


def decode_signature_recorded(data: bytes) -> Tuple[bytes, bytes, int, str]:
    """Decode the non-indexed event data -> (payloadHash, signature, timestamp, metadata)."""
    if len(data) < 128:
        raise ValueError("event data too short")
    payload_hash = data[0:32]
    signature = _read_dyn(data, int.from_bytes(data[32:64], "big"))
    timestamp = int.from_bytes(data[64:96], "big")
    metadata = _read_dyn(data, int.from_bytes(data[96:128], "big")).decode("utf-8")
    return payload_hash, signature, timestamp, metadata
