"""EIP-1559 (type 0x02) transaction signing."""

from typing import Tuple

from . import rlp
from .ethcrypto import KeyPair, keccak256, parse_address


def sign_eip1559(key: KeyPair, chain_id: int, nonce: int, max_priority_fee: int,
                 max_fee: int, gas_limit: int, to: str, value: int,
                 data: bytes) -> Tuple[bytes, bytes]:
    """Returns (raw_tx_bytes, tx_hash)."""
    fields = [chain_id, nonce, max_priority_fee, max_fee, gas_limit,
              parse_address(to), value, data, []]
    sig = key.sign_digest(keccak256(b"\x02" + rlp.encode(fields)))
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    y_parity = sig[64] - 27
    raw = b"\x02" + rlp.encode(fields + [y_parity, r, s])
    return raw, keccak256(raw)
