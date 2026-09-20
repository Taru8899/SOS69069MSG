"""
Minimal Ethereum crypto with NO dependency on eth-account / web3
(those need pydantic-core and ckzg, which have no Android wheels).

Depends only on `cryptography` (available on Android via Chaquopy).

- keccak256            pure Python
- secp256k1 signing    `cryptography` (OpenSSL, random k) + low-s + recovery id
- public-key recovery  pure Python (public data only, no secrets involved)
"""

from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed, decode_dss_signature,
)

# ------------------------------------------------------------------ keccak
_MASK = (1 << 64) - 1
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]


def _rol(v: int, n: int) -> int:
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _keccak_f(A):
    for rnd in range(24):
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        A = [A[i] ^ D[i % 5] for i in range(25)]
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(A[x + 5 * y], _ROT[x][y])
        A = [
            B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y])
            for y in range(5) for x in range(5)
        ]
        A[0] ^= _RC[rnd]
    return A


def keccak256(data: bytes) -> bytes:
    """Original Keccak-256 (Ethereum), NOT NIST SHA3-256."""
    rate = 136
    q = rate - (len(data) % rate)
    pad = b"\x81" if q == 1 else b"\x01" + b"\x00" * (q - 2) + b"\x80"
    data = data + pad
    A = [0] * 25
    for off in range(0, len(data), rate):
        block = data[off:off + rate]
        for i in range(rate // 8):
            A[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        A = _keccak_f(A)
    return b"".join(A[i].to_bytes(8, "little") for i in range(4))


# --------------------------------------------------------------- secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = N // 2
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = Optional[Tuple[int, int]]


def _add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % P == 0:
            return None
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return x, (lam * (p[0] - x) - p[1]) % P


def _mul(k: int, pt: Point) -> Point:
    result: Point = None
    while k:
        if k & 1:
            result = _add(result, pt)
        pt = _add(pt, pt)
        k >>= 1
    return result


def recover_pubkey(digest: bytes, r: int, s: int, v: int) -> Optional[bytes]:
    """Return the 64-byte uncompressed public key (x||y), or None."""
    if v not in (27, 28) or not (1 <= r < N and 1 <= s < N):
        return None
    x = r
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if (y & 1) != (v - 27):
        y = P - y
    z = int.from_bytes(digest, "big")
    rinv = pow(r, -1, N)
    q = _add(_mul(rinv * s % N, (x, y)), _mul((-z * rinv) % N, G))
    if q is None:
        return None
    return q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")


# ---------------------------------------------------------------- addresses
def to_checksum(addr20: bytes) -> str:
    """EIP-55 checksummed address from 20 raw bytes."""
    hex_addr = addr20.hex()
    h = keccak256(hex_addr.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(hex_addr))


def parse_address(addr: str) -> bytes:
    a = addr[2:] if addr[:2] in ("0x", "0X") else addr
    if len(a) != 40:
        raise ValueError(f"Not a 20-byte address: {addr!r}")
    return bytes.fromhex(a)


def normalize_address(addr: str) -> str:
    return to_checksum(parse_address(addr))


def _pubkey_of(private_key: bytes) -> bytes:
    k = int.from_bytes(private_key, "big")
    if not (1 <= k < N):
        raise ValueError("private key out of range")
    nums = ec.derive_private_key(k, ec.SECP256K1()).public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def address_of_private_key(private_key: bytes) -> str:
    return to_checksum(keccak256(_pubkey_of(private_key))[-20:])


def recover_address(digest: bytes, signature: bytes) -> Optional[str]:
    """Address that produced a 65-byte r||s||v signature over digest."""
    if len(signature) != 65:
        return None
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    if v < 27:
        v += 27
    pub = recover_pubkey(digest, r, s, v)
    return None if pub is None else to_checksum(keccak256(pub)[-20:])


# ------------------------------------------------------------------ signing
@dataclass(frozen=True)
class KeyPair:
    private_key: bytes
    address: str

    @staticmethod
    def from_private_key(private_key: bytes) -> "KeyPair":
        return KeyPair(private_key, address_of_private_key(private_key))

    def sign_digest(self, digest: bytes) -> bytes:
        """65-byte r||s||v, low-s (EIP-2), v in {27,28} — what the contract accepts."""
        if len(digest) != 32:
            raise ValueError("digest must be 32 bytes")
        priv = ec.derive_private_key(int.from_bytes(self.private_key, "big"), ec.SECP256K1())
        der = priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        r, s = decode_dss_signature(der)
        if s > HALF_N:
            s = N - s
        for v in (27, 28):
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])
            if recover_address(digest, sig) == self.address:
                return sig
        raise RuntimeError("could not determine recovery id")
