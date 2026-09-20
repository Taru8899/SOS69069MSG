"""
One-time signer keys derived from a 32-byte master seed.

Replaces the earlier BIP-39/BIP-44 approach: these keys only ever sign
records, never hold funds, and don't need to be importable into a wallet,
so a plain HKDF chain is simpler and needs no wordlist or eth-account.

    signer_i = HKDF(master_seed, info = "sos69069/signer/<i>")

The next unused index is persisted, so restarting never reuses a signer.
BACK UP THE SEED: it regenerates every signer key.
"""

import json
import os

from .crypto_utils import derive_material
from .ethcrypto import KeyPair, N


def generate_seed() -> bytes:
    return os.urandom(32)


class AddressFactory:
    def __init__(self, master_seed: bytes, storage_path: str = "signer_counter.json"):
        if len(master_seed) != 32:
            raise ValueError("master seed must be 32 bytes")
        self.master_seed = master_seed
        self.storage_path = storage_path
        self.next_index = 0
        if os.path.exists(storage_path):
            with open(storage_path) as f:
                self.next_index = int(json.load(f).get("next_signer", 0))

    def _save(self):
        with open(self.storage_path, "w") as f:
            json.dump({"next_signer": self.next_index}, f)

    def signer_at(self, index: int) -> KeyPair:
        for attempt in range(8):  # range check practically never loops
            info = b"sos69069/signer/%d/%d" % (index, attempt)
            key = derive_material(self.master_seed, info, 32)
            if 1 <= int.from_bytes(key, "big") < N:
                return KeyPair.from_private_key(key)
        raise RuntimeError("key derivation failed")

    def my_signer_addresses(self) -> set:
        """Addresses of every signer this seed has handed out (cached), to label 'you'."""
        cache = getattr(self, "_addr_cache", None)
        if cache is None:
            cache = self._addr_cache = {}
        for i in range(self.next_index):
            if i not in cache:
                cache[i] = self.signer_at(i).address
        return set(cache.values())

    def new_signer(self) -> KeyPair:
        kp = self.signer_at(self.next_index)
        self.next_index += 1
        self._save()
        return kp

    def relayer_key(self, index: int = 0) -> KeyPair:
        """Deterministic key that pays gas when YOU submit records. Fund it with a
        little ETH. Kept separate from signer keys (different HKDF domain)."""
        key = derive_material(self.master_seed, b"sos69069/relayer/%d" % index, 32)
        return KeyPair.from_private_key(key)
