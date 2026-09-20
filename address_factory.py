"""
Role-separated, one-time address factory (signer / relayer / funding).
Never reuses an address. Counters are persisted, so restarting the app
allocates fresh addresses instead of colliding with old ones.

Note: the rendezvous address D is derived from the shared secret, not here.
"""

import json
import os
from typing import Dict, Set, Tuple

from eth_account import Account
from eth_utils import to_checksum_address

from config import PATH_FUNDING, PATH_RELAYER, PATH_SIGNER

Account.enable_unaudited_hdwallet_features()


class AddressFactory:
    def __init__(self, mnemonic: str, storage_path: str = "used_addresses.json"):
        self.mnemonic = mnemonic
        self.storage_path = storage_path
        self.used: Set[str] = set()
        self.next_index: Dict[str, int] = {}
        self._load()

    # ---- persistence ----
    def _load(self):
        if os.path.exists(self.storage_path):
            with open(self.storage_path) as f:
                data = json.load(f)
            if isinstance(data, list):  # old format
                self.used = set(data)
            else:
                self.used = set(data.get("used", []))
                self.next_index = data.get("next", {})

    def _save(self):
        with open(self.storage_path, "w") as f:
            json.dump({"used": sorted(self.used), "next": self.next_index}, f)

    # ---- derivation ----
    def _derive(self, path: str, index: int) -> Tuple[str, Account]:
        acct = Account.from_mnemonic(self.mnemonic, account_path=f"{path}/{index}")
        addr = to_checksum_address(acct.address)
        if addr in self.used:
            raise RuntimeError(f"Address already used: {addr}")
        self.used.add(addr)
        self._save()
        return addr, acct

    def _next(self, path: str) -> Tuple[str, Account]:
        """Allocate the next never-used index on this path."""
        index = self.next_index.get(path, 0)
        while True:
            try:
                result = self._derive(path, index)
                break
            except RuntimeError:
                index += 1
        self.next_index[path] = index + 1
        self._save()
        return result

    def new_signer(self) -> Tuple[str, Account]:
        return self._next(PATH_SIGNER)

    def new_relayer(self) -> Tuple[str, Account]:
        return self._next(PATH_RELAYER)

    def new_funding(self) -> Tuple[str, Account]:
        return self._next(PATH_FUNDING)
