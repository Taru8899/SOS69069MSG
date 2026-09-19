"""
Role-separated, one-time address factory.
Never reuses an address across roles or conversations.
"""

from eth_account import Account
from eth_utils import to_checksum_address
from typing import Tuple, Set
import json
import os

from config import PATH_FUNDING, PATH_RELAYER, PATH_SIGNER, PATH_RENDEZVOUS

Account.enable_unaudited_hdwallet_features()


class AddressFactory:
    def __init__(self, mnemonic: str, storage_path: str = "used_addresses.json"):
        self.mnemonic = mnemonic
        self.storage_path = storage_path
        self.used: Set[str] = set()
        self._load()

    def _load(self):
        if os.path.exists(self.storage_path):
            with open(self.storage_path) as f:
                self.used = set(json.load(f))

    def _save(self):
        with open(self.storage_path, "w") as f:
            json.dump(list(self.used), f)

    def _derive(self, path: str, index: int) -> Tuple[str, Account]:
        full_path = f"{path}/{index}"
        acct = Account.from_mnemonic(self.mnemonic, account_path=full_path)
        addr = to_checksum_address(acct.address)
        if addr in self.used:
            raise RuntimeError(f"Address already used: {addr}")
        self.used.add(addr)
        self._save()
        return addr, acct

    def new_signer(self, index: int) -> Tuple[str, Account]:
        return self._derive(PATH_SIGNER, index)

    def new_rendezvous(self, index: int) -> Tuple[str, Account]:
        """D address – we only need the address, never the private key on-chain."""
        return self._derive(PATH_RENDEZVOUS, index)

    def new_relayer(self, index: int) -> Tuple[str, Account]:
        return self._derive(PATH_RELAYER, index)

    def new_funding(self, index: int) -> Tuple[str, Account]:
        return self._derive(PATH_FUNDING, index)
