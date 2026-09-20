"""
Conversation manager.

The rendezvous address D is derived ONLY from the shared secret, so every
party holding the secret computes the same D independently. (The previous
version derived it from each user's own mnemonic, which gave A and B
different addresses.)

D is a plain address that receives `intendedTo` records; nobody needs its
private key for anything, and it never holds funds.
"""

from dataclasses import dataclass, field
from typing import Dict, List

from eth_account import Account
from eth_utils import to_checksum_address

from address_factory import AddressFactory
from crypto_utils import derive_material


def derive_rendezvous(shared_secret: bytes) -> str:
    """Deterministic D from the shared secret alone."""
    key = derive_material(shared_secret, b"sos69069/rendezvous-key", 32)
    return to_checksum_address(Account.from_key(key).address)


@dataclass
class Conversation:
    conversation_id: bytes
    shared_secret: bytes
    rendezvous_d: str
    # one-time signer accounts, held in memory only
    my_accounts: Dict[str, Account] = field(default_factory=dict)
    unused: List[str] = field(default_factory=list)

    @property
    def my_signers(self) -> List[str]:
        return list(self.my_accounts.keys())


class ConversationManager:
    def __init__(self, factory: AddressFactory):
        self.factory = factory
        self.conversations: Dict[bytes, Conversation] = {}

    def start_conversation(self, shared_secret: bytes, prealloc: int = 3) -> Conversation:
        """Idempotent: calling twice with the same secret returns the same conversation."""
        conv_id = derive_material(shared_secret, b"sos69069/conv-id", 16)
        if conv_id in self.conversations:
            return self.conversations[conv_id]

        conv = Conversation(
            conversation_id=conv_id,
            shared_secret=shared_secret,
            rendezvous_d=derive_rendezvous(shared_secret),
        )
        for _ in range(prealloc):
            self._allocate(conv)
        self.conversations[conv_id] = conv
        return conv

    def _allocate(self, conv: Conversation) -> str:
        addr, acct = self.factory.new_signer()
        conv.my_accounts[addr] = acct
        conv.unused.append(addr)
        return addr

    def next_signer(self, conv: Conversation):
        """Hand out a fresh one-time signer (address, account) per message."""
        if not conv.unused:
            self._allocate(conv)
        addr = conv.unused.pop(0)
        return addr, conv.my_accounts[addr]
