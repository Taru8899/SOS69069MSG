"""
Conversation manager — random one-time D, no shared secret.

D is pure public common ground. Anyone who knows D can read and write
to it. Generate a fresh D per conversation; abandon it when finished.
"""

from dataclasses import dataclass, field
from typing import Dict, List
import os

from .address_factory import AddressFactory
from .ethcrypto import KeyPair


def random_rendezvous() -> str:
    """Fresh random Ethereum address used only as intendedTo (never holds funds)."""
    return KeyPair.from_private_key(os.urandom(32)).address


@dataclass
class Conversation:
    conversation_id: bytes          # random 16 bytes
    rendezvous_d: str
    my_keys: Dict[str, KeyPair] = field(default_factory=dict)
    unused: List[str] = field(default_factory=list)

    @property
    def my_signers(self) -> List[str]:
        return list(self.my_keys.keys())


class ConversationManager:
    def __init__(self, factory: AddressFactory):
        self.factory = factory
        self.conversations: Dict[bytes, Conversation] = {}
        self.current: Conversation | None = None

    def start_conversation(self, d: str | None = None, prealloc: int = 3) -> Conversation:
        """
        Start (or switch to) a conversation.
        - d=None  → generate a brand-new random D
        - d=addr  → use the address the user pasted / received
        """
        if d:
            d = d.strip()
            if not (d.startswith("0x") and len(d) == 42):
                raise ValueError("D must be a 42-character 0x-address")
            conv_id = bytes.fromhex(d[2:18].ljust(32, "0")[:32])  # stable id from address
        else:
            d = random_rendezvous()
            conv_id = os.urandom(16)

        if conv_id in self.conversations:
            self.current = self.conversations[conv_id]
            return self.current

        conv = Conversation(conv_id, d)
        for _ in range(prealloc):
            self._allocate(conv)
        self.conversations[conv_id] = conv
        self.current = conv
        return conv

    def _allocate(self, conv: Conversation) -> str:
        kp = self.factory.new_signer()
        conv.my_keys[kp.address] = kp
        conv.unused.append(kp.address)
        return kp.address

    def next_signer(self, conv: Conversation) -> KeyPair:
        """A fresh one-time signer per message."""
        if not conv.unused:
            self._allocate(conv)
        return conv.my_keys[conv.unused.pop(0)]
