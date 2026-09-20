"""
Conversation manager.

The rendezvous address D is derived ONLY from the shared secret, so every
party holding it computes the same D. D never holds funds and its private
key is never needed; it is just the `intendedTo` value.
"""

from dataclasses import dataclass, field
from typing import Dict, List

from .address_factory import AddressFactory
from .crypto_utils import derive_material
from .ethcrypto import KeyPair


def derive_rendezvous(shared_secret: bytes) -> str:
    key = derive_material(shared_secret, b"sos69069/rendezvous-key", 32)
    return KeyPair.from_private_key(key).address


@dataclass
class Conversation:
    conversation_id: bytes
    shared_secret: bytes
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

    def start_conversation(self, shared_secret: bytes, prealloc: int = 3) -> Conversation:
        """Idempotent for the same secret."""
        if len(shared_secret) != 32:
            raise ValueError("shared secret must be 32 bytes")
        conv_id = derive_material(shared_secret, b"sos69069/conv-id", 16)
        if conv_id in self.conversations:
            return self.conversations[conv_id]
        conv = Conversation(conv_id, shared_secret, derive_rendezvous(shared_secret))
        for _ in range(prealloc):
            self._allocate(conv)
        self.conversations[conv_id] = conv
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
