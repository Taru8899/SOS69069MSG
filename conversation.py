"""
Conversation manager: start with A + B → D, later add more signers to the same D.
"""

from dataclasses import dataclass, field
from typing import List, Dict
from crypto_utils import derive_material
from address_factory import AddressFactory


@dataclass
class Conversation:
    conversation_id: bytes
    shared_secret: bytes
    rendezvous_d: str
    my_signers: List[str] = field(default_factory=list)
    # local view only – never leaves the device
    known_participants: Dict[str, List[str]] = field(default_factory=dict)


class ConversationManager:
    def __init__(self, factory: AddressFactory):
        self.factory = factory
        self.conversations: Dict[bytes, Conversation] = {}

    def start_conversation(self, shared_secret: bytes, my_index_base: int = 0) -> Conversation:
        """
        Both A and B call this with the same shared_secret.
        They will independently derive the same D.
        """
        conv_id = derive_material(shared_secret, b"conv-id", 16)
        material = derive_material(shared_secret, b"rendezvous", 32)

        # Deterministic D from the shared secret
        d_index = int.from_bytes(material[:4], "big") % 100_000
        d_addr, _ = self.factory.new_rendezvous(d_index)

        # Allocate a few one-time signers for myself
        my_signers = []
        for i in range(3):
            addr, _ = self.factory.new_signer(my_index_base + i)
            my_signers.append(addr)

        conv = Conversation(
            conversation_id=conv_id,
            shared_secret=shared_secret,
            rendezvous_d=d_addr,
            my_signers=my_signers,
        )
        self.conversations[conv_id] = conv
        return conv

    def add_participant(self, conv: Conversation, new_shared_material: bytes):
        """
        When a new party joins, they receive the conversation secret
        (or a derived group secret) and start signing to the same D.
        """
        # The new party will call start_conversation-like logic
        # with the same secret and therefore obtain the same D.
        pass  # the real work is done on the new device
