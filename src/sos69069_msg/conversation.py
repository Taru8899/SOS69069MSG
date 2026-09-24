"""
Two-address conversation — local pair only.

On-chain: each user always signs intendedTo = their own address (self-post).
Off-chain: the app stores My + Other so CHECK can merge both streams and
label Me / Other. Ending the conversation deletes that local link.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .ethcrypto import KeyPair, normalize_address


def random_wallet() -> KeyPair:
    """Fresh passwordless wallet for one conversation."""
    return KeyPair.from_private_key(os.urandom(32))


@dataclass
class Conversation:
    """Local-only pairing. Never published on-chain as a pair."""
    my: KeyPair
    other: str  # checksummed peer address

    @property
    def my_address(self) -> str:
        return self.my.address

    @property
    def other_address(self) -> str:
        return self.other


class ConversationStore:
    """
    Persist the active pair on disk. end_conversation() wipes it so the
    next chat starts from a clean page with no A↔B link left.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> Optional[Conversation]:
        if not self.path.exists():
            return None
        try:
            j = json.loads(self.path.read_text())
            key = bytes.fromhex(j["my_key"].removeprefix("0x"))
            other = normalize_address(j["other"])
            return Conversation(KeyPair.from_private_key(key), other)
        except Exception:
            return None

    def save(self, conv: Conversation) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({
            "my_address": conv.my_address,
            "my_key": conv.my.private_key.hex(),
            "other": conv.other_address,
        }))
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def clear(self) -> None:
        """End conversation: delete local A↔B link completely."""
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass


def start_pair(my: KeyPair | None, other: str) -> Conversation:
    """
    my=None → generate a fresh wallet.
    other   → peer address (required).
    """
    other_n = normalize_address(other.strip())
    if my is None:
        my = random_wallet()
    if my.address.lower() == other_n.lower():
        raise ValueError("My address and Other address must be different")
    return Conversation(my, other_n)
