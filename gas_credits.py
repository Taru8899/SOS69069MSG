"""
Very light local stub for the reciprocal gas-credit system.
In a real deployment this would talk to a privacy-preserving coordinator.
"""

from typing import Dict
import json
import os


class GasCreditBook:
    def __init__(self, path: str = "gas_credits.json"):
        self.path = path
        self.credits: Dict[str, int] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path) as f:
                self.credits = json.load(f)

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self.credits, f)

    def earn(self, user_id: str, amount: int = 1):
        """Called when this user pays gas for a stranger’s signature."""
        self.credits[user_id] = self.credits.get(user_id, 0) + amount
        self._save()

    def spend(self, user_id: str, amount: int = 1) -> bool:
        """Called when this user wants someone else to pay for his signature."""
        if self.credits.get(user_id, 0) >= amount:
            self.credits[user_id] -= amount
            self._save()
            return True
        return False

    def balance(self, user_id: str) -> int:
        return self.credits.get(user_id, 0)
