"""
vault.py

In-memory reversible token storage with compact, token-optimized identifiers.
"""

import itertools
import re

ENTITY_PREFIX_MAP = {
    "PERSON_NAME": "P",
    "EMAIL": "E",
    "PHONE": "T",
    "IP_ADDRESS": "A",
    "SSN": "S",
    "CREDIT_CARD": "C",
    "API_KEY": "K",
    "PAN": "PAN",
    "POTENTIAL_SECRET": "X",
}


class InMemoryVault:
    def __init__(self):
        self._store: dict[str, str] = {}
        self._counters: dict[str, itertools.count] = {}

    def store(self, entity_type: str, value: str) -> str:
        counter = self._counters.setdefault(entity_type, itertools.count(1))
        prefix = ENTITY_PREFIX_MAP.get(entity_type, entity_type[:2].upper())
        token = f"[{prefix}{next(counter)}]"
        self._store[token] = value
        return token

    def resolve(self, token: str) -> str | None:
        return self._store.get(token)

    def rehydrate(self, text: str) -> str:
        """Replace every known token in `text` with its original value."""
        token_re = re.compile(r"\[[A-Z]+\d+\]")

        def _sub(m):
            return self._store.get(m.group(), m.group())

        return token_re.sub(_sub, text)

    def size(self) -> int:
        return len(self._store)