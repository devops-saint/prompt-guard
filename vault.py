"""
vault.py

Stores the mapping from placeholder token -> real value, so tokenized PII can
be rehydrated once the LLM response comes back.

v1 uses a plain in-memory dict. THIS IS NOT PRODUCTION-SAFE — it's here so the
demo runs with zero setup. Before going further than a demo:

  - Swap InMemoryVault for a store with encryption at rest (e.g. a small table
    in your existing DB with column-level encryption, or a secrets manager /
    Vault/KMS-backed key-value store).
  - Add TTL/expiry — tokens shouldn't live forever once a request completes.
  - Restrict access to this store separately from your general app database;
    it's the single highest-value target in the whole system.
  - Add a deletion path (per-request or per-user) for right-to-erasure requests
    once compliance requirements apply.

Any replacement just needs to implement `store(value) -> token` and
`resolve(token) -> value | None`.
"""

from dataclasses import dataclass, field
import itertools
import re


class InMemoryVault:
    def __init__(self):
        self._store: dict[str, str] = {}
        self._counters: dict[str, itertools.count] = {}

    def store(self, entity_type: str, value: str) -> str:
        counter = self._counters.setdefault(entity_type, itertools.count(1))
        token = f"{{{{PII_{entity_type}_{next(counter):04d}}}}}"
        self._store[token] = value
        return token

    def resolve(self, token: str) -> str | None:
        return self._store.get(token)

    def rehydrate(self, text: str) -> str:
        """Replace every known token in `text` with its original value."""
        token_re = re.compile(r"\{\{PII_[A-Z_]+_\d{4}\}\}")

        def _sub(m):
            return self._store.get(m.group(), m.group())

        return token_re.sub(_sub, text)

    def size(self) -> int:
        return len(self._store)
