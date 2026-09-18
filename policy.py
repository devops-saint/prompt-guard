"""
policy.py

Loads entity redaction actions from policy.json.
"""

from dataclasses import dataclass, field
import json
import os

DEFAULT_POLICY = {
    "default_action": "tokenize",
    "min_confidence": 0.35,
    "rules": {
        "EMAIL": "tokenize", #mask,tokenize, block 3 states are present here...
        "PHONE": "tokenize",
        "SSN": "tokenize",
        "CREDIT_CARD": "tokenize",
        "PAN" : "tokenize",
        "IP_ADDRESS": "tokenize",
        "API_KEY": "tokenize",
        "POTENTIAL_SECRET": "tokenize",
        "PERSON_NAME": "tokenize",
    },
}


@dataclass
class Policy:
    default_action: str
    min_confidence: float
    rules: dict = field(default_factory=dict)

    def action_for(self, entity_type: str) -> str:
        return self.rules.get(entity_type, self.default_action)

    @classmethod
    def load(cls, path: str | None = None) -> "Policy":
        if path is None:
            candidate = os.path.join(os.path.dirname(__file__), "policy.json")
            path = candidate if os.path.exists(candidate) else None

        data = DEFAULT_POLICY
        if path and os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
        return cls(
            default_action=data.get("default_action", "tokenize"),
            min_confidence=data.get("min_confidence", 0.35),
            rules=data.get("rules", {}),
        )