"""
policy.py

Loads redaction policy from a config file (policy.json) rather than hardcoding
rules in application logic. This is the piece you'll extend most as compliance
requirements arrive — e.g. adding HIPAA's 18 identifiers, or stricter rules for
prompts headed to external vs. internal models.

Actions per entity type:
  - "allow"     : leave as-is (use sparingly, e.g. for low-risk internal tools)
  - "mask"      : irreversible replace, e.g. "[EMAIL]"
  - "tokenize"  : reversible replace via the vault, e.g. "{{PII_EMAIL_004}}"
  - "block"     : reject the entire prompt rather than send anything
"""

from dataclasses import dataclass, field
import json
import os

DEFAULT_POLICY = {
    "default_action": "tokenize",  # applied to any entity type not listed below
    "min_confidence": 0.35,         # matches below this confidence are ignored
    "rules": {
        "EMAIL": "tokenize",
        "PHONE": "tokenize",
        "SSN": "block",
        "CREDIT_CARD": "block",
        "IP_ADDRESS": "mask",
        "API_KEY": "block",
        "POTENTIAL_SECRET": "block",
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
        """
        Loads from a JSON file if provided and it exists, otherwise looks for
        policy.json next to this file, otherwise falls back to DEFAULT_POLICY.
        (Using JSON instead of YAML to keep v1 dependency-free; swap to PyYAML
        once you're ready to hand this file to non-engineers.)
        """
        if path is None:
            candidate = os.path.join(os.path.dirname(__file__), "policy.json")
            path = candidate if os.path.exists(candidate) else None

        data = DEFAULT_POLICY
        if path and os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
        return cls(
            default_action=data.get("default_action", "tokenize"),
            min_confidence=data.get("min_confidence", 0.5),
            rules=data.get("rules", {}),
        )
