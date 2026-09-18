"""
classifier.py

Macro sensitivity classification and destination policy enforcement.
"""

from dataclasses import dataclass, field
import json
import os

LEVELS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"]

DEFAULT_CLASSIFICATION_RULES = {
    "SECRET": [
        "root password", "master key", "private key", "signing key",
        "unreleased earnings", "board minutes", "acquisition target",
    ],
    "RESTRICTED": [
        "production database", "production credentials", "customer pii export",
        "security incident", "vulnerability", "penetration test",
    ],
    "CONFIDENTIAL": [
        "internal architecture", "system architecture", "infrastructure diagram",
        "customer list", "pricing strategy", "contract terms", "roadmap",
        "unreleased feature", "internal only", "do not distribute",
    ],
    "INTERNAL": [
        "internal", "employee", "org chart", "team structure", "runbook",
        "postmortem", "wiki",
    ],
}

DEFAULT_DESTINATION_POLICY = {
    "PUBLIC": ["any"],
    "INTERNAL": ["approved_enterprise_ai"],
    "CONFIDENTIAL": ["approved_enterprise_ai"],
    "RESTRICTED": ["approved_enterprise_ai_restricted"],
    "SECRET": [],
}


@dataclass
class Classification:
    level: str
    matched_terms: list = field(default_factory=list)

    def allowed_for(self, destination: str, destination_policy: dict) -> bool:
        allowed = destination_policy.get(self.level, [])
        return "any" in allowed or destination in allowed


class SensitivityClassifier:
    def __init__(self, rules: dict | None = None, destination_policy: dict | None = None):
        self.rules = rules or DEFAULT_CLASSIFICATION_RULES
        self.destination_policy = destination_policy or DEFAULT_DESTINATION_POLICY

    @classmethod
    def load(cls, path: str | None = None) -> "SensitivityClassifier":
        if path is None:
            candidate = os.path.join(os.path.dirname(__file__), "classification_policy.json")
            path = candidate if os.path.exists(candidate) else None
        if path and os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            return cls(
                rules=data.get("rules", DEFAULT_CLASSIFICATION_RULES),
                destination_policy=data.get("destination_policy", DEFAULT_DESTINATION_POLICY),
            )
        return cls()

    def classify(self, text: str) -> Classification:
        lowered = text.lower()
        for level in ["SECRET", "RESTRICTED", "CONFIDENTIAL", "INTERNAL"]:
            terms = self.rules.get(level, [])
            matched = [t for t in terms if t.lower() in lowered]
            if matched:
                return Classification(level=level, matched_terms=matched)
        return Classification(level="PUBLIC", matched_terms=[])