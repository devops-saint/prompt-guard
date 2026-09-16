"""
classifier.py

Entity detection (detectors.py) catches specific values — an email address, a
credit card number. It cannot catch this:

    "Our production Snowflake account has 14 warehouses and the customer
    ingestion pipeline uses this architecture..."

That sentence has zero PII but may be highly confidential. This module
classifies the *whole prompt* into a sensitivity level, separately from
per-entity redaction, and the policy engine uses that level to decide which
destinations (which LLM providers/models) the prompt is allowed to reach at
all — regardless of what redaction already happened.

v1 approach: keyword/phrase rule matching, loaded from a config file so the
rules are yours to tune, not buried in code. This is intentionally the same
tier of technique as the regex detectors — a real deployment should add an
ML classifier for cases keywords miss (see README "Enhance" section).

Levels, from least to most sensitive:
    PUBLIC        - no restriction
    INTERNAL      - fine for any approved enterprise AI
    CONFIDENTIAL  - approved AI + additional controls (e.g. must tokenize)
    RESTRICTED    - approved models only, possibly no external AI
    SECRET        - never leaves the enterprise boundary
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

# Which destinations each sensitivity level may be sent to. "destination" is
# a label your proxy assigns per provider/model (e.g. "approved_enterprise_ai"
# vs "external_public_api") — wire this up in proxy.py once you have more than
# one real destination.
DEFAULT_DESTINATION_POLICY = {
    "PUBLIC": ["any"],
    "INTERNAL": ["approved_enterprise_ai"],
    "CONFIDENTIAL": ["approved_enterprise_ai"],
    "RESTRICTED": ["approved_enterprise_ai_restricted"],
    "SECRET": [],  # empty = never leaves the boundary, regardless of destination
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
        # Check from most to least sensitive; first match wins.
        for level in ["SECRET", "RESTRICTED", "CONFIDENTIAL", "INTERNAL"]:
            terms = self.rules.get(level, [])
            matched = [t for t in terms if t.lower() in lowered]
            if matched:
                return Classification(level=level, matched_terms=matched)
        return Classification(level="PUBLIC", matched_terms=[])
