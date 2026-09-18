"""
guard.py

The main orchestrator:
    detect entities -> classify sensitivity -> apply policy ->
    redact/tokenize -> check destination against sensitivity ->
    emit structured audit record -> return canonical prompt

This is the piece to import and call from wherever your app currently calls
an LLM API directly.
"""

from dataclasses import dataclass, field
from collections import Counter
import logging
import time

from detectors import ALL_DETECTORS, Match
from policy import Policy
from vault import InMemoryVault
from classifier import SensitivityClassifier, Classification
from audit import AuditRecord, emit as emit_audit
from schema import CanonicalPrompt

logger = logging.getLogger("prompt_guard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


@dataclass
class GuardResult:
    sanitized_prompt: str
    blocked: bool
    block_reasons: list[str] = field(default_factory=list)
    entity_counts: Counter = field(default_factory=Counter)
    request_id: str = ""
    sensitivity_level: str = "PUBLIC"
    canonical_prompt: "CanonicalPrompt | None" = None


class PromptGuard:
    def __init__(
        self,
        policy: Policy | None = None,
        vault: InMemoryVault | None = None,
        classifier: SensitivityClassifier | None = None,
    ):
        self.policy = policy or Policy.load()
        self.vault = vault or InMemoryVault()
        self.classifier = classifier or SensitivityClassifier.load()
        self.detectors = ALL_DETECTORS

    def _detect_all(self, text: str) -> list[Match]:
        matches: list[Match] = []
        for detector in self.detectors:
            matches.extend(detector(text))
        # Filter by confidence threshold and drop overlaps (keep highest-confidence)
        matches = [m for m in matches if m.confidence >= self.policy.min_confidence]
        matches.sort(key=lambda m: (m.start, -m.confidence))
        deduped: list[Match] = []
        last_end = -1
        for m in matches:
            if m.start >= last_end:
                deduped.append(m)
                last_end = m.end
        return deduped

    def sanitize(self, prompt: str, request_id: str = "", destination: str = "any") -> GuardResult:
        """
        `destination` identifies where this prompt is headed (e.g.
        "any", "approved_enterprise_ai", "approved_enterprise_ai_restricted").
        Wire your proxy's routing logic to pass the real destination label
        once you have more than one; "any" only satisfies the PUBLIC level.
        """
        request_id = request_id or f"req_{int(time.time() * 1000)}"
        matches = self._detect_all(prompt)
        classification = self.classifier.classify(prompt)

        entity_block_reasons = [
            f"{m.entity_type} detected" for m in matches
            if self.policy.action_for(m.entity_type) == "block"
        ]
        destination_blocked = not classification.allowed_for(
            destination, self.classifier.destination_policy
        )

        if entity_block_reasons or destination_blocked:
            reasons = sorted(set(entity_block_reasons))
            if destination_blocked:
                reasons.append(
                    f"sensitivity {classification.level} not permitted for destination '{destination}'"
                )
            self._audit(
                request_id, classification, {}, {}, "BLOCK", reasons, destination
            )
            return GuardResult(
                sanitized_prompt="",
                blocked=True,
                block_reasons=reasons,
                request_id=request_id,
                sensitivity_level=classification.level,
            )

        # Apply mask/tokenize actions right-to-left so earlier offsets stay valid
        out = prompt
        counts: Counter = Counter()
        actions: dict = {}
        for m in sorted(matches, key=lambda m: m.start, reverse=True):
            action = self.policy.action_for(m.entity_type)
            actions[m.entity_type] = action
            if action == "allow":
                continue
            elif action == "mask":
                replacement = f"[{m.entity_type}]"
            elif action == "tokenize":
                replacement = self.vault.store(m.entity_type, m.value)
            else:
                continue
            out = out[: m.start] + replacement + out[m.end :]
            counts[m.entity_type] += 1

        self._audit(request_id, classification, counts, actions, "ALLOW", [], destination)

        canonical = CanonicalPrompt(
            sanitized_text=out,
            sensitivity_level=classification.level,
            entity_types_present=sorted(counts.keys()),
            destination=destination,
            request_id=request_id,
        )

        return GuardResult(
            sanitized_prompt=out,
            blocked=False,
            entity_counts=counts,
            request_id=request_id,
            sensitivity_level=classification.level,
            canonical_prompt=canonical,
        )

    def _audit(
        self,
        request_id: str,
        classification: Classification,
        counts: dict,
        actions: dict,
        final_action: str,
        block_reasons: list,
        destination: str,
    ) -> None:
        record = AuditRecord.build(
            request_id=request_id,
            sensitivity_level=classification.level,
            sensitivity_matched_terms=classification.matched_terms,
            entity_counts=dict(counts),
            entity_actions=actions,
            final_action=final_action,
            block_reasons=block_reasons,
            destination=destination,
        )
        emit_audit(record, logger)

    def rehydrate(self, llm_response: str) -> str:
        """Call this on the model's response before showing it to the user,
        so any tokenized values the model echoed back are restored."""
        return self.vault.rehydrate(llm_response)
