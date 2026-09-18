"""
schema.py

A canonical, provider-agnostic representation of a guarded prompt. The point
is to decouple "what the guard produced" from "what format provider X wants",
so adding a new provider or a prompt-optimization step later doesn't mean
touching the guard's internals.

v1 keeps this intentionally simple: it carries the sanitized text plus the
metadata a provider adapter or an optimizer would need. It does NOT attempt
to split the prompt into task/context/constraints — that kind of structural
rewrite needs an LLM call of its own (the "prompt optimizer" layer), and per
the design principle below, that call must happen AFTER sanitization, never
before. See README for how to add an optimizer that fills in richer fields
without ever reintroducing redacted values.
"""

from dataclasses import dataclass, field, asdict
import json


@dataclass
class CanonicalPrompt:
    sanitized_text: str
    sensitivity_level: str
    entity_types_present: list = field(default_factory=list)
    destination: str = ""
    request_id: str = ""

    # Optimizer-filled fields — left empty until an optimization stage exists.
    # An optimizer must only ever operate on `sanitized_text` and must not
    # receive the vault, so it structurally cannot reintroduce real values.
    task: str = ""
    context: str = ""
    constraints: list = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


def to_provider_format(canonical: CanonicalPrompt, provider: str) -> dict:
    """
    Adapter stub: converts the canonical prompt into whatever shape a given
    provider's API expects. Add one branch per provider as you integrate them
    — this is the seam that keeps the guard itself provider-agnostic.
    """
    text = canonical.sanitized_text
    if canonical.task:
        text = f"{canonical.task}\n\n{canonical.context}\n\n{text}"

    if provider in ("anthropic", "claude"):
        return {"messages": [{"role": "user", "content": text}]}
    elif provider == "openai":
        return {"messages": [{"role": "user", "content": text}]}
    else:
        # Generic fallback — most providers accept a plain prompt string
        return {"prompt": text}
