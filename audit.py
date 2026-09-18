"""
audit.py

A structured audit record for every request, answering "what happened to my
prompt?" without ever storing the prompt itself or the raw sensitive values.

This is deliberately a plain dataclass with a `to_json()` method rather than
a database model — wire `emit()` up to your actual logging/SIEM pipeline
(Splunk, CloudWatch, a Kafka topic, whatever your org already uses) by
replacing the body of `emit()`. The record shape is the part worth keeping
stable; the transport is not.
"""

from dataclasses import dataclass, field, asdict
import json
import time


@dataclass
class DetectionSummary:
    entity_type: str
    count: int
    action: str  # "mask" | "tokenize" | "block" | "allow"


@dataclass
class AuditRecord:
    request_id: str
    timestamp: float
    sensitivity_level: str
    sensitivity_matched_terms: list = field(default_factory=list)
    detections: list = field(default_factory=list)  # list[DetectionSummary]
    final_action: str = "ALLOW"  # "ALLOW" | "BLOCK" | "RESTRICT"
    block_reasons: list = field(default_factory=list)
    destination: str = ""

    def to_json(self) -> str:
        d = asdict(self)
        return json.dumps(d, sort_keys=True)

    @classmethod
    def build(
        cls,
        request_id: str,
        sensitivity_level: str,
        sensitivity_matched_terms: list,
        entity_counts: dict,
        entity_actions: dict,
        final_action: str,
        block_reasons: list,
        destination: str = "",
    ) -> "AuditRecord":
        detections = [
            DetectionSummary(entity_type=et, count=n, action=entity_actions.get(et, "unknown"))
            for et, n in entity_counts.items()
        ]
        return cls(
            request_id=request_id,
            timestamp=time.time(),
            sensitivity_level=sensitivity_level,
            sensitivity_matched_terms=sensitivity_matched_terms,
            detections=detections,
            final_action=final_action,
            block_reasons=block_reasons,
            destination=destination,
        )


def emit(record: AuditRecord, logger) -> None:
    """
    Sends the audit record to your logging pipeline. v1 just writes structured
    JSON to the given logger at INFO level — swap this for a real sink
    (SIEM, audit DB, Kafka topic) when you're ready. Never pass the original
    prompt or raw matched values into this function or the record above.
    """
    logger.info("AUDIT %s", record.to_json())
