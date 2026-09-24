from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Outcome(StrEnum):
    """Etapa final observada para un candidato."""

    INPUT_BLOCKED = "input_blocked"
    GUARDRAIL_BLOCKED = "guardrail_blocked"
    TEXT_BLOCKED = "text_blocked"
    SIGNAL_CONFLICT = "signal_conflict"
    MODEL_REFUSAL = "model_refusal"
    OUTPUT_BLOCKED = "output_blocked"
    ACCEPTED_UNVERIFIED = "accepted_unverified"
    ATTACK_SUCCESS = "attack_success"
    ATTACK_FAILURE = "attack_failure"
    TRANSPORT_ERROR = "transport_error"
    TARGET_ERROR = "target_error"
    INVALID_RESPONSE = "invalid_response"


ERROR_OUTCOMES = {
    Outcome.TRANSPORT_ERROR,
    Outcome.TARGET_ERROR,
    Outcome.INVALID_RESPONSE,
}


@dataclass(slots=True)
class Seed:
    id: str
    prompt: str
    category: str = "unknown"
    technique: str = "seed"
    reasoning: str = ""
    expected: str = "malicious"
    success_indicators: list[str] = field(default_factory=list)
    source: str = "user"
    # v3 taxonomy / planner metadata. Defaults keep v2 datasets compatible.
    frameworks: list[str] = field(default_factory=list)
    control_ids: list[str] = field(default_factory=list)
    technique_id: str = ""
    technique_name: str = ""
    external_technique_ids: list[str] = field(default_factory=list)
    oracle: str = "manual"
    capability: str = "prompt"
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Candidate:
    id: str
    run_id: str
    root_seed_id: str
    parent_id: str | None
    generation: int
    prompt: str
    category: str
    operator: str
    expected: str = "malicious"
    success_indicators: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    control_ids: list[str] = field(default_factory=list)
    technique_id: str = ""
    technique_name: str = ""
    external_technique_ids: list[str] = field(default_factory=list)
    oracle: str = "manual"
    capability: str = "prompt"
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Evaluation:
    outcome: Outcome
    blocked: bool | None
    guardrail_passed: bool | None
    model_complied: bool | None
    output_passed: bool | None
    answer: str = ""
    reason: str = ""
    attack_type: str = ""
    risk_score: float | None = None
    http_status: int | None = None
    latency_ms: float = 0.0
    estimated_cost_usd: float = 0.0
    provider_cost_usd: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.outcome in ERROR_OUTCOMES

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["outcome"] = self.outcome.value
        return result


@dataclass(slots=True)
class ScoredCandidate:
    candidate: Candidate
    evaluation: Evaluation
    semantic_similarity: float
    novelty: float
    fitness: float
    selected: bool = False
