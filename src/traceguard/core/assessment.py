"""Versioned deterministic assessment contracts; no infrastructure dependencies."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from traceguard.core.intelligence import EnrichedReport, LookupIOC, ProviderID
from traceguard.core.models import AnalysisReport

RiskLabel = Literal["unknown", "low", "suspicious", "malicious"]


class ScoringPolicy(BaseModel):
    """Fixed approved heuristic policy, not probability calibration."""

    model_config = ConfigDict(frozen=True)
    version: Literal["phase4-v1"] = "phase4-v1"
    risk_cap: Literal[100] = 100
    confidence_cap: Literal[95] = 95
    correlation_cap: Literal[10] = 10
    confidence_bonus_cap: Literal[20] = 20
    tension_penalty: Literal[10] = 10


class EvidenceReference(BaseModel):
    evidence_id: str
    provider_id: ProviderID
    outcome_index: int
    ioc_index: int
    lookup: LookupIOC | None
    report_reference: str | None = None
    observed_at: datetime | None = None
    observed_at_original: str | int | None = None
    fetched_at: datetime | None = None
    pointers: list[str]
    field_values: dict[str, JsonValue]


class ScoreContribution(BaseModel):
    reference: EvidenceReference
    rule_id: str
    base_score: int = 0
    base_support: int = 0
    age_seconds: float | None = None
    freshness_percent: int = 0
    freshness_reason: str = "No usable adverse evidence."
    weighted_score: int = 0
    weighted_support: int = 0
    role: Literal["maximum", "corroborating", "non_additive", "zero", "excluded"] = "excluded"
    no_adverse: bool = False
    reason: str
    flags: list[str] = Field(default_factory=list)


class EvidenceTension(BaseModel):
    kind: str
    evidence_ids: list[str]
    explanation: str


class IOCassessment(BaseModel):
    ioc_index: int
    ioc_id: str
    policy_version: str
    scoring_as_of: datetime
    risk_score: int = Field(ge=0, le=100)
    evidence_confidence: int = Field(ge=0, le=95)
    label: RiskLabel
    reason: str
    contributions: list[ScoreContribution]
    maximum_score: int
    maximum_support: int
    qualified_provider_count: int
    corroboration_evidence_ids: list[str]
    risk_bonus: int
    confidence_bonus: int
    tension_penalty: int
    risk_before_cap: int
    confidence_before_cap: int
    risk_cap: int = 100
    confidence_cap: int = 95
    tensions: list[EvidenceTension]
    coverage: dict[str, int]
    limitations: list[str]


class Relationship(BaseModel):
    kind: Literal["url_has_host", "email_has_domain"]
    source_id: str
    target_id: str
    pointers: list[str]
    risk_contribution: Literal[0] = 0
    confidence_contribution: Literal[0] = 0


class OccurrenceReference(BaseModel):
    occurrence_id: str
    ioc_id: str
    source: str
    line: int
    column: int
    start_offset: int
    end_offset: int
    pointer: str


class RelationshipGroup(BaseModel):
    kind: Literal["same_source_line", "same_input", "same_lookup"]
    group_id: str
    members: list[str]
    occurrences: list[OccurrenceReference] = Field(default_factory=list)
    lookup: LookupIOC | None = None
    reused_evidence_ids: list[str] = Field(default_factory=list)
    risk_contribution: Literal[0] = 0
    confidence_contribution: Literal[0] = 0


class Relationships(BaseModel):
    edges: list[Relationship] = Field(default_factory=list)
    groups: list[RelationshipGroup] = Field(default_factory=list)
    explanation: str = "Descriptive only: no causation, resolution, or transfer of risk."


class AssessedReport(AnalysisReport):
    schema_version: str = "1.2"
    assessments: list[IOCassessment]
    relationships: Relationships
    scoring_diagnostics: list[str] = Field(default_factory=list)


class AssessedEnrichedReport(AssessedReport, EnrichedReport):
    """Preserve enrichment fields and their original evidence without mutation."""
