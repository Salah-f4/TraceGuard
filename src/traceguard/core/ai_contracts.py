"""Provider-neutral constrained reporting contracts; no I/O or credentials."""

from datetime import datetime
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from traceguard.core.assessment import AssessedEnrichedReport, AssessedReport
from traceguard.core.intelligence import ProviderID, Status

Section = Literal[
    "executive_summary",
    "ioc_findings",
    "correlations",
    "uncertainties",
    "prioritized_investigation_steps",
    "analyst_notes",
]
SECTIONS: tuple[Section, ...] = (
    "executive_summary",
    "ioc_findings",
    "correlations",
    "uncertainties",
    "prioritized_investigation_steps",
    "analyst_notes",
)
CAPS = dict(zip(SECTIONS, (6, 20, 20, 40, 20, 20), strict=True))
Kind = Literal["fact", "interpretation", "uncertainty", "recommended_step"]
AIStatus = Literal[
    "completed",
    "disabled_missing_key",
    "invalid_configuration",
    "skipped_no_citable_evidence",
    "privacy_blocked",
    "skipped_budget",
    "auth_error",
    "rate_limited",
    "timeout",
    "network_error",
    "provider_error",
    "refused",
    "invalid_output",
    "response_too_large",
    "cancelled",
]
Priority = Literal["high", "medium", "routine"]
Alias = Annotated[str, Field(pattern=r"^[IERC][1-9][0-9]*$")]
Nonce = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Selection(Strict):
    claim_alias: Alias
    kind: Kind
    ioc_aliases: list[Alias]
    evidence_aliases: list[Alias]
    relation_aliases: list[Alias]


class AIOutput(Strict):
    claims: list[Annotated[str, Field(pattern=r"^C[1-9][0-9]*$")]]


class ClaimSpec(Selection):
    template_key: Literal[
        "assessment_snapshot",
        "provider_adverse",
        "no_adverse_or_no_match",
        "partial_coverage",
        "stale_or_ambiguous",
        "conflicting_evidence",
        "corroboration",
        "recorded_relationship",
        "review_existing_telemetry",
        "reconcile_existing_evidence",
        "capture_local_context",
        "reputation_limit",
        "analyst_caution",
    ]
    destination: Section
    mandatory: bool


class IOCView(Strict):
    id: Alias
    type: Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]
    risk: int = Field(ge=0, le=100)
    label: Literal["unknown", "low", "suspicious", "malicious"]
    confidence: int = Field(ge=0, le=95)


class EvidenceView(Strict):
    id: Alias
    provider: ProviderID
    status: Status
    iocs: list[Alias]
    # Numeric fields required by approved provider rules only.
    numbers: dict[
        Literal[
            "malicious",
            "suspicious",
            "harmless",
            "abuseConfidenceScore",
            "totalReports",
            "url_count",
        ],
        Annotated[int, Field(ge=0, le=2**53)],
    ]
    scope: Literal["exact", "host"]
    freshness: int = Field(ge=0, le=100)
    weighted_score: int = Field(ge=0, le=100)
    url_status: Literal["online", "offline", "other_or_missing"]


class RelationView(Strict):
    id: Alias
    kind: Literal["url_has_host", "same_lookup", "same_source_line", "same_input"]
    iocs: list[Alias]


class AIRequest(Strict):
    input_version: Literal["ai-input-v3"] = "ai-input-v3"
    request_nonce: Nonce
    # Only constructed, numeric/enum views; never original report dictionaries.
    iocs: list[IOCView]
    evidence: list[EvidenceView]
    relations: list[RelationView]
    claims: list[ClaimSpec]


class AILimits(Strict):
    input_tokens: int = Field(default=4000, ge=1, le=4000)
    output_tokens: int = Field(default=1000, ge=1, le=1000)
    max_bytes: int = Field(default=65536, ge=1, le=65536)
    cost_microusd: int = Field(default=50000, ge=0, le=50000)


class Usage(Strict):
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)


InvalidOutputReason = Literal[
    "provider_refusal",
    "missing_structured_response",
    "json_schema_validation_failure",
    "unknown_claim_alias",
    "duplicate_claim_alias",
    "invalid_section_assignment",
    "citation_ownership_validation_failure",
    "missing_mandatory_uncertainty",
    "ordering_count_limit_violation",
    "other_validation_failure",
]


class ValidationCounts(Strict):
    returned_claim_count: int = Field(default=0, ge=0)
    unknown_alias_count: int = Field(default=0, ge=0)
    duplicate_count: int = Field(default=0, ge=0)


class OutputValidationError(ValueError):
    def __init__(self, reason: InvalidOutputReason, counts: ValidationCounts | None = None):
        super().__init__(reason)
        self.reason = reason
        self.counts = counts or ValidationCounts()


class AdapterResult(Strict):
    status: AIStatus
    invalid_output_reason: InvalidOutputReason | None = None
    validation_counts: ValidationCounts = Field(default_factory=ValidationCounts)
    output: str | None = Field(default=None, repr=False)
    attempts: int = 0
    usage: Usage | None = None


class AIAdapter(Protocol):
    async def generate(self, request: AIRequest, limits: AILimits) -> AdapterResult: ...


class RenderedClaim(Strict):
    claim_id: str
    kind: Kind
    text: str
    ioc_ids: list[str]
    evidence_ids: list[str]
    relation_refs: list[str] = Field(default_factory=list)
    template_key: str
    action_priority: Priority | None = None
    local_pointers: list[str] = Field(default_factory=list)
    origin: Literal["ai_assisted", "deterministic_fallback"] = "deterministic_fallback"


class AIReporting(Strict):
    requested: Literal[True] = True
    status: AIStatus
    invalid_output_reason: InvalidOutputReason | None = None
    validation_counts: ValidationCounts = Field(default_factory=ValidationCounts)
    origin: Literal["ai_assisted", "deterministic_fallback"]
    provider: Literal["groq"] = "groq"
    model: Literal["qwen/qwen3.8-27b"] = "qwen/qwen3.8-27b"
    prompt_version: Literal["report-v3"] = "report-v3"
    catalogue_version: Literal["catalogue-v1"] = "catalogue-v1"
    projection_version: Literal["ai-input-v3"] = "ai-input-v3"
    started_at: datetime
    completed_at: datetime
    attempts: int
    usage: Usage | None
    projected_ioc_ids: list[str]
    omitted_iocs: dict[str, str]
    token_estimates: dict[str, int] = Field(default_factory=dict)
    sections: dict[Section, list[RenderedClaim]]


class AIReport(AssessedReport):
    schema_version: str = "1.3"
    ai_reporting: AIReporting


class AIEnrichedReport(AIReport, AssessedEnrichedReport):
    """Add reporting without changing any deterministic findings."""
