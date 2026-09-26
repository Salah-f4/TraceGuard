"""Provider-neutral enrichment contracts. No credentials or HTTP objects."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from traceguard.core.models import AnalysisReport, IOCType

ProviderID = Literal["virustotal", "abuseipdb", "urlhaus"]
PROVIDERS: tuple[ProviderID, ...] = ("virustotal", "abuseipdb", "urlhaus")
Status = Literal[
    "found",
    "not_found",
    "skipped_invalid",
    "skipped_unsupported",
    "skipped_email",
    "skipped_non_public",
    "skipped_sensitive_url",
    "skipped_url_query",
    "skipped_special_use_domain",
    "disabled_missing_key",
    "auth_error",
    "rate_limited",
    "timeout",
    "network_error",
    "provider_error",
    "invalid_response",
    "response_too_large",
    "skipped_budget",
    "skipped_provider_unavailable",
    "cancelled",
]
CAPABILITIES: dict[ProviderID, frozenset[IOCType]] = {
    "virustotal": frozenset(set(IOCType) - {IOCType.EMAIL}),
    "abuseipdb": frozenset({IOCType.IPV4, IOCType.IPV6}),
    "urlhaus": frozenset({IOCType.IPV4, IOCType.DOMAIN, IOCType.URL, IOCType.MD5, IOCType.SHA256}),
}
Attribute = str | int | bool | list[str] | dict[str, int] | None


class LookupIOC(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    type: IOCType
    normalized_value: str


class ProviderEvidence(BaseModel):
    attributes: dict[str, Attribute] = Field(default_factory=dict)
    observed_at: datetime | None = None
    observed_at_original: str | int | None = None
    reference: str | None = None


class ProviderOutcome(BaseModel):
    provider_id: ProviderID
    ioc_index: int | None = None
    status: Status
    reason: str
    attempted: bool = False
    attempts: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    fetched_at: datetime | None = None
    http_status: int | None = None
    retry_after: float | None = None
    fragment_stripped: bool = False
    reused: bool = False
    evidence: ProviderEvidence | None = None


class EnrichmentSummary(BaseModel):
    requested: bool = True
    completeness: Literal["complete", "partial", "unavailable"]
    completed_at: datetime
    provider_availability: dict[str, str]
    status_counts: dict[str, int]
    attempts: int
    attempt_limit: int = 30
    deadline_seconds: float = 120
    cancelled: bool = False


class EnrichedReport(AnalysisReport):
    schema_version: str = "1.1"
    enrichment: EnrichmentSummary
    provider_results: list[ProviderOutcome]
