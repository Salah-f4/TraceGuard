"""Provider-neutral opt-in orchestration, independent of CLI and HTTPX."""

import asyncio
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Literal

from traceguard.core.eligibility import eligible
from traceguard.core.intelligence import (
    CAPABILITIES,
    PROVIDERS,
    EnrichedReport,
    EnrichmentSummary,
    LookupIOC,
    ProviderID,
    ProviderOutcome,
)
from traceguard.core.models import AnalysisReport
from traceguard.core.ports import IntelligenceProvider

_FAILURES = {
    "auth_error",
    "rate_limited",
    "timeout",
    "network_error",
    "provider_error",
    "invalid_response",
    "response_too_large",
    "skipped_budget",
    "skipped_provider_unavailable",
    "disabled_missing_key",
    "cancelled",
}


async def enrich_report(
    report: AnalysisReport,
    providers: Mapping[ProviderID, IntelligenceProvider],
    *,
    utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> EnrichedReport:
    outcomes: dict[tuple[int, ProviderID], ProviderOutcome] = {}
    queues: dict[ProviderID, list[tuple[int, LookupIOC, bool]]] = {p: [] for p in PROVIDERS}
    availability: dict[str, str] = {
        p: "enabled" if p in providers else "missing_key" for p in PROVIDERS
    }
    cancelled = False
    for index, result in enumerate(report.results):
        candidate = LookupIOC(type=result.type, normalized_value=result.normalized_value)
        decision = eligible(candidate)
        status = decision.status
        reason = decision.reason
        if not result.is_valid:
            status, reason = "skipped_invalid", "Invalid offline indicator."
        for provider in PROVIDERS:
            pair_status, pair_reason = status, reason
            if pair_status is None and result.type not in CAPABILITIES[provider]:
                pair_status, pair_reason = (
                    "skipped_unsupported",
                    "Provider does not support this type.",
                )
            if pair_status is None and provider not in providers:
                pair_status, pair_reason = "disabled_missing_key", "Provider key is not configured."
            if pair_status is not None:
                outcomes[index, provider] = ProviderOutcome(
                    provider_id=provider,
                    ioc_index=index,
                    status=pair_status,
                    reason=pair_reason,
                    completed_at=utcnow(),
                )
            else:
                assert decision.lookup is not None
                queues[provider].append((index, decision.lookup, decision.fragment_stripped))

    async def worker(provider: ProviderID) -> None:
        cache: dict[tuple[str, str], ProviderOutcome] = {}
        stopped = False
        failures = 0
        for index, lookup, fragment_stripped in queues[provider]:
            cache_key = (lookup.type.value, lookup.normalized_value)
            if cache_key in cache:
                result = cache[cache_key].model_copy(deep=True)
                result.reused = True
                result.attempted = False
                result.attempts = 0
            elif stopped:
                result = ProviderOutcome(
                    provider_id=provider,
                    status="skipped_provider_unavailable",
                    reason="Provider disabled for the remainder of this run.",
                    completed_at=utcnow(),
                )
            else:
                await asyncio.sleep(0)
                try:
                    result = await providers[provider].lookup(lookup)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # Never expose adapter exception text (may contain credentials).
                    result = ProviderOutcome(
                        provider_id=provider,
                        status="provider_error",
                        reason="Provider adapter failed.",
                        completed_at=utcnow(),
                    )
                cache[cache_key] = result.model_copy(deep=True)
                if result.status in {"auth_error", "rate_limited"}:
                    stopped = True
                    availability[provider] = result.status
                if result.status in {"timeout", "network_error", "provider_error"}:
                    failures += 1
                    if failures >= 3:
                        stopped = True
                        availability[provider] = "circuit_open"
                else:
                    failures = 0
            result.ioc_index = index
            result.fragment_stripped = fragment_stripped
            outcomes[index, provider] = result
            if result.status == "cancelled":
                raise asyncio.CancelledError

    tasks = [asyncio.create_task(worker(provider)) for provider in PROVIDERS if queues[provider]]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        cancelled = True
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    for provider, queue in queues.items():
        for index, _, stripped in queue:
            if (index, provider) not in outcomes:
                outcomes[index, provider] = ProviderOutcome(
                    provider_id=provider,
                    ioc_index=index,
                    status="cancelled",
                    reason="Enrichment was interrupted.",
                    fragment_stripped=stripped,
                    completed_at=utcnow(),
                )
    results = [
        outcomes[index, provider] for index in range(len(report.results)) for provider in PROVIDERS
    ]
    counts = Counter(item.status for item in results)
    failed = any(item.status in _FAILURES for item in results)
    usable = any(item.status in {"found", "not_found"} for item in results)
    completeness: Literal["complete", "partial", "unavailable"] = (
        "partial" if failed and usable else "unavailable" if failed else "complete"
    )
    summary = EnrichmentSummary(
        completeness=completeness,
        completed_at=utcnow(),
        provider_availability=availability,
        status_counts={str(key): value for key, value in counts.items()},
        attempts=sum(item.attempts for item in results),
        cancelled=cancelled,
    )
    return EnrichedReport(
        **{**report.model_dump(), "schema_version": "1.1"},
        enrichment=summary,
        provider_results=results,
    )
