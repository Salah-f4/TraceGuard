"""Orchestration isolation, duplicate reuse, failure circuits, and cancellation."""

import asyncio

import pytest

from traceguard.core.enrichment import enrich_report
from traceguard.core.intelligence import (
    LookupIOC,
    ProviderEvidence,
    ProviderID,
    ProviderOutcome,
    Status,
)
from traceguard.core.investigation import analyze_text


class StubProvider:
    def __init__(
        self, provider: ProviderID, status: Status = "found", *, crash: bool = False
    ) -> None:
        self.provider_id = provider
        self.status = status
        self.crash = crash
        self.calls: list[LookupIOC] = []

    async def lookup(self, ioc: LookupIOC) -> ProviderOutcome:
        self.calls.append(ioc)
        if self.crash:
            raise RuntimeError("Untrusted adapter details must not be shown.")
        return ProviderOutcome(
            provider_id=self.provider_id,
            status=self.status,
            reason="Synthetic outcome.",
            attempted=True,
            attempts=1,
            evidence=ProviderEvidence(attributes={"synthetic": True})
            if self.status == "found"
            else None,
        )


def test_fragment_duplicates_reuse_one_lookup_and_preserve_offline() -> None:
    offline = analyze_text("https://public-site.com/A#One https://public-site.com/A#Two")
    before = offline.model_dump_json()
    provider = StubProvider("virustotal")
    report = asyncio.run(enrich_report(offline, {"virustotal": provider}))
    assert len(provider.calls) == 1
    assert provider.calls[0].normalized_value == "https://public-site.com/A"
    outcomes = [r for r in report.provider_results if r.provider_id == "virustotal"]
    assert all(r.fragment_stripped for r in outcomes)
    assert [r.reused for r in outcomes] == [False, True]
    assert report.enrichment.attempts == 1
    assert report.enrichment.completeness == "partial"
    assert offline.model_dump_json() == before
    assert report.schema_version == "1.1"


@pytest.mark.parametrize("status", ["auth_error", "rate_limited"])
def test_auth_and_rate_limits_stop_only_one_provider(status: Status) -> None:
    offline = analyze_text("8.8.8.8 1.1.1.1")
    bad, good = StubProvider("virustotal", status), StubProvider("abuseipdb")
    report = asyncio.run(enrich_report(offline, {"virustotal": bad, "abuseipdb": good}))
    assert len(bad.calls) == 1
    assert len(good.calls) == 2
    assert report.enrichment.provider_availability["virustotal"] == status
    assert report.enrichment.completeness == "partial"
    assert any(r.status == "skipped_provider_unavailable" for r in report.provider_results)


@pytest.mark.parametrize("crash", [False, True])
def test_repeated_failure_opens_circuit(crash: bool) -> None:
    offline = analyze_text("one.com two.com three.com four.com")
    provider = StubProvider("virustotal", "provider_error", crash=crash)
    report = asyncio.run(enrich_report(offline, {"virustotal": provider}))
    assert len(provider.calls) == 3
    assert report.enrichment.provider_availability["virustotal"] == "circuit_open"
    assert report.enrichment.completeness == "unavailable"
    assert "Untrusted adapter details" not in report.model_dump_json()


def test_eligibility_reason_precedes_missing_key() -> None:
    report = asyncio.run(enrich_report(analyze_text("10.0.0.1 user@public-site.com 999.1.2.3"), {}))
    assert len(report.provider_results) == 9
    assert {r.status for r in report.provider_results} == {
        "skipped_non_public",
        "skipped_email",
        "skipped_invalid",
    }
    assert report.enrichment.completeness == "complete"
    assert report.enrichment.attempts == 0


def test_no_keys_unavailable() -> None:
    report = asyncio.run(enrich_report(analyze_text("8.8.8.8"), {}))
    assert report.enrichment.completeness == "unavailable"
    assert all(r.status == "disabled_missing_key" for r in report.provider_results)


def test_no_automatic_score_or_classification() -> None:
    report = asyncio.run(
        enrich_report(analyze_text("8.8.8.8"), {"virustotal": StubProvider("virustotal")})
    )
    assert "classification" not in report.model_dump_json()
    assert "risk_score" not in report.model_dump_json()


def test_cancellation_keeps_completed_results() -> None:
    async def run() -> None:
        entered = asyncio.Event()

        class SlowProvider(StubProvider):
            async def lookup(self, ioc: LookupIOC) -> ProviderOutcome:
                if self.calls:
                    entered.set()
                    await asyncio.Event().wait()
                return await super().lookup(ioc)

        provider = SlowProvider("virustotal")
        task = asyncio.create_task(
            enrich_report(
                analyze_text("8.8.8.8 1.1.1.1"),
                {"virustotal": provider},
            )
        )
        await entered.wait()
        task.cancel()
        report = await task
        statuses = [r.status for r in report.provider_results if r.provider_id == "virustotal"]
        assert statuses == ["found", "cancelled"]
        assert report.enrichment.cancelled

    asyncio.run(run())


def test_cancelled_adapter_outcome_stops_queue() -> None:
    provider = StubProvider("virustotal", "cancelled")
    report = asyncio.run(enrich_report(analyze_text("8.8.8.8 1.1.1.1"), {"virustotal": provider}))
    assert len(provider.calls) == 1
    assert report.enrichment.cancelled
