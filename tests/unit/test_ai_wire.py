"""Compact, value-free wire protocol budget and ownership regressions."""

import asyncio
import json

import pytest

from tests.ai_support import valid_output
from tests.unit.test_scoring import NOW, abuse, found, report_for, vt
from traceguard.adapters.ai.groq import compact, fits_budget, request_body, token_estimates
from traceguard.ai_service import run_ai
from traceguard.core.ai_contracts import AILimits
from traceguard.core.ai_reporting import project, validate_output
from traceguard.core.assessment import AssessedReport
from traceguard.core.intelligence import ProviderOutcome
from traceguard.core.scoring import assess_report


def smoke_report() -> AssessedReport:
    outcomes = [
        vt(0, 0, harmless=75),
        abuse(0, 200),
        ProviderOutcome(provider_id="urlhaus", ioc_index=0, status="not_found", reason="Synthetic"),
        found(
            "virustotal",
            {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 75}},
            index=1,
        ),
        ProviderOutcome(
            provider_id="abuseipdb", ioc_index=1, status="skipped_unsupported", reason="Synthetic"
        ),
        ProviderOutcome(provider_id="urlhaus", ioc_index=1, status="not_found", reason="Synthetic"),
    ]
    return assess_report(
        report_for(outcomes, "1.1.1.1 https://www.cloudflare.com/"), scoring_as_of=NOW
    )


def test_two_ioc_smoke_fits_and_citations_resolve() -> None:
    report = smoke_report()
    p = project(report, "a" * 32)
    body = request_body(p.request, AILimits())
    wire = compact(body)
    assert fits_budget(p.request, AILimits())
    d = token_estimates(p.request, AILimits())
    assert d["input_total"] < 4000 and d["output_reserve"] == 1000
    assert (
        sum(
            d[k]
            for k in ("system_prompt", "schema", "projection", "catalogue", "framing_and_escaping")
        )
        == d["input_total"]
    )
    assert {i.id for i in p.request.iocs} == {"I1", "I2"}
    for forbidden in [
        "1.1.1.1",
        "cloudflare",
        "/assessments",
        "observed_at",
        "normalized_value",
        "occurrences",
    ]:
        assert forbidden not in wire
    for a in report.assessments:
        assert a.ioc_id not in wire
        for c in a.contributions:
            assert c.reference.evidence_id not in wire
    selected = validate_output(report, p, json.dumps(valid_output(p.request)))
    for items in selected.values():
        for claim in items:
            owners = {
                a.ioc_id
                for a in report.assessments
                if any(c.reference.evidence_id in claim.evidence_ids for c in a.contributions)
            }
            assert set(claim.ioc_ids) <= owners
    assert all(type(v) is int for v in d.values())


def test_altered_local_ownership_rejected() -> None:
    report = smoke_report()
    p = project(report, "a" * 32)
    p.request.claims[0].evidence_aliases.append("E999")
    with pytest.raises(ValueError, match="citation_ownership_validation_failure"):
        validate_output(report, p, json.dumps(valid_output(p.request)))


def test_large_projection_skips_without_truncation() -> None:
    text = " ".join(f"1.1.1.{n}" for n in range(1, 21))
    outcomes = [
        found("abuseipdb", {"abuseConfidenceScore": 0, "totalReports": 1}, index=n)
        for n in range(20)
    ]
    report = assess_report(report_for(outcomes, text), scoring_as_of=NOW)
    before = report.model_dump(exclude={"schema_version"})
    final = asyncio.run(run_ai(report))
    assert final.ai_reporting.status == "skipped_budget" and final.ai_reporting.attempts == 0
    assert final.model_dump(exclude={"schema_version", "ai_reporting"}) == before
    assert len(final.ai_reporting.sections["ioc_findings"]) == 20
