"""Flat selection regression for valid claims previously assigned wrong sections."""

import asyncio
import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from tests.unit.test_scoring import NOW, abuse, report_for, vt
from traceguard import ai_service
from traceguard.adapters.ai.groq import GroqAdapter, request_body, schema
from traceguard.ai_config import KEY_NAME
from traceguard.core.ai_contracts import AdapterResult, AILimits, AIRequest
from traceguard.core.ai_reporting import project, validate_output
from traceguard.core.scoring import assess_report


def test_eleven_valid_aliases_route_locally(monkeypatch: pytest.MonkeyPatch) -> None:
    aged = abuse(80)
    assert aged.evidence is not None
    aged.evidence.observed_at = NOW - timedelta(days=40)
    report = assess_report(report_for([vt(6), aged]), scoring_as_of=NOW)
    projection = project(report, "a" * 32)
    aliases = [c.claim_alias for c in projection.request.claims]
    assert len(aliases) == 11
    # Synthetic reproduction: all aliases were valid but in an invalid section.
    old_response = {"executive_summary": aliases}
    with pytest.raises(ValueError):
        validate_output(report, projection, json.dumps(old_response))
    flat = {"claims": list(reversed(aliases))}
    routed = validate_output(report, projection, json.dumps(flat))
    for section, claims in routed.items():
        expected = {
            projection.candidates[c.claim_alias].rendered.claim_id
            for c in projection.request.claims
            if c.destination == section
        }
        assert {c.claim_id for c in claims} == expected
    assert sum(map(len, routed.values())) == 11
    assert list(schema()["properties"]) == ["claims"]
    body = json.dumps(request_body(projection.request, AILimits()))
    assert all(section not in body for section in routed)
    monkeypatch.setenv(KEY_NAME, "synthetic-key")

    async def generate(self: GroqAdapter, request: AIRequest, limits: AILimits) -> AdapterResult:
        return AdapterResult(
            status="completed",
            attempts=1,
            output=json.dumps({"claims": [c.claim_alias for c in reversed(request.claims)]}),
        )

    monkeypatch.setattr(GroqAdapter, "generate", generate)
    result = asyncio.run(ai_service.run_ai(report))
    assert result.ai_reporting.validation_counts.returned_claim_count == 11
    assert result.ai_reporting.status == "completed"
    assert result.ai_reporting.origin == "ai_assisted"
    assert result.model_dump(exclude={"ai_reporting", "schema_version"}) == report.model_dump(
        exclude={"schema_version"}
    )


def test_destination_is_frozen_and_revalidated() -> None:
    report = assess_report(report_for([vt(6)]), scoring_as_of=NOW)
    p = project(report, "a" * 32)
    with pytest.raises(ValidationError):
        p.request.claims[0].destination = "correlations"
    p.request.claims[0] = p.request.claims[0].model_copy(update={"destination": "correlations"})
    with pytest.raises(ValueError, match="citation_ownership_validation_failure"):
        validate_output(
            report, p, json.dumps({"claims": [c.claim_alias for c in p.request.claims]})
        )
