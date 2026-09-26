"""Safe diagnostic codes and counts, never response text."""

import asyncio
import json
from typing import get_args

import httpx
import pytest
from pydantic import SecretStr

from tests.ai_support import assessed, envelope, projected, valid_output
from traceguard import ai_service
from traceguard.adapters.ai.groq import GroqAdapter
from traceguard.ai_config import KEY_NAME
from traceguard.core.ai_contracts import (
    AdapterResult,
    AILimits,
    AIRequest,
    InvalidOutputReason,
    OutputValidationError,
)
from traceguard.core.ai_reporting import validate_output


@pytest.mark.parametrize("reason", get_args(InvalidOutputReason))
def test_diagnostic_categories(monkeypatch: pytest.MonkeyPatch, reason: str) -> None:
    p = projected()
    value = valid_output(p.request)
    item = value["claims"][0]
    if reason == "unknown_claim_alias":
        value["claims"][0] = "C999"
    elif reason == "duplicate_claim_alias":
        value["claims"].append(item)
    elif reason == "invalid_section_assignment":
        value["claims"] = [
            c.claim_alias for c in p.request.claims if c.destination != "ioc_findings"
        ]
    elif reason == "missing_mandatory_uncertainty":
        value["claims"] = [
            c.claim_alias for c in p.request.claims if c.destination != "uncertainties"
        ]
    elif reason == "ordering_count_limit_violation":
        value["claims"] = [item] * 81
    elif reason == "json_schema_validation_failure":
        value["untrusted"] = "synthetic-private-canary"
    elif reason == "citation_ownership_validation_failure":
        p.request.claims[0].evidence_aliases.append("E999")
    if reason not in {
        "provider_refusal",
        "missing_structured_response",
        "other_validation_failure",
    }:
        with pytest.raises(OutputValidationError) as caught:
            validate_output(assessed(), p, json.dumps(value))
        assert caught.value.reason == reason
        if reason == "unknown_claim_alias":
            assert caught.value.counts.unknown_alias_count == 1
        if reason == "duplicate_claim_alias":
            assert caught.value.counts.duplicate_count == 1
        assert "synthetic-private-canary" not in str(caught.value)
        return
    body = envelope(p.request)
    if reason == "provider_refusal":
        body["choices"][0]["message"]["refusal"] = "synthetic-private-canary"
    elif reason == "missing_structured_response":
        body["choices"][0]["message"]["content"] = None
    else:
        body["choices"][0]["message"]["tool_calls"] = [{"text": "synthetic-private-canary"}]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    result = asyncio.run(
        GroqAdapter(
            SecretStr("synthetic-test-key"), transport=httpx.MockTransport(handler)
        ).generate(p.request, AILimits())
    )
    assert result.invalid_output_reason == reason
    assert result.output is None and "synthetic-private-canary" not in result.model_dump_json()


def test_service_preserves_safe_counts_and_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(KEY_NAME, "synthetic-test-key")

    async def generate(self: GroqAdapter, request: AIRequest, limits: AILimits) -> AdapterResult:
        value = valid_output(request)
        value["claims"].append("C999")
        return AdapterResult(status="completed", output=json.dumps(value), attempts=1)

    monkeypatch.setattr(GroqAdapter, "generate", generate)
    report = assessed()
    result = asyncio.run(ai_service.run_ai(report))
    assert result.ai_reporting.invalid_output_reason == "unknown_claim_alias"
    assert result.ai_reporting.validation_counts.unknown_alias_count == 1
    assert result.ai_reporting.validation_counts.returned_claim_count > 0
    assert result.ai_reporting.origin == "deterministic_fallback"
    assert result.model_dump(exclude={"schema_version", "ai_reporting"}) == report.model_dump(
        exclude={"schema_version"}
    )
    assert "C999" not in result.model_dump_json()


def test_unexpected_validator_exception_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(KEY_NAME, "synthetic-test-key")

    async def generate(self: GroqAdapter, request: AIRequest, limits: AILimits) -> AdapterResult:
        return AdapterResult(status="completed", output="synthetic-private-canary")

    def invalid(*args: object) -> None:
        raise RuntimeError("synthetic-private-canary")

    monkeypatch.setattr(GroqAdapter, "generate", generate)
    monkeypatch.setattr(ai_service, "validate_output", invalid)
    r = asyncio.run(ai_service.run_ai(assessed()))
    assert r.ai_reporting.invalid_output_reason == "other_validation_failure"
    assert "synthetic-private-canary" not in r.model_dump_json()
