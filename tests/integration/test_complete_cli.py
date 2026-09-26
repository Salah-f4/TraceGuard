"""Whole CLI pipeline with real parsers/scoring/AI validation and mocked HTTP only."""

import hashlib
import json

import httpx
import pytest
from pydantic import SecretStr
from typer.testing import CliRunner

from tests.support import Clock, body_for
from traceguard import bootstrap
from traceguard.adapters.ai import groq
from traceguard.adapters.cli.app import app
from traceguard.adapters.intelligence.http import LookupHTTP, Runtime
from traceguard.ai_config import KEY_NAME, MODEL
from traceguard.config import ENV_NAMES, Credentials
from traceguard.core.ai_contracts import AIEnrichedReport
from traceguard.core.intelligence import LookupIOC, ProviderID
from traceguard.core.models import IOCType
from traceguard.core.scoring import assess_report


@pytest.mark.parametrize("case", ["success", "refused", "unknown", "missing_uncertainty"])
def test_complete_mocked_pipeline(
    monkeypatch: pytest.MonkeyPatch, credentials: Credentials, case: str
) -> None:
    value = hashlib.sha256(b"TraceGuard harmless release fixture").hexdigest()
    calls: list[tuple[str, str]] = []
    clock = Clock()
    for provider, name in ENV_NAMES.items():
        token = credentials.get(provider)
        assert token is not None
        monkeypatch.setenv(name, token.get_secret_value())
    monkeypatch.setenv(KEY_NAME, "generated-inert-groq-canary")

    def factory(provider: ProviderID, configured: Credentials, runtime: Runtime) -> LookupHTTP:
        def respond(request: httpx.Request) -> httpx.Response:
            calls.append((provider, request.method))
            if provider == "virustotal":
                assert request.method == "GET" and "/files/" in request.url.path
                body = body_for(provider, LookupIOC(type=IOCType.SHA256, normalized_value=value))
                return httpx.Response(200, json=body)
            assert provider == "urlhaus" and request.method == "POST"
            assert value in request.content.decode()
            return httpx.Response(200, json={"query_status": "no_results"})

        return LookupHTTP(provider, configured, runtime, transport=httpx.MockTransport(respond))

    original = groq.GroqAdapter

    def ai_factory(key: SecretStr) -> groq.GroqAdapter:
        def respond(request: httpx.Request) -> httpx.Response:
            calls.append(("groq", request.method))
            body = json.loads(request.content)
            assert body["model"] == MODEL and body["stream"] is False and "tools" not in body
            assert body["response_format"]["json_schema"]["strict"] is True
            facts = json.loads(body["messages"][1]["content"])
            assert value not in request.content.decode()
            assert "generated-inert-groq-canary" not in request.content.decode()
            selected = [c[0] for c in facts["c"]]
            if case == "unknown":
                selected.append("C999")
            if case == "missing_uncertainty":
                selected = [c[0] for c in facts["c"] if facts["t"][c[1]][1] != "uncertainty"]
            message = {"role": "assistant", "content": json.dumps({"claims": selected})}
            if case == "refused":
                message["refusal"] = "synthetic refusal"
            return httpx.Response(
                200,
                json={
                    "model": MODEL,
                    "choices": [{"finish_reason": "stop", "message": message}],
                    "usage": {"prompt_tokens": 500, "completion_tokens": 100, "total_tokens": 600},
                },
            )

        return original(key, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(bootstrap, "LookupHTTP", factory)
    monkeypatch.setattr(bootstrap, "Runtime", clock.runtime)
    monkeypatch.setattr(groq, "GroqAdapter", ai_factory)
    result = CliRunner().invoke(
        app, ["analyze", "--text", value, "--enrich", "--ai", "--format", "json"]
    )
    assert result.exit_code == 0
    report = AIEnrichedReport.model_validate_json(result.stdout)
    expected = {
        "success": "completed",
        "refused": "refused",
        "unknown": "invalid_output",
        "missing_uncertainty": "invalid_output",
    }[case]
    assert report.ai_reporting.status == expected
    assert report.ai_reporting.attempts == 1
    assert calls == [("virustotal", "GET"), ("urlhaus", "POST"), ("groq", "POST")]
    recomputed = assess_report(report, scoring_as_of=report.assessments[0].scoring_as_of)
    assert report.assessments == recomputed.assessments
    assert report.relationships == recomputed.relationships
    assert not credentials.contains(result.output)
    assert "generated-inert-groq-canary" not in result.output
    if case == "success":
        assert report.ai_reporting.validation_counts.returned_claim_count > 0
        assert report.ai_reporting.origin == "ai_assisted"
    else:
        assert report.ai_reporting.origin == "deterministic_fallback"
