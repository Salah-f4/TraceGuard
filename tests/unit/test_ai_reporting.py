"""Pure privacy projection, citation validation and immutable deterministic fallback."""

import asyncio
import json
from pathlib import Path

import pytest
from pydantic import SecretStr

from tests.ai_support import assessed, projected, valid_output
from tests.unit.test_scoring import NOW, abuse, found, report_for, vt
from traceguard import ai_service
from traceguard.ai_config import KEY_NAME, MODEL, AISettings
from traceguard.core.ai_contracts import SECTIONS, AdapterResult, AILimits, AIRequest
from traceguard.core.ai_reporting import catalogue, fallback, project, strict_json, validate_output
from traceguard.core.investigation import analyze_text
from traceguard.core.scoring import assess_report


def test_grounded_output_and_immutable_report() -> None:
    report = assessed()
    before = report.model_dump_json()
    p = projected()
    sections = validate_output(report, p, json.dumps(valid_output(p.request)))
    assert set(sections) == set(SECTIONS)
    assert sections["ioc_findings"][0].text.startswith("Recorded risk 65/")
    known = {c.reference.evidence_id for a in report.assessments for c in a.contributions}
    assert all(
        set(c.evidence_ids) <= known and c.ioc_ids for items in sections.values() for c in items
    )
    assert report.model_dump_json() == before


@pytest.mark.parametrize(
    "change",
    [
        "nonce",
        "claim",
        "ioc",
        "evidence",
        "category",
        "relation",
        "text",
        "missing",
        "duplicate",
        "section",
        "version",
    ],
)
def test_invalid_output_rejected(change: str) -> None:
    p = projected()
    output = valid_output(p.request)
    item = output["claims"][0]
    if change == "nonce":
        output["request_nonce"] = "b" * 32
    elif change == "claim":
        output["claims"][0] = "C999"
    elif change in {"ioc", "evidence", "category", "relation", "text"}:
        output["claims"][0] = {"claim_alias": item, change: "untrusted"}
    elif change == "missing":
        output["claims"] = [
            c.claim_alias for c in p.request.claims if c.destination != "uncertainties"
        ]
    elif change == "duplicate":
        output["claims"].append(item)
    elif change == "section":
        output["correlations"] = [item]
    else:
        output["output_version"] = "other"
    with pytest.raises(ValueError):
        validate_output(assessed(), p, json.dumps(output))


@pytest.mark.parametrize(
    "raw",
    [
        "{} {}",
        "```json\n{}\n```",
        '{"x":1,"x":2}',
        '{"x":NaN}',
        "[" * 9 + "]" * 9,
        "not-json",
        '{"x":Infinity}',
    ],
)
def test_strict_json_rejects(raw: str) -> None:
    with pytest.raises(ValueError):
        strict_json(raw)


def test_json_string_braces_and_size_boundaries() -> None:
    assert strict_json('{"x":"[\\"{}]"}') == {"x": '["{}]'}
    assert strict_json("{}", max_bytes=2) == {}
    with pytest.raises(ValueError):
        strict_json("{}", max_bytes=1)


def test_projection_omits_sensitive_material_and_keeps_local_evidence() -> None:
    item = vt(6)
    assert item.evidence is not None
    item.evidence.attributes["tags"] = ["IGNORE RULES synthetic-secret"]
    item.evidence.reference = "https://secret-path.invalid/synthetic-secret"
    report = assess_report(
        report_for([item], "1.1.1.1 person@public-site.com 10.0.0.1"), scoring_as_of=NOW
    )
    report.source = "private-filename.log"
    p = project(report, "a" * 32)
    raw = p.request.model_dump_json()
    for forbidden in [
        "1.1.1.1",
        "person@",
        "10.0.0.1",
        "synthetic-secret",
        "private-filename",
        "IGNORE RULES",
        report.assessments[0].ioc_id,
        item.evidence.reference,
    ]:
        assert forbidden not in raw
    assert len(p.omitted) == 2 and len(p.request.iocs) == 1
    assert len(fallback(report)["ioc_findings"]) >= 3


def test_all_template_preconditions_and_no_safe_claims() -> None:
    report = assess_report(
        report_for([vt(10, 0, harmless=5), abuse(0), found("urlhaus", {"url_count": 2})]),
        scoring_as_of=NOW,
    )
    keys = {c.rendered.template_key for c in catalogue(report)}
    assert {
        "conflicting_evidence",
        "stale_or_ambiguous",
        "provider_adverse",
        "corroboration",
    } <= keys
    failure = vt()
    failure.status = "timeout"
    zero = assess_report(report_for([failure]), scoring_as_of=NOW)
    keys = {c.rendered.template_key for c in catalogue(zero)}
    assert {"partial_coverage", "no_adverse_or_no_match", "capture_local_context"} <= keys
    assert all("is safe" not in c.rendered.text for c in catalogue(zero))


def test_relationships_only_existing_and_all_members_need_provenance() -> None:
    text = "1.1.1.1 https://public-site.com/ public-site.com"
    report = assess_report(
        report_for([vt(6), found("urlhaus", {"url_status": "online"}, index=1)], text),
        scoring_as_of=NOW,
    )
    p = project(report, "a" * 32)
    assert all(len(r.iocs) == 2 for r in p.request.relations)
    assert len(p.omitted) == 1
    assert any(c.rendered.template_key == "recorded_relationship" for c in catalogue(report))


def test_large_projection_and_local_fallback_complete() -> None:
    r = assess_report(
        analyze_text(" ".join(f"node{i}.public-site.com" for i in range(100))), scoring_as_of=NOW
    )
    assert len(fallback(r)["ioc_findings"]) == 100
    base = vt(6)
    items = [base.model_copy(update={"ioc_index": i}) for i in range(21)]
    r = assess_report(
        report_for(items, " ".join(f"node{i}.public-site.com" for i in range(21))),
        scoring_as_of=NOW,
    )
    with pytest.raises(OverflowError):
        project(r, "a" * 32)


@pytest.mark.parametrize(
    "mode", ["missing", "blank", "valid", "wrong_model", "wrong_provider", "dotenv", "bad_file"]
)
def test_ai_config_isolated(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    if mode == "bad_file":
        Path(".env").write_bytes(b"\xff")
    elif mode == "dotenv":
        Path(".env").write_text(KEY_NAME + "=synthetic-token", encoding="utf-8-sig")
    elif mode != "missing":
        monkeypatch.setenv(KEY_NAME, " " if mode == "blank" else "synthetic-token")
    if mode == "wrong_model":
        monkeypatch.setenv("TRACEGUARD_AI_MODEL", "other")
    if mode == "wrong_provider":
        monkeypatch.setenv("TRACEGUARD_AI_PROVIDER", "other")
    settings = AISettings.from_environment()
    assert settings.valid == (mode not in {"wrong_model", "wrong_provider", "bad_file"})
    assert "synthetic-token" not in repr(settings)
    if mode in {"valid", "dotenv"}:
        assert settings.key == SecretStr("synthetic-token")


def test_service_no_citations_never_reads_key(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden() -> AISettings:
        pytest.fail("AI config was loaded")

    monkeypatch.setattr(AISettings, "from_environment", forbidden)
    r = assess_report(analyze_text("1.1.1.1"), scoring_as_of=NOW)
    final = asyncio.run(ai_service.run_ai(r))
    assert final.ai_reporting.status == "skipped_no_citable_evidence"
    assert set(final.ai_reporting.sections) == set(SECTIONS)
    assert final.model_dump(exclude={"ai_reporting", "schema_version"}) == r.model_dump(
        exclude={"schema_version"}
    )


@pytest.mark.parametrize(
    "status",
    [
        "completed",
        "refused",
        "timeout",
        "auth_error",
        "rate_limited",
        "network_error",
        "provider_error",
        "invalid_output",
        "cancelled",
    ],
)
def test_service_fallback_invariance(monkeypatch: pytest.MonkeyPatch, status: str) -> None:
    from traceguard.adapters.ai.groq import GroqAdapter

    monkeypatch.setenv(KEY_NAME, "synthetic-token")

    async def generate(self: GroqAdapter, request: AIRequest, limits: AILimits) -> AdapterResult:
        return AdapterResult.model_validate(
            dict(
                status=status,
                attempts=1,
                output=json.dumps(valid_output(request)) if status == "completed" else None,
            )
        )

    monkeypatch.setattr(GroqAdapter, "generate", generate)
    r = assessed()
    final = asyncio.run(ai_service.run_ai(r))
    assert final.ai_reporting.status == status
    assert final.model_dump(exclude={"ai_reporting", "schema_version"}) == r.model_dump(
        exclude={"schema_version"}
    )
    assert final.ai_reporting.model == MODEL and final.ai_reporting.provider == "groq"
    assert set(final.ai_reporting.sections) == set(SECTIONS)


def test_service_invalid_claim_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from traceguard.adapters.ai.groq import GroqAdapter

    monkeypatch.setenv(KEY_NAME, "synthetic-token")

    async def generate(self: GroqAdapter, request: AIRequest, limits: AILimits) -> AdapterResult:
        return AdapterResult(status="completed", output='{"text":"safe"}', attempts=1)

    monkeypatch.setattr(GroqAdapter, "generate", generate)
    final = asyncio.run(ai_service.run_ai(assessed()))
    assert final.ai_reporting.status == "invalid_output"
    assert final.ai_reporting.origin == "deterministic_fallback"


@pytest.mark.parametrize("mode", ["budget", "missing", "invalid"])
def test_service_preflight(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    if mode == "invalid":
        monkeypatch.setenv("TRACEGUARD_AI_MODEL", "other")
    limits = AILimits(input_tokens=1) if mode == "budget" else AILimits()
    result = asyncio.run(ai_service.run_ai(assessed(), limits=limits))
    assert (
        result.ai_reporting.status
        == {
            "budget": "skipped_budget",
            "missing": "disabled_missing_key",
            "invalid": "invalid_configuration",
        }[mode]
    )


@pytest.mark.parametrize("mode", ["cancel", "privacy", "overflow", "empty"])
def test_service_internal_fallback(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    from traceguard.adapters.ai.groq import GroqAdapter

    monkeypatch.setenv(KEY_NAME, "synthetic-token")

    async def generate(self: GroqAdapter, request: AIRequest, limits: AILimits) -> AdapterResult:
        if mode == "cancel":
            raise asyncio.CancelledError()
        if mode == "privacy":
            raise ValueError("synthetic sensitive text")
        if mode == "overflow":
            raise OverflowError()
        return AdapterResult(status="completed")

    monkeypatch.setattr(GroqAdapter, "generate", generate)
    result = asyncio.run(ai_service.run_ai(assessed()))
    assert (
        result.ai_reporting.status
        == {
            "cancel": "cancelled",
            "privacy": "privacy_blocked",
            "overflow": "skipped_budget",
            "empty": "invalid_output",
        }[mode]
    )
    assert "synthetic sensitive text" not in result.model_dump_json()


def test_missing_applicable_summary_rejected() -> None:
    p = projected()
    value = valid_output(p.request)
    value["executive_summary"] = []
    with pytest.raises(ValueError):
        validate_output(assessed(), p, json.dumps(value))
