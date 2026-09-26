"""Golden approved heuristics, invariants and retained-evidence contract tests."""

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from typing import get_args

import pytest

from traceguard.adapters.cli.reporting import render_report
from traceguard.core.assessment import AssessedEnrichedReport, IOCassessment
from traceguard.core.intelligence import (
    PROVIDERS,
    Attribute,
    EnrichedReport,
    EnrichmentSummary,
    ProviderEvidence,
    ProviderID,
    ProviderOutcome,
    Status,
)
from traceguard.core.investigation import analyze_text
from traceguard.core.scoring import assess_report, freshness, label_for

NOW = datetime(2026, 9, 25, tzinfo=UTC)


def found(
    provider: ProviderID,
    attrs: dict[str, Attribute],
    *,
    index: int = 0,
    observed: datetime | None = NOW,
) -> ProviderOutcome:
    return ProviderOutcome(
        provider_id=provider,
        ioc_index=index,
        status="found",
        reason="Mock report",
        fetched_at=NOW,
        evidence=ProviderEvidence(attributes=attrs, observed_at=observed),
    )


def vt(m: int | None = None, s: int | None = None, **stats: int) -> ProviderOutcome:
    if m is not None:
        stats["malicious"] = m
    if s is not None:
        stats["suspicious"] = s
    return found("virustotal", {"last_analysis_stats": stats, "report_id": "1.1.1.1"})


def abuse(a: int, reports: int = 1) -> ProviderOutcome:
    return found("abuseipdb", {"abuseConfidenceScore": a, "totalReports": reports})


def report_for(outcomes: list[ProviderOutcome], text: str = "1.1.1.1") -> EnrichedReport:
    offline = analyze_text(text)
    return EnrichedReport(
        **offline.model_dump(exclude={"schema_version"}),
        enrichment=EnrichmentSummary(
            completeness="complete",
            completed_at=NOW,
            provider_availability={},
            status_counts={},
            attempts=0,
        ),
        provider_results=outcomes,
    )


def score(outcomes: list[ProviderOutcome], text: str = "1.1.1.1") -> IOCassessment:
    return assess_report(report_for(outcomes, text), scoring_as_of=NOW).assessments[0]


@pytest.mark.parametrize(
    ("outcomes", "text", "expected"),
    [
        (
            [
                ProviderOutcome(provider_id=p, ioc_index=0, status="not_found", reason="No match")
                for p in PROVIDERS
            ],
            "1.1.1.1",
            (0, "unknown", 0),
        ),
        ([vt(0, 0, harmless=56, undetected=33), abuse(0, 58)], "1.1.1.1", (0, "unknown", 0)),
        ([vt(1)], "1.1.1.1", (20, "low", 40)),
        (
            [found("urlhaus", {"url_status": "online"})],
            "https://public-site.com/",
            (71, "malicious", 67),
        ),
        ([found("urlhaus", {"url_count": 500})], "public-site.com", (22, "low", 33)),
        ([vt(6), abuse(80, 20)], "1.1.1.1", (70, "malicious", 80)),
        ([vt(10), abuse(0, 0)], "1.1.1.1", (80, "malicious", 70)),
        (
            [found("urlhaus", {}, observed=NOW - timedelta(days=200))],
            "a" * 64,
            (47, "suspicious", 45),
        ),
        (
            [vt(10), abuse(95, 30), found("urlhaus", {"url_count": 2})],
            "1.1.1.1",
            (90, "malicious", 95),
        ),
        (
            [
                found(
                    "virustotal",
                    {"report_id": "1.1.1.1", "last_analysis_stats": {"malicious": 6}},
                    observed=None,
                )
            ],
            "1.1.1.1",
            (32, "suspicious", 35),
        ),
        (
            [found("urlhaus", {"url_status": "offline"})],
            "https://public-site.com/",
            (63, "suspicious", 60),
        ),
    ],
)
def test_worked_examples(
    outcomes: list[ProviderOutcome], text: str, expected: tuple[int, str, int]
) -> None:
    original = report_for(outcomes, text)
    before = original.model_dump_json()
    result = assess_report(original, scoring_as_of=NOW)
    a = result.assessments[0]
    assert (a.risk_score, a.label, a.evidence_confidence) == expected
    assert original.model_dump_json() == before
    assert isinstance(result, AssessedEnrichedReport)
    assert result.provider_results == original.provider_results
    for contribution in a.contributions:
        assert contribution.reference.pointers
        for pointer, expected_value in contribution.reference.field_values.items():
            value = json.loads(result.model_dump_json())
            for part in pointer.lstrip("/").split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                value = value[int(part)] if isinstance(value, list) else value[part]
            assert value == expected_value
    assert a.risk_score == min(100, a.maximum_score + a.risk_bonus)
    assert a.evidence_confidence == max(
        0, min(95, a.maximum_support + a.confidence_bonus - a.tension_penalty)
    )


@pytest.mark.parametrize(
    ("m", "expected"), [(0, 0), (1, 20), (2, 45), (4, 45), (5, 65), (9, 65), (10, 80), (100, 80)]
)
def test_vt_bands(m: int, expected: int) -> None:
    assert score([vt(m, 0)]).risk_score == expected


@pytest.mark.parametrize(("s", "expected"), [(0, 0), (1, 10), (2, 10), (3, 30), (100, 30)])
def test_suspicious_bands(s: int, expected: int) -> None:
    a = score([vt(None, s)])
    assert a.risk_score == expected
    assert "missing_malicious" in a.contributions[0].flags


@pytest.mark.parametrize(
    ("a", "expected"),
    [(0, 0), (1, 10), (9, 10), (10, 25), (49, 25), (50, 50), (89, 50), (90, 70), (100, 70)],
)
def test_abuse_bands(a: int, expected: int) -> None:
    assert score([abuse(a)]).risk_score == expected


@pytest.mark.parametrize(
    ("days", "before", "after"), [(7, 100, 90), (30, 90, 75), (90, 75, 50), (365, 50, 25)]
)
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_freshness_boundaries(days: int, before: int, after: int, offset: int) -> None:
    percent, age, _ = freshness(NOW - timedelta(days=days, microseconds=offset), NOW, "virustotal")
    assert percent == (after if offset > 0 else before)
    assert age is not None


@pytest.mark.parametrize(
    ("observed", "expected"),
    [
        (None, 50),
        (NOW.replace(tzinfo=None), 50),
        (NOW + timedelta(minutes=5), 100),
        (NOW + timedelta(minutes=5, microseconds=1), 50),
        (NOW.astimezone(timezone(timedelta(hours=3))), 100),
    ],
)
def test_timestamp_edge_cases(observed: datetime | None, expected: int) -> None:
    assert freshness(observed, NOW, "virustotal")[0] == expected
    assert freshness(observed, NOW, "urlhaus")[0] == min(75, expected)


@pytest.mark.parametrize(
    ("value", "label"),
    [
        (0, "unknown"),
        (1, "low"),
        (29, "low"),
        (30, "suspicious"),
        (69, "suspicious"),
        (70, "malicious"),
        (100, "malicious"),
    ],
)
def test_labels(value: int, label: str) -> None:
    assert label_for(value) == label


@pytest.mark.parametrize("status", [s for s in get_args(Status) if s != "found"])
def test_non_evidence_status_invariance(status: Status) -> None:
    a = score(
        [
            vt(6),
            abuse(80),
            ProviderOutcome(provider_id="urlhaus", ioc_index=0, status=status, reason="Mock"),
        ]
    )
    assert (a.risk_score, a.evidence_confidence) == (70, 80)


def test_duplicate_and_failed_duplicates_do_not_add_votes() -> None:
    item = vt(6)
    a = score(
        [
            item,
            item.model_copy(deep=True),
            abuse(80),
            ProviderOutcome(
                provider_id="virustotal",
                ioc_index=0,
                status="timeout",
                reason="Mock",
                fetched_at=NOW + timedelta(seconds=1),
            ),
        ]
    )
    assert (a.risk_score, a.evidence_confidence, a.qualified_provider_count) == (70, 80, 2)
    assert sum(c.reason == "duplicate_provider_lookup_not_selected" for c in a.contributions) == 1


def test_latest_and_stable_tie_selection_and_order_independence() -> None:
    old, new = vt(10), vt(1)
    old.fetched_at = NOW - timedelta(seconds=1)
    assert score([old, new]).risk_score == 20
    assert score([new, old]).risk_score == 20
    old.fetched_at = NOW
    assert score([old, new]).risk_score == score([new, old]).risk_score
    assert (
        score([old, new]).contributions[0].reference.evidence_id
        == score([new, old]).contributions[0].reference.evidence_id
    )


def test_refetch_never_refreshes_observation() -> None:
    item = found(
        "virustotal",
        {"report_id": "1.1.1.1", "last_analysis_stats": {"malicious": 10}},
        observed=NOW - timedelta(days=200),
    )
    first = score([item])
    item.fetched_at = NOW + timedelta(days=1)
    later = score([item])
    assert first.risk_score == later.risk_score == 40
    assert first.evidence_confidence == later.evidence_confidence == 40
    assert "future_fetched_at" in later.contributions[0].flags


def test_single_tension_and_missing_is_not_zero() -> None:
    a = score([vt(0, 0), abuse(0), found("urlhaus", {"url_count": 5})])
    assert (a.risk_score, a.evidence_confidence, a.tension_penalty) == (22, 23, 10)
    assert len(a.tensions) == 1 and len(a.tensions[0].evidence_ids) == 3
    assert score([vt(None, 0), abuse(95)]).tension_penalty == 0
    mixed = score([vt(10, 0, harmless=99), abuse(0)])
    assert len(mixed.tensions) == 2 and mixed.tension_penalty == 10
    assert mixed.risk_score == 80


@pytest.mark.parametrize(
    "attrs",
    [
        {},
        {"abuseConfidenceScore": 101, "totalReports": 1},
        {"abuseConfidenceScore": 1, "totalReports": 0},
    ],
)
def test_abuse_invalid_or_inconsistent(attrs: dict[str, Attribute]) -> None:
    a = score([found("abuseipdb", attrs)])
    assert a.risk_score == 0 and a.contributions[0].flags


@pytest.mark.parametrize(
    "attrs", [{}, {"last_analysis_stats": {"malicious": -1}}, {"last_analysis_stats": {}}]
)
def test_vt_missing_or_invalid(attrs: dict[str, Attribute]) -> None:
    attrs["report_id"] = "1.1.1.1"
    a = score([found("virustotal", attrs)])
    assert a.risk_score == 0 and a.contributions[0].flags


@pytest.mark.parametrize("status", [None, "offline", "unexpected"])
def test_url_status_fallback(status: str | None) -> None:
    attrs: dict[str, Attribute] = {} if status is None else {"url_status": status}
    assert score([found("urlhaus", attrs)], "https://public-site.com/").risk_score == 63


@pytest.mark.parametrize(
    "attrs",
    [
        {},
        {"url_count": 0},
        {
            "url_count": 5,
            "tags": ["arbitrary"],
            "threat": "arbitrary",
            "signature": "arbitrary",
            "file_size": 999,
        },
    ],
)
def test_host_counts_and_metadata(attrs: dict[str, Attribute]) -> None:
    assert score([found("urlhaus", attrs)]).risk_score == (
        22 if attrs.get("url_count") == 5 else 11
    )


def test_optional_abuse_metadata_never_adds_risk() -> None:
    item = abuse(50)
    assert item.evidence is not None
    item.evidence.attributes.update(numDistinctUsers=999, isp="arbitrary", countryCode="XX")
    assert score([item]).risk_score == 50


def test_bad_mappings_and_identity_are_excluded() -> None:
    missing = vt(10)
    missing.ioc_index = None
    negative = vt(10)
    negative.ioc_index = -1
    large = vt(10)
    large.ioc_index = 100
    wrong = found("virustotal", {"report_id": "8.8.8.8", "last_analysis_stats": {"malicious": 10}})
    no_evidence = ProviderOutcome(provider_id="urlhaus", ioc_index=0, status="found", reason="Mock")
    r = assess_report(report_for([missing, negative, large, wrong, no_evidence]), scoring_as_of=NOW)
    assert len(r.scoring_diagnostics) == 3 and r.assessments[0].risk_score == 0
    assert {c.reason for c in r.assessments[0].contributions} == {
        "identity_mismatch",
        "missing_evidence",
    }
    assert score([abuse(95)], "public-site.com").risk_score == 0
    assert score([found("urlhaus", {})], "a" * 40).risk_score == 0
    assert score([vt(10)], "999.1.1.1").risk_score == 0


def test_fragment_evidence_reuse_and_no_host_risk_transfer() -> None:
    text = "https://public-site.com/#a https://public-site.com/#b public-site.com"
    item = found("urlhaus", {"url_status": "online"})
    r = assess_report(
        report_for([item, item.model_copy(update={"ioc_index": 1, "reused": True})], text),
        scoring_as_of=NOW,
    )
    assert [a.risk_score for a in r.assessments] == [71, 71, 0]
    assert [a.qualified_provider_count for a in r.assessments] == [1, 1, 0]
    groups = [g for g in r.relationships.groups if g.kind == "same_lookup"]
    assert len(groups) == 1 and len(groups[0].reused_evidence_ids) == 1


def test_vt_url_and_hash_identity() -> None:
    url = "https://public-site.com/"
    item = found(
        "virustotal",
        {
            "report_id": hashlib.sha256(url.encode()).hexdigest(),
            "last_analysis_stats": {"malicious": 10},
        },
    )
    assert score([item], url).risk_score == 80
    assert score([item], "https://other-site.com/").risk_score == 0
    assert score([vt(10)], "a" * 32).risk_score == 80


def test_as_of_required_and_input_immutable() -> None:
    report = report_for([vt(1)])
    with pytest.raises(ValueError, match="timezone-aware"):
        assess_report(report, scoring_as_of=NOW.replace(tzinfo=None))
    result = assess_report(report, scoring_as_of=NOW)
    assert isinstance(result, AssessedEnrichedReport)
    result.provider_results[0].reason = "changed copy"
    assert report.provider_results[0].reason == "Mock report"


def test_report_rendering_parity_and_control_escaping() -> None:
    item = abuse(90)
    assert item.evidence is not None
    item.evidence.attributes["isp"] = "[bold]UNTRUSTED[/bold]\x1b[31m"
    r = assess_report(report_for([item]), scoring_as_of=NOW)
    terminal = render_report(r, json_format=False)
    exported = render_report(r, json_format=True)
    block = terminal.split("Complete assessment and relationship breakdown (schema 1.2):\n", 1)[1]
    assert json.loads(block) == json.loads(exported)
    assert "\x1b" not in terminal
    assert "[bold]UNTRUSTED[/bold]" in terminal


def test_synthetic_cap_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    from traceguard.core import scoring

    def boosted(*args: object) -> tuple[int, int, str, bool, list[str]]:
        return 150, 150, "synthetic-cap-test", False, []

    monkeypatch.setattr(scoring, "provider_base", boosted)
    a = score([vt(10), abuse(90), found("urlhaus", {"url_count": 1})])
    assert a.risk_before_cap == 160 and a.confidence_before_cap == 170
    assert (a.risk_score, a.evidence_confidence) == (100, 95)


def test_confidence_lower_clamp_for_old_weak_tension() -> None:
    item = vt(None, 1)
    assert item.evidence is not None
    item.evidence.observed_at = NOW - timedelta(days=366)
    a = score([item, abuse(0)])
    assert a.risk_score == 2 and a.confidence_before_cap == -4
    assert a.evidence_confidence == 0 and a.label == "low"


def test_all_unknown_offline_and_capability_exclusions() -> None:
    r = assess_report(analyze_text("User@public-site.com 10.0.0.1 999.1.1.1"), scoring_as_of=NOW)
    assert all(a.risk_score == a.evidence_confidence == 0 for a in r.assessments)
    assert all(a.label == "unknown" for a in r.assessments)
    assert "Invalid IOC" in r.assessments[-1].reason
    assert score([found("urlhaus", {})], "a" * 32).risk_score == 71


def test_failure_cannot_create_conflict_even_with_attached_evidence() -> None:
    zero = abuse(0)
    zero.status = "network_error"
    a = score([vt(10), zero])
    assert a.risk_score == 80 and a.evidence_confidence == 80 and not a.tensions


def test_more_engine_failures_or_harmless_votes_do_not_change_score() -> None:
    first, second = score([vt(5, 0)]), score([vt(5, 0, failure=100, timeout=100, harmless=100)])
    assert (first.risk_score, first.evidence_confidence) == (
        second.risk_score,
        second.evidence_confidence,
    )
    assert second.tensions[0].kind == "vt_mixed_verdicts"
