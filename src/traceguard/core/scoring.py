"""Pure deterministic Phase 4 heuristics. Scores and confidence are not probabilities."""

import hashlib
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import cast

from pydantic import JsonValue

from traceguard.core.assessment import (
    AssessedEnrichedReport,
    AssessedReport,
    EvidenceReference,
    EvidenceTension,
    IOCassessment,
    RiskLabel,
    ScoreContribution,
    ScoringPolicy,
)
from traceguard.core.correlation import correlate, ioc_id, stable_id
from traceguard.core.eligibility import eligible
from traceguard.core.intelligence import (
    CAPABILITIES,
    EnrichedReport,
    LookupIOC,
    ProviderID,
    ProviderOutcome,
)
from traceguard.core.models import AnalysisReport, IOCType

POLICY = ScoringPolicy()
LIMITATIONS = [
    "Provisional heuristics, not probabilities or proof of compromise.",
    "Zero, not_found, harmless votes, and no adverse evidence never establish safety.",
    "Distinct providers are only a proxy for independent upstream sources.",
    "URLhaus timestamp provenance is ambiguous; freshness is capped at 75%.",
    "Relationships are descriptive only and never transfer risk.",
]


def label_for(score: int) -> RiskLabel:
    if score == 0:
        return "unknown"
    if score < 30:
        return "low"
    if score < 70:
        return "suspicious"
    return "malicious"


def freshness(
    observed: datetime | None, as_of: datetime, provider: ProviderID
) -> tuple[int, float | None, str]:
    if observed is None or observed.tzinfo is None:
        factor, age, reason = 50, None, "missing_or_invalid_observed_at"
    elif observed > as_of + timedelta(minutes=5):
        factor, age, reason = 50, None, "future_observed_at"
    else:
        age = max(0.0, (as_of - observed).total_seconds())
        factor, reason = 25, "older_than_365_days"
        for days, percent in ((7, 100), (30, 90), (90, 75), (365, 50)):
            if age <= days * 86400:
                factor, reason = percent, f"within_{days}_days"
                break
    if provider == "urlhaus":
        factor = min(factor, 75)
        reason += ";urlhaus_ambiguous_timestamp_cap_75"
    return factor, age, reason


def _count(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def provider_base(
    provider: ProviderID, lookup: LookupIOC, outcome: ProviderOutcome
) -> tuple[int, int, str, bool, list[str]]:
    """Return B,Q,rule,no-adverse,flags from an already validated found outcome."""
    assert outcome.evidence is not None
    attrs = outcome.evidence.attributes
    flags: list[str] = []
    if provider == "virustotal":
        stats = attrs.get("last_analysis_stats")
        if not isinstance(stats, dict) or any(_count(v) is None for v in stats.values()):
            return 0, 0, "vt.invalid_stats", False, ["invalid_analysis_stats"]
        m, s = _count(stats.get("malicious")), _count(stats.get("suspicious"))
        for name, value in [("malicious", m), ("suspicious", s)]:
            if value is None:
                flags.append(f"missing_{name}")
        if ((m or 0) > 0 or (s or 0) > 0) and (stats.get("harmless", 0) > 0):
            flags.append("vt_mixed_verdicts")
        for threshold, b, q in ((10, 80, 80), (5, 65, 70), (2, 45, 60), (1, 20, 40)):
            if m is not None and m >= threshold:
                return b, q, f"vt.malicious_ge_{threshold}", False, flags
        if s is not None and s > 0:
            return (
                (30, 45, "vt.suspicious_ge_3", False, flags)
                if s >= 3
                else (10, 25, "vt.suspicious_1_2", False, flags)
            )
        return 0, 0, "vt.no_positive_votes", m == 0 and s == 0, flags
    if provider == "abuseipdb":
        a, reports = _count(attrs.get("abuseConfidenceScore")), _count(attrs.get("totalReports"))
        if a is None or reports is None or a > 100:
            return 0, 0, "abuse.invalid_fields", False, ["missing_or_invalid_abuse_fields"]
        if reports == 0 or a == 0:
            if a > 0:
                flags.append("positive_abuse_score_without_reports")
            return 0, 0, "abuse.no_positive_support", a == 0, flags
        for threshold, b, q in ((90, 70, 70), (50, 50, 60), (10, 25, 45), (1, 10, 30)):
            if a >= threshold:
                return b, q, f"abuse.score_ge_{threshold}", False, flags
    if lookup.type == IOCType.URL:
        status = attrs.get("url_status")
        if status == "online":
            return 95, 90, "urlhaus.exact_online_url", False, flags
        if status != "offline":
            flags.append("missing_or_unknown_url_status")
        return 85, 80, "urlhaus.exact_historical_url", False, flags
    if lookup.type in {IOCType.MD5, IOCType.SHA256}:
        return 95, 90, "urlhaus.exact_payload", False, flags
    count = _count(attrs.get("url_count"))
    if count is not None and count > 0:
        return 30, 45, "urlhaus.host_positive_count", False, flags
    return 15, 30, "urlhaus.host_without_positive_count", False, ["missing_or_zero_url_count"]


def _fields(value: JsonValue, pointer: str) -> dict[str, JsonValue]:
    result = {pointer: value}
    if isinstance(value, dict):
        for key, child in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            result.update(_fields(child, f"{pointer}/{escaped}"))
    return result


def _reference(
    outcome: ProviderOutcome, oi: int, index: int, lookup: LookupIOC | None
) -> EvidenceReference:
    evidence = outcome.evidence
    values = _fields(cast(JsonValue, outcome.model_dump(mode="json")), f"/provider_results/{oi}")
    values[f"/results/{index}/type"] = lookup.type.value if lookup else None
    # The source IOC value may include a fragment; lookup is separately recorded.
    evidence_id = stable_id(
        [
            outcome.provider_id,
            lookup.model_dump() if lookup else None,
            evidence.model_dump(mode="json") if evidence else None,
            outcome.status,
        ]
    )
    return EvidenceReference(
        evidence_id=evidence_id,
        provider_id=outcome.provider_id,
        outcome_index=oi,
        ioc_index=index,
        lookup=lookup,
        report_reference=evidence.reference if evidence else None,
        observed_at=evidence.observed_at if evidence else None,
        observed_at_original=evidence.observed_at_original if evidence else None,
        fetched_at=outcome.fetched_at,
        pointers=sorted(values),
        field_values=values,
    )


def aggregate(
    contributions: list[ScoreContribution], policy: ScoringPolicy = POLICY
) -> tuple[int, int, int, int, int, list[str], list[EvidenceTension]]:
    active = [c for c in contributions if c.role != "excluded"]
    positive = [c for c in active if c.weighted_score > 0]
    qualified = [c for c in positive if c.weighted_score >= 20 and c.freshness_percent >= 75]
    ids = sorted({c.reference.evidence_id for c in qualified})
    k = len({c.reference.provider_id for c in qualified})
    tensions: list[EvidenceTension] = []
    for c in active:
        if "vt_mixed_verdicts" in c.flags:
            tensions.append(
                EvidenceTension(
                    kind="vt_mixed_verdicts",
                    evidence_ids=[c.reference.evidence_id],
                    explanation="Adverse and harmless votes coexist.",
                )
            )
    counter = [c for c in active if c.no_adverse]
    tension_ids = sorted({c.reference.evidence_id for c in positive + counter})
    penalty = policy.tension_penalty if positive and counter else 0
    if penalty:
        tensions.append(
            EvidenceTension(
                kind="cross_provider_no_adverse",
                evidence_ids=tension_ids,
                explanation=(
                    "Positive evidence and explicit zero-adverse evidence coexist; "
                    "neither proves safety."
                ),
            )
        )
    risk_bonus = min(policy.correlation_cap, 5 * max(0, k - 1))
    confidence_bonus = min(policy.confidence_bonus_cap, 10 * max(0, k - 1))
    risk_raw = max((c.weighted_score for c in positive), default=0) + risk_bonus
    confidence_raw = (
        max((c.weighted_support for c in positive), default=0) + confidence_bonus - penalty
    )
    return risk_raw, confidence_raw, risk_bonus, confidence_bonus, penalty, ids, tensions


def _identity_ok(outcome: ProviderOutcome, lookup: LookupIOC) -> bool:
    # Adapters validate exact response identities. Recheck retained VT IDs as well.
    if outcome.provider_id != "virustotal" or lookup.type in {
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }:
        return True
    assert outcome.evidence is not None
    expected = (
        hashlib.sha256(lookup.normalized_value.encode()).hexdigest()
        if lookup.type == IOCType.URL
        else lookup.normalized_value
    )
    return outcome.evidence.attributes.get("report_id") == expected


def assess_report(
    report: AnalysisReport, *, scoring_as_of: datetime, policy: ScoringPolicy = POLICY
) -> AssessedReport:
    """Assess validated in-memory evidence without I/O or mutation of input."""
    if scoring_as_of.tzinfo is None or scoring_as_of.utcoffset() is None:
        raise ValueError("scoring_as_of must be timezone-aware.")
    as_of = scoring_as_of.astimezone(UTC)
    outcomes = report.provider_results if isinstance(report, EnrichedReport) else []
    diagnostics: list[str] = []
    per_ioc: dict[int, list[ScoreContribution]] = defaultdict(list)
    candidates: dict[tuple[ProviderID, IOCType, str], list[ScoreContribution]] = defaultdict(list)
    identities: dict[int, LookupIOC] = {}
    for result_index, ioc in enumerate(report.results):
        if ioc.is_valid:
            decision = eligible(LookupIOC(type=ioc.type, normalized_value=ioc.normalized_value))
            if decision.lookup:
                identities[result_index] = decision.lookup
    for oi, outcome in enumerate(outcomes):
        index = outcome.ioc_index
        if index is None or index < 0 or index >= len(report.results):
            diagnostics.append(f"/provider_results/{oi}: missing_or_invalid_ioc_mapping")
            continue
        lookup = identities.get(index)
        ref = _reference(outcome, oi, index, lookup)
        ref.field_values[f"/results/{index}/type"] = report.results[index].type.value
        ref.field_values[f"/results/{index}/normalized_value"] = report.results[
            index
        ].normalized_value
        ref.pointers = sorted(ref.field_values)
        c = ScoreContribution(reference=ref, rule_id="excluded", reason=outcome.status)
        per_ioc[index].append(c)
        if outcome.fetched_at is None or outcome.fetched_at.tzinfo is None:
            c.flags.append("missing_or_invalid_fetched_at")
        elif outcome.fetched_at > as_of:
            c.flags.append("future_fetched_at")
        if outcome.status != "found":
            continue
        if lookup is None or lookup.type not in CAPABILITIES[outcome.provider_id]:
            c.reason = "invalid_or_unsupported_lookup_mapping"
            continue
        if outcome.evidence is None:
            c.reason = "missing_evidence"
            continue
        if not _identity_ok(outcome, lookup):
            c.reason = "identity_mismatch"
            continue
        key = outcome.provider_id, lookup.type, lookup.normalized_value
        candidates[key].append(c)
    chosen: dict[tuple[ProviderID, IOCType, str], ScoreContribution] = {}
    for key, pool in candidates.items():

        def rank(c: ScoreContribution) -> tuple[datetime, str, int]:
            fetched = c.reference.fetched_at
            return (
                fetched
                if fetched is not None and fetched.tzinfo is not None
                else datetime.min.replace(tzinfo=UTC),
                c.reference.evidence_id,
                -c.reference.outcome_index,
            )

        winner = max(pool, key=rank)
        chosen[key] = winner
        for c in pool:
            if c is not winner:
                c.reason = "duplicate_provider_lookup_not_selected"
        oi = winner.reference.outcome_index
        outcome = outcomes[oi]
        lookup = winner.reference.lookup
        assert lookup is not None and outcome.evidence is not None
        b, q, rule, no_adverse, flags = provider_base(key[0], lookup, outcome)
        percent, age, rationale = freshness(outcome.evidence.observed_at, as_of, key[0])
        winner.rule_id, winner.base_score, winner.base_support = rule, b, q
        winner.freshness_percent, winner.age_seconds = percent, age
        winner.freshness_reason = rationale
        winner.weighted_score, winner.weighted_support = b * percent // 100, q * percent // 100
        winner.no_adverse = no_adverse
        winner.flags.extend(flags)
        if age is None:
            winner.flags.append(rationale.split(";")[0])
        winner.role = "zero" if b == 0 else "non_additive"
        winner.reason = (
            "No weighted adverse evidence; safety unknown." if b == 0 else "Provider evidence rule."
        )
    assessments: list[IOCassessment] = []
    for index, ioc in enumerate(report.results):
        contributions = [c.model_copy(deep=True) for c in per_ioc[index]]
        lookup = identities.get(index)
        if lookup:
            for provider in sorted(CAPABILITIES):
                selected = chosen.get((provider, lookup.type, lookup.normalized_value))
                if selected and all(
                    c.reference.outcome_index != selected.reference.outcome_index
                    for c in contributions
                ):
                    contributions.append(selected.model_copy(deep=True))
        contributions.sort(
            key=lambda c: (
                c.reference.provider_id,
                c.reference.evidence_id,
                c.reference.outcome_index,
            )
        )
        raw, confidence_raw, bonus, cb, penalty, refs, tensions = aggregate(contributions, policy)
        score, confidence = (
            min(policy.risk_cap, raw),
            max(0, min(policy.confidence_cap, confidence_raw)),
        )
        maximum = max((c.weighted_score for c in contributions if c.role != "excluded"), default=0)
        for c in contributions:
            if c.role != "excluded" and c.weighted_score:
                c.role = (
                    "maximum"
                    if c.weighted_score == maximum
                    else "corroborating"
                    if c.reference.evidence_id in refs
                    else "non_additive"
                )
        coverage: Counter[str] = Counter()
        for c in per_ioc[index]:
            status = outcomes[c.reference.outcome_index].status
            bucket = (
                "found"
                if status == "found"
                else "not_found"
                if status == "not_found"
                else "disabled"
                if status == "disabled_missing_key"
                else "skipped"
                if status.startswith("skipped_")
                else "failed"
            )
            coverage[bucket] += 1
        assessments.append(
            IOCassessment(
                ioc_index=index,
                ioc_id=ioc_id(ioc),
                policy_version=policy.version,
                scoring_as_of=as_of,
                risk_score=score,
                evidence_confidence=confidence,
                label=label_for(score),
                reason=(
                    "Invalid IOC; safety unknown."
                    if not ioc.is_valid
                    else "No provider evidence; safety unknown."
                    if not contributions
                    else "No weighted adverse evidence; safety unknown."
                    if score == 0
                    else "Provisional adverse reputation assessment; not proof of compromise."
                ),
                contributions=contributions,
                maximum_score=maximum,
                maximum_support=max(
                    (
                        c.weighted_support
                        for c in contributions
                        if c.role != "excluded" and c.weighted_score > 0
                    ),
                    default=0,
                ),
                qualified_provider_count=len(
                    {
                        c.reference.provider_id
                        for c in contributions
                        if c.role != "excluded" and c.reference.evidence_id in refs
                    }
                ),
                corroboration_evidence_ids=refs,
                risk_bonus=bonus,
                confidence_bonus=cb,
                tension_penalty=penalty,
                risk_before_cap=raw,
                confidence_before_cap=confidence_raw,
                tensions=tensions,
                coverage=dict(sorted(coverage.items())),
                limitations=LIMITATIONS.copy(),
            )
        )
    relationships = correlate(report)
    evidence_by_lookup: dict[tuple[IOCType, str], set[str]] = defaultdict(set)
    for key, c in chosen.items():
        evidence_by_lookup[(key[1], key[2])].add(c.reference.evidence_id)
    for group in relationships.groups:
        if group.kind == "same_lookup" and group.lookup:
            group.reused_evidence_ids = sorted(
                evidence_by_lookup[(group.lookup.type, group.lookup.normalized_value)]
            )
    data = report.model_dump()
    data.update(
        schema_version="1.2",
        assessments=assessments,
        relationships=relationships,
        scoring_diagnostics=sorted(diagnostics),
    )
    if isinstance(report, EnrichedReport):
        return AssessedEnrichedReport.model_validate(data)
    return AssessedReport.model_validate(data)
