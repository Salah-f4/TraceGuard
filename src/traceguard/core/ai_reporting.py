"""Pure claim catalogue, private-to-public projection, and citation validation."""

import json
from dataclasses import dataclass
from typing import Literal, cast

from traceguard.core.ai_contracts import (
    CAPS,
    SECTIONS,
    AIOutput,
    AIRequest,
    ClaimSpec,
    EvidenceView,
    IOCView,
    Kind,
    OutputValidationError,
    RelationView,
    RenderedClaim,
    Section,
    ValidationCounts,
)
from traceguard.core.assessment import AssessedReport
from traceguard.core.correlation import stable_id
from traceguard.core.eligibility import eligible
from traceguard.core.intelligence import EnrichedReport, LookupIOC, Status
from traceguard.core.models import IOCType

Template = Literal[
    "assessment_snapshot",
    "provider_adverse",
    "no_adverse_or_no_match",
    "partial_coverage",
    "stale_or_ambiguous",
    "conflicting_evidence",
    "corroboration",
    "recorded_relationship",
    "review_existing_telemetry",
    "reconcile_existing_evidence",
    "capture_local_context",
    "reputation_limit",
    "analyst_caution",
]


@dataclass(frozen=True)
class Candidate:
    rendered: RenderedClaim
    destination: Section
    mandatory: bool


@dataclass(frozen=True)
class Projection:
    request: AIRequest
    candidates: dict[str, Candidate]
    omitted: dict[str, str]
    projected: list[str]


def catalogue(report: AssessedReport) -> list[Candidate]:
    result: list[Candidate] = []

    def add(
        template: Template,
        kind: Kind,
        text: str,
        ids: list[str],
        evidence: list[str],
        sections: list[Section],
        mandatory: Section | None = None,
        relations: list[str] | None = None,
        pointers: list[str] | None = None,
        priority: Literal["high", "medium", "routine"] | None = None,
    ) -> None:
        refs = sorted(set(evidence))
        for destination in sections:
            result.append(
                Candidate(
                    RenderedClaim(
                        claim_id=stable_id([template, ids, refs, relations, text, destination]),
                        kind=kind,
                        text=text,
                        ioc_ids=ids,
                        evidence_ids=refs,
                        relation_refs=relations or [],
                        template_key=template,
                        local_pointers=pointers or [],
                        action_priority=priority,
                    ),
                    destination,
                    mandatory == destination,
                )
            )

    for a in sorted(report.assessments, key=lambda a: (-a.risk_score, a.ioc_id)):
        ids, refs = [a.ioc_id], sorted({c.reference.evidence_id for c in a.contributions})
        pointer = [f"/assessments/{a.ioc_index}"]
        add(
            "assessment_snapshot",
            "fact",
            f"Recorded risk {a.risk_score}/{a.risk_cap}, label {a.label}, evidence confidence "
            f"{a.evidence_confidence}/100. Zero/unknown never establishes safety.",
            ids,
            refs,
            ["ioc_findings", "executive_summary"],
            "ioc_findings",
            pointers=pointer,
        )
        add(
            "reputation_limit",
            "uncertainty",
            "Reputation evidence does not prove compromise in this environment.",
            ids,
            refs,
            ["uncertainties"],
            "uncertainties",
            pointers=pointer,
        )
        add(
            "analyst_caution",
            "interpretation",
            "Scores and confidence are provisional heuristics, not probabilities. "
            "Use the preserved deterministic evidence before drawing incident conclusions.",
            ids,
            refs,
            ["analyst_notes"],
            "analyst_notes",
            pointers=pointer,
        )
        priority: Literal["high", "medium", "routine"] = (
            "high" if a.label == "malicious" else "medium" if a.label == "suspicious" else "routine"
        )
        add(
            "review_existing_telemetry" if a.risk_score else "capture_local_context",
            "recommended_step",
            "Manually review existing internal telemetry if available. Document context locally. "
            "No action was performed; do not close an investigation solely on a zero score.",
            ids,
            refs,
            ["prioritized_investigation_steps"],
            pointers=pointer,
            priority=priority,
        )
        if a.risk_score == 0:
            add(
                "no_adverse_or_no_match",
                "uncertainty",
                "No weighted adverse evidence is available. Unknown does not mean safe.",
                ids,
                refs,
                ["uncertainties"],
                "uncertainties",
                pointers=pointer,
            )
        for c in a.contributions:
            ref = [c.reference.evidence_id]
            provider = c.reference.provider_id
            if c.role != "excluded" and c.weighted_score > 0:
                add(
                    "provider_adverse",
                    "fact",
                    f"{provider} evidence contributes {c.weighted_score} freshness-adjusted points "
                    f"(base {c.base_score}); provider reputation does not prove compromise.",
                    ids,
                    ref,
                    ["ioc_findings", "executive_summary"],
                    pointers=c.reference.pointers,
                )
            if c.freshness_percent and c.freshness_percent < 100:
                add(
                    "stale_or_ambiguous",
                    "uncertainty",
                    f"{provider} freshness weight is {c.freshness_percent}%. "
                    "Evidence is aged or its timestamp provenance is incomplete/ambiguous.",
                    ids,
                    ref,
                    ["uncertainties"],
                    "uncertainties",
                    pointers=c.reference.pointers,
                )
            status = outcome_status(report, c.reference.outcome_index)
            if status == "not_found" or c.no_adverse:
                add(
                    "no_adverse_or_no_match",
                    "uncertainty",
                    f"{provider} returned no match or explicit zero-adverse evidence; this does "
                    "not establish safety.",
                    ids,
                    ref,
                    ["uncertainties"],
                    "uncertainties",
                )
            elif status != "found":
                add(
                    "partial_coverage",
                    "uncertainty",
                    f"{provider} coverage status is {status}; "
                    "no risk or confidence penalty applies.",
                    ids,
                    ref,
                    ["uncertainties"],
                    "uncertainties",
                )
        if a.corroboration_evidence_ids and a.qualified_provider_count > 1:
            add(
                "corroboration",
                "interpretation",
                f"{a.qualified_provider_count} distinct providers support the recorded "
                f"corroboration bonus of {a.risk_bonus}. Upstream independence is unverified.",
                ids,
                a.corroboration_evidence_ids,
                ["correlations"],
            )
        for tension in a.tensions:
            add(
                "conflicting_evidence",
                "uncertainty",
                "Contrasting evidence remains visible; "
                "no AI reconciliation or score change is allowed.",
                ids,
                tension.evidence_ids,
                ["uncertainties"],
                "uncertainties",
            )
            add(
                "reconcile_existing_evidence",
                "recommended_step",
                "Manually review already-collected contrasting evidence. No new lookup was made.",
                ids,
                tension.evidence_ids,
                ["prioritized_investigation_steps"],
                priority=priority,
            )
    by_id = {a.ioc_id: a for a in report.assessments}
    relations: list[tuple[str, list[str], str]] = []
    for i, edge in enumerate(report.relationships.edges):
        relations.append((edge.kind, [edge.source_id, edge.target_id], f"/relationships/edges/{i}"))
    for i, group in enumerate(report.relationships.groups):
        if len(group.members) > 1:
            relations.append((group.kind, group.members, f"/relationships/groups/{i}"))
    for kind, ids, relation_pointer in relations:
        refs = sorted(
            {
                c.reference.evidence_id
                for node in ids
                if node in by_id
                for c in by_id[node].contributions
            }
        )
        add(
            "recorded_relationship",
            "fact",
            f"Recorded relationship: {kind}. This is descriptive association, not communication, "
            "causation, compromise, or a shared campaign.",
            ids,
            refs,
            ["correlations"],
            relations=[relation_pointer],
        )
    # Repeated evidence/occurrences must not create duplicate claims.
    return list({c.rendered.claim_id: c for c in result}.values())


def outcome_status(report: AssessedReport, index: int) -> Status:
    if isinstance(report, EnrichedReport) and 0 <= index < len(report.provider_results):
        return report.provider_results[index].status
    return "invalid_response"


def project(report: AssessedReport, nonce: str) -> Projection:
    omitted: dict[str, str] = {}
    nodes: dict[str, str] = {}
    for a in sorted(report.assessments, key=lambda a: a.ioc_id):
        ioc = report.results[a.ioc_index]
        decision = eligible(LookupIOC(type=ioc.type, normalized_value=ioc.normalized_value))
        if not ioc.is_valid or decision.lookup is None:
            omitted[a.ioc_id] = "privacy_or_invalid"
        elif not a.contributions:
            omitted[a.ioc_id] = "no_citable_evidence"
        else:
            nodes[a.ioc_id] = f"I{len(nodes) + 1}"
    if len(nodes) > 20:
        raise OverflowError("Projection budget exceeded.")
    evidence_map: dict[str, str] = {}
    evidence: dict[str, EvidenceView] = {}
    iocs: list[IOCView] = []
    for a in sorted(report.assessments, key=lambda a: a.ioc_id):
        if a.ioc_id not in nodes:
            continue
        ioc = report.results[a.ioc_index]
        iocs.append(
            IOCView.model_validate(
                dict(
                    id=nodes[a.ioc_id],
                    type=ioc.type.value,
                    risk=a.risk_score,
                    label=a.label,
                    confidence=a.evidence_confidence,
                )
            )
        )
        for c in a.contributions:
            eid = c.reference.evidence_id
            if eid in evidence_map:
                evidence[eid].iocs.append(nodes[a.ioc_id])
                continue
            alias = f"E{len(evidence_map) + 1}"
            evidence_map[eid] = alias
            attrs = {}
            if isinstance(report, EnrichedReport):
                outcome = report.provider_results[c.reference.outcome_index]
                if outcome.evidence:
                    attrs = outcome.evidence.attributes
            numbers: dict[str, int] = {}
            source = (
                attrs.get("last_analysis_stats")
                if c.reference.provider_id == "virustotal"
                else attrs
            )
            fields = (
                ("malicious", "suspicious", "harmless")
                if c.reference.provider_id == "virustotal"
                else ("abuseConfidenceScore", "totalReports")
                if c.reference.provider_id == "abuseipdb"
                else ("url_count",)
            )
            if isinstance(source, dict):
                for name in fields:
                    val = source.get(name)
                    if type(val) is int:
                        numbers[name] = val
            url_status = attrs.get("url_status")
            evidence[eid] = EvidenceView.model_validate(
                dict(
                    id=alias,
                    provider=c.reference.provider_id,
                    status=outcome_status(report, c.reference.outcome_index),
                    iocs=[nodes[a.ioc_id]],
                    numbers=numbers,
                    scope="exact"
                    if ioc.type in {IOCType.URL, IOCType.MD5, IOCType.SHA1, IOCType.SHA256}
                    else "host",
                    freshness=c.freshness_percent,
                    weighted_score=c.weighted_score,
                    url_status=url_status
                    if url_status in ("online", "offline")
                    else "other_or_missing",
                )
            )
    specs: list[ClaimSpec] = []
    selected: dict[str, Candidate] = {}
    relations: list[RelationView] = []
    relation_map: dict[str, str] = {}
    for candidate in catalogue(report):
        claim = candidate.rendered
        if not claim.evidence_ids or any(n not in nodes for n in claim.ioc_ids):
            continue
        if any(e not in evidence_map for e in claim.evidence_ids):
            continue
        # Each referenced node needs its own provenance, including relationship members.
        if any(
            not any(nodes[n] in evidence[e].iocs for e in claim.evidence_ids) for n in claim.ioc_ids
        ):
            continue
        raliases = []
        for pointer in claim.relation_refs:
            if pointer not in relation_map:
                parts = pointer.split("/")
                item = report.relationships.model_dump()[parts[2]][int(parts[3])]
                if item["kind"] == "email_has_domain":
                    raise ValueError("Privacy boundary rejected relationship.")
                rid = f"R{len(relation_map) + 1}"
                relation_map[pointer] = rid
                relations.append(
                    RelationView.model_validate(
                        dict(id=rid, kind=item["kind"], iocs=[nodes[n] for n in claim.ioc_ids])
                    )
                )
            raliases.append(relation_map[pointer])
        cid = f"C{len(specs) + 1}"
        specs.append(
            ClaimSpec(
                claim_alias=cid,
                kind=claim.kind,
                ioc_aliases=sorted(nodes[n] for n in claim.ioc_ids),
                evidence_aliases=sorted(evidence_map[e] for e in claim.evidence_ids),
                relation_aliases=raliases,
                template_key=cast(Template, claim.template_key),
                destination=candidate.destination,
                mandatory=candidate.mandatory,
            )
        )
        selected[cid] = candidate
    # Make section completeness explicit without exposing routing to the model.
    for section in SECTIONS:
        if not any(c.destination == section and c.mandatory for c in specs):
            for i, spec in enumerate(specs):
                if spec.destination == section:
                    specs[i] = spec.model_copy(update={"mandatory": True})
                    break
    request = AIRequest(
        request_nonce=nonce,
        iocs=iocs,
        evidence=list(evidence.values()),
        relations=relations,
        claims=specs,
    )
    if len(evidence) > 80 or len(relations) > 40 or len(specs) > 120:
        raise OverflowError("Projection budget exceeded.")
    return Projection(request, selected, omitted, list(nodes))


def strict_json(raw: str, *, max_bytes: int = 65536) -> object:
    if len(raw.encode("utf-8")) > max_bytes:
        raise ValueError("Output too large.")
    # Scan nesting before parsing, ignoring braces inside quoted/escaped strings.
    depth = 0
    quoted = False
    escaped = False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > 8:
                raise ValueError("Excessive JSON depth.")
        elif char in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key.")
            result[key] = value
        return result

    def constant(value: str) -> object:
        raise ValueError("Nonfinite JSON number.")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def fallback(report: AssessedReport) -> dict[Section, list[RenderedClaim]]:
    sections: dict[Section, list[RenderedClaim]] = {s: [] for s in SECTIONS}
    for c in catalogue(report):
        sections[c.destination].append(c.rendered)
    return sections


def validate_output(
    report: AssessedReport, projection: Projection, raw: str
) -> dict[Section, list[RenderedClaim]]:
    # Rebuild predicates and ownership against the frozen local report.
    current = project(report, projection.request.request_nonce)
    if current.request != projection.request:
        raise OutputValidationError("citation_ownership_validation_failure")
    try:
        output = AIOutput.model_validate(strict_json(raw))
    except ValueError:
        raise OutputValidationError("json_schema_validation_failure") from None
    specs = {c.claim_alias: c for c in current.request.claims}
    selected: dict[Section, list[RenderedClaim]] = {s: [] for s in SECTIONS}
    items = output.claims
    counts = ValidationCounts(
        returned_claim_count=len(items),
        unknown_alias_count=sum(item not in specs for item in items),
        duplicate_count=len(items) - len(set(items)),
    )
    if not items or len(items) > 80:
        raise OutputValidationError("ordering_count_limit_violation", counts)
    if counts.unknown_alias_count:
        raise OutputValidationError("unknown_claim_alias", counts)
    if counts.duplicate_count:
        raise OutputValidationError("duplicate_claim_alias", counts)
    seen = set(items)
    for spec in specs.values():
        if spec.mandatory and spec.claim_alias not in seen:
            raise OutputValidationError(
                "missing_mandatory_uncertainty"
                if spec.destination == "uncertainties"
                else "invalid_section_assignment",
                counts,
            )
    for item in items:
        spec = specs[item]
        selected[spec.destination].append(
            current.candidates[item].rendered.model_copy(update={"origin": "ai_assisted"})
        )
    for section in SECTIONS:
        if len(selected[section]) > CAPS[section]:
            raise OutputValidationError("ordering_count_limit_violation", counts)
        if not selected[section] and any(c.destination == section for c in specs.values()):
            raise OutputValidationError("invalid_section_assignment", counts)
    priorities = {"high": 0, "medium": 1, "routine": 2, None: 3}
    selected["prioritized_investigation_steps"].sort(key=lambda c: priorities[c.action_priority])
    return selected
