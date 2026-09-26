"""Allowlisted compact wire projection; private ownership maps stay local."""

from traceguard.core.ai_contracts import AIRequest


def compact_parts(request: AIRequest) -> tuple[dict[str, object], dict[str, object]]:
    providers = {"virustotal": "V", "abuseipdb": "A", "urlhaus": "U"}
    templates: list[object] = []
    template_ids: dict[str, int] = {}
    claims: list[object] = []
    for c in request.claims:
        if c.template_key not in template_ids:
            template_ids[c.template_key] = len(templates)
            templates.append(
                [
                    c.template_key,
                    c.kind,
                ]
            )
        claims.append(
            [
                c.claim_alias,
                template_ids[c.template_key],
                c.ioc_aliases,
                c.evidence_aliases,
                c.relation_aliases,
                c.mandatory,
            ]
        )
    facts: dict[str, object] = {
        "i": [
            [
                i.id,
                i.type,
                i.risk,
                i.label,
                i.confidence,
                sorted(
                    {
                        template_ids[c.template_key]
                        for c in request.claims
                        if i.id in c.ioc_aliases
                        and c.template_key
                        in {
                            "conflicting_evidence",
                            "no_adverse_or_no_match",
                            "partial_coverage",
                            "stale_or_ambiguous",
                        }
                    }
                ),
            ]
            for i in request.iocs
        ],
        "e": [
            [
                e.id,
                providers[e.provider],
                e.status,
                e.iocs,
                e.numbers,
                e.scope,
                "current"
                if e.freshness == 100
                else "unweighted"
                if e.freshness == 0
                else "reduced",
                e.url_status,
            ]
            for e in request.evidence
        ],
        "r": [[r.id, r.kind, r.iocs] for r in request.relations],
    }
    return facts, {"t": templates, "c": claims}
