"""Local descriptive relationships. No lookup, risk transfer, or quadratic cliques."""

import hashlib
import ipaddress
import json
from collections import defaultdict
from urllib.parse import urlsplit

from traceguard.core.assessment import (
    OccurrenceReference,
    Relationship,
    RelationshipGroup,
    Relationships,
)
from traceguard.core.eligibility import eligible
from traceguard.core.intelligence import LookupIOC
from traceguard.core.models import AnalysisReport, IOCResult, IOCType


def stable_id(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def ioc_id(ioc: IOCResult) -> str:
    return stable_id([ioc.type.value, ioc.normalized_value])


def correlate(report: AnalysisReport) -> Relationships:
    """Return new relationships using existing valid nodes and occurrence metadata."""
    valid = [(i, ioc) for i, ioc in enumerate(report.results) if ioc.is_valid]
    nodes = {(ioc.type, ioc.normalized_value): (ioc_id(ioc), i) for i, ioc in valid}
    edges: dict[tuple[str, str, str], Relationship] = {}
    lines: dict[tuple[str, int], dict[str, OccurrenceReference]] = defaultdict(dict)
    lookups: dict[str, set[str]] = defaultdict(set)
    lookup_values: dict[str, LookupIOC] = {}
    for index, ioc in valid:
        node = ioc_id(ioc)
        target_type = IOCType.DOMAIN
        host = ""
        kind: str = ""
        if ioc.type == IOCType.URL:
            try:
                host = urlsplit(ioc.normalized_value).hostname or ""
            except ValueError:
                host = ""
            try:
                address = ipaddress.ip_address(host)
                target_type = IOCType.IPV4 if address.version == 4 else IOCType.IPV6
                host = address.compressed
            except ValueError:
                pass
            kind = "url_has_host"
            decision = eligible(LookupIOC(type=ioc.type, normalized_value=ioc.normalized_value))
            if decision.lookup is not None:
                key = decision.lookup.normalized_value
                lookups[key].add(node)
                lookup_values[key] = decision.lookup
        elif ioc.type == IOCType.EMAIL:
            host = ioc.normalized_value.rsplit("@", 1)[-1]
            kind = "email_has_domain"
        target = nodes.get((target_type, host))
        if target is not None and kind in {"url_has_host", "email_has_domain"}:
            edge = Relationship(
                kind="url_has_host" if kind == "url_has_host" else "email_has_domain",
                source_id=node,
                target_id=target[0],
                pointers=[
                    f"/results/{index}/normalized_value",
                    f"/results/{target[1]}/normalized_value",
                ],
            )
            edges[(kind, node, target[0])] = edge
        for oi, occurrence in enumerate(ioc.occurrences):
            loc = occurrence.source_location
            oid = stable_id([node, loc.model_dump()])
            lines[(loc.source, loc.line)].setdefault(
                oid,
                OccurrenceReference(
                    occurrence_id=oid,
                    ioc_id=node,
                    **loc.model_dump(),
                    pointer=f"/results/{index}/occurrences/{oi}/source_location",
                ),
            )
    groups = [
        RelationshipGroup(
            kind="same_input",
            group_id=stable_id(["same_input", report.source]),
            members=sorted({ioc_id(ioc) for _, ioc in valid}),
        )
    ]
    for line_key, occurrences in sorted(lines.items()):
        members = sorted({occ.ioc_id for occ in occurrences.values()})
        if len(members) > 1:
            groups.append(
                RelationshipGroup(
                    kind="same_source_line",
                    group_id=stable_id(["same_source_line", line_key]),
                    members=members,
                    occurrences=sorted(
                        occurrences.values(),
                        key=lambda item: (item.ioc_id, item.start_offset, item.end_offset),
                    ),
                )
            )
    for key, members_set in sorted(lookups.items()):
        if len(members_set) > 1:
            groups.append(
                RelationshipGroup(
                    kind="same_lookup",
                    group_id=stable_id(["same_lookup", key]),
                    members=sorted(members_set),
                    lookup=lookup_values[key],
                )
            )
    return Relationships(
        edges=[edges[key] for key in sorted(edges)],
        groups=sorted(groups, key=lambda item: (item.kind, item.group_id)),
    )
