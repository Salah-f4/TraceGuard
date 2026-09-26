"""Local relationship provenance, scalability and no-inference tests."""

from traceguard.core.correlation import correlate
from traceguard.core.investigation import analyze_text


def test_hosts_email_ip_literals_and_idna() -> None:
    r = analyze_text(
        "bücher.de https://bücher.de/ User@bücher.de "
        "2606:4700:4700::1111 https://[2606:4700:4700::1111]/ "
        "1.1.1.1 http://1.1.1.1/"
    )
    links = correlate(r)
    assert [e.kind for e in links.edges].count("url_has_host") == 3
    assert [e.kind for e in links.edges].count("email_has_domain") == 1
    assert all(e.risk_contribution == e.confidence_contribution == 0 for e in links.edges)
    assert len([g for g in links.groups if g.kind == "same_input"]) == 1


def test_line_occurrence_deduplication_and_source_separation() -> None:
    r = analyze_text("1.1.1.1 public-site.com\n1.1.1.1 public-site.com")
    r.results[0].occurrences.append(r.results[0].occurrences[0].model_copy(deep=True))
    r.results[1].occurrences[1].source_location = (
        r.results[1].occurrences[1].source_location.model_copy(update={"source": "other"})
    )
    links = correlate(r)
    lines = [g for g in links.groups if g.kind == "same_source_line"]
    assert len(lines) == 1 and len(lines[0].occurrences) == 2
    assert all(o.line == 1 for o in lines[0].occurrences)
    assert all(
        o.pointer and o.column > 0 and o.end_offset > o.start_offset for o in lines[0].occurrences
    )


def test_ten_thousand_single_line_members_without_pair_expansion() -> None:
    report = analyze_text(" ".join(f"node{i}.public-site.com" for i in range(10_000)))
    links = correlate(report)
    assert len(links.edges) == 0
    assert len(links.groups) == 2
    assert all(len(group.members) == 10_000 for group in links.groups)
    assert len(next(g for g in links.groups if g.kind == "same_source_line").occurrences) == 10_000


def test_invalid_nodes_and_no_derived_iocs() -> None:
    report = analyze_text("999.1.1.1 https://public-site.com/ a@other-site.com")
    before = report.model_dump_json()
    links = correlate(report)
    assert not links.edges
    assert len(next(g for g in links.groups if g.kind == "same_input").members) == 2
    assert before == report.model_dump_json()


def test_order_independent_group_members_and_fragment_links() -> None:
    r = analyze_text("https://public-site.com/#a https://public-site.com/#b public-site.com")
    first = correlate(r)
    r.results.reverse()
    second = correlate(r)
    assert [(g.kind, g.group_id, g.members) for g in first.groups] == [
        (g.kind, g.group_id, g.members) for g in second.groups
    ]
    assert [(e.kind, e.source_id, e.target_id) for e in first.edges] == [
        (e.kind, e.source_id, e.target_id) for e in second.edges
    ]
