"""Generate labelled public examples from synthetic data, without any HTTP calls."""

import hashlib
import json
import sys
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.text import Text

from traceguard.adapters.cli.reporting import render_report
from traceguard.core.ai_contracts import AIEnrichedReport, AIReporting, Usage, ValidationCounts
from traceguard.core.ai_reporting import project, validate_output
from traceguard.core.intelligence import (
    EnrichedReport,
    EnrichmentSummary,
    ProviderEvidence,
    ProviderOutcome,
)
from traceguard.core.investigation import analyze_text
from traceguard.core.models import AnalysisReport
from traceguard.core.scoring import assess_report


def main() -> None:
    def deny_network(event: str, args: tuple[object, ...]) -> None:
        if event.startswith("socket."):
            raise RuntimeError("Examples must be generated offline.")

    sys.addaudithook(deny_network)
    root = Path(__file__).resolve().parents[1]
    now = datetime(2026, 9, 26, tzinfo=UTC)
    offline = assess_report(
        analyze_text("192.0.2.1 hxxps[:]//example[.]com/Demo"), scoring_as_of=now
    )
    value = hashlib.sha256(b"TraceGuard harmless documentation example").hexdigest()
    raw = analyze_text(value)
    enriched = EnrichedReport(
        **raw.model_dump(exclude={"schema_version"}),
        enrichment=EnrichmentSummary(
            completeness="complete",
            completed_at=now,
            provider_availability={"virustotal": "mocked"},
            status_counts={"found": 1},
            attempts=1,
        ),
        provider_results=[
            ProviderOutcome(
                provider_id="virustotal",
                ioc_index=0,
                status="found",
                reason="Synthetic documentation response; no lookup performed.",
                fetched_at=now,
                evidence=ProviderEvidence(
                    observed_at=now,
                    attributes={
                        "report_id": value,
                        "last_analysis_stats": {"malicious": 6, "suspicious": 0, "harmless": 0},
                    },
                ),
            )
        ],
    )
    assessed = assess_report(enriched, scoring_as_of=now)
    projection = project(assessed, "a" * 32)
    selections = validate_output(
        assessed,
        projection,
        json.dumps({"claims": [c.claim_alias for c in projection.request.claims]}),
    )
    ai = AIEnrichedReport(
        **assessed.model_dump(exclude={"schema_version"}),
        ai_reporting=AIReporting(
            status="completed",
            origin="ai_assisted",
            started_at=now,
            completed_at=now,
            attempts=1,
            usage=Usage(prompt_tokens=500, completion_tokens=100, total_tokens=600),
            projected_ioc_ids=projection.projected,
            omitted_iocs=projection.omitted,
            sections=selections,
            validation_counts=ValidationCounts(
                returned_claim_count=sum(map(len, selections.values()))
            ),
        ),
    )
    pairs: list[tuple[str, AnalysisReport]] = [("offline", offline), ("mocked-ai", ai)]
    for name, report in pairs:
        title = "SYNTHETIC / MOCKED EXAMPLE - no service calls"
        content = render_report(report, json_format=False)
        (root / f"docs/examples/{name}.txt").write_text(title + "\n" + content, encoding="utf-8")
        console = Console(
            file=StringIO(), record=True, width=100, force_terminal=True, color_system="truecolor"
        )
        console.print(Text(title, style="bold cyan"))
        console.print(Text("Terminal excerpt; complete accessible text is in docs/examples/."))
        lines = content.splitlines()
        if name == "mocked-ai":
            start = next(i for i, line in enumerate(lines) if line.startswith("AI reporting:"))
            excerpt_lines = (
                lines[:2]
                + ["[... synthetic evidence omitted from capture ...]"]
                + lines[start : start + 13]
            )
        else:
            excerpt_lines = lines[:25]
        console.print(Text("\n".join(excerpt_lines)))
        console.save_svg(
            str(root / f"docs/images/{name}.svg"),
            title="TraceGuard synthetic example",
            unique_id=name,
        )
    excerpt = {
        "notice": "Entirely synthetic; usage and provider evidence are fabricated.",
        "schema_version": ai.schema_version,
        "risk_score": ai.assessments[0].risk_score,
        "label": ai.assessments[0].label,
        "ai_reporting": {
            "status": ai.ai_reporting.status,
            "accepted_claims": ai.ai_reporting.validation_counts.returned_claim_count,
            "example_claim": ai.ai_reporting.sections["ioc_findings"][0].model_dump(),
        },
    }
    (root / "docs/examples/report-excerpt.json").write_text(
        json.dumps(excerpt, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
