"""Safe terminal output and JSON serialization."""

from io import StringIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from traceguard.core.ai_contracts import SECTIONS, AIReport
from traceguard.core.assessment import AssessedReport
from traceguard.core.intelligence import EnrichedReport
from traceguard.core.models import AnalysisReport


def render_report(report: AnalysisReport, *, json_format: bool) -> str:
    if json_format:
        return report.model_dump_json(indent=2) + "\n"
    stream = StringIO()
    console = Console(file=stream, width=100, color_system=None, highlight=False)
    console.print(
        f"TraceGuard: {report.unique_count} unique IOCs from {report.extracted_count} occurrences",
        markup=False,
    )
    console.print(
        "Provisional heuristics, not probabilities. Zero/unknown never means safe."
        if isinstance(report, AssessedReport)
        else "Offline syntax validation only; no threat assessment.",
        markup=False,
    )
    for index, result in enumerate(report.results, 1):
        table = Table(title=f"IOC {index}", show_header=False, expand=True)
        table.add_column(width=18)
        table.add_column(overflow="fold")
        fields = {
            "Type": result.type.value,
            "Original": result.original_value,
            "Normalized": result.normalized_value,
            "Defanged": str(result.is_defanged),
            "Valid": str(result.is_valid),
            "Validation": result.validation_message,
        }
        for label, value in fields.items():
            table.add_row(Text(label), Text(value))
        if isinstance(report, AssessedReport):
            assessment = report.assessments[index - 1]
            table.add_row(Text("Risk"), Text(f"{assessment.risk_score}/100 ({assessment.label})"))
            table.add_row(
                Text("Evidence confidence"), Text(f"{assessment.evidence_confidence}/100")
            )
            table.add_row(Text("Assessment"), Text(assessment.reason))
        for occurrence in result.occurrences:
            location = occurrence.source_location
            table.add_row(
                Text("Occurrence"),
                Text(
                    f"{location.source}:{location.line}:{location.column} "
                    f"[{location.start_offset}:{location.end_offset}] "
                    f"defanged={occurrence.is_defanged} {occurrence.original_value}"
                ),
            )
        console.print(table)
    if isinstance(report, EnrichedReport):
        console.print(f"Enrichment: {report.enrichment.completeness}", markup=False)
        for outcome in report.provider_results:
            console.print(
                Text(
                    f"IOC {outcome.ioc_index}: {outcome.provider_id}: "
                    f"{outcome.status} — {outcome.reason}"
                )
            )
            if outcome.evidence is not None:
                console.print(Text(outcome.evidence.model_dump_json(indent=2)))
    if isinstance(report, AssessedReport):
        if isinstance(report, AIReport):
            console.print(
                Text(f"AI reporting: {report.ai_reporting.status} ({report.ai_reporting.origin})")
            )
            for section in SECTIONS:
                console.print(Text(section.replace("_", " ").title()))
                if not report.ai_reporting.sections[section]:
                    console.print("No applicable claims in this section.", markup=False)
                for claim in report.ai_reporting.sections[section]:
                    console.print(Text(f"[{claim.kind}; {claim.origin}] {claim.text}"))
                    console.print(
                        Text(
                            f"IOC IDs: {', '.join(claim.ioc_ids)}; "
                            f"evidence IDs: {', '.join(claim.evidence_ids)}"
                        ),
                        soft_wrap=True,
                    )
        console.print(
            f"Complete assessment and relationship breakdown (schema {report.schema_version}):",
            markup=False,
        )
        # JSON escaping neutralizes control sequences and Rich markup. Keep this
        # complete, unwrapped block identical to the export for machine/human audit.
        console.print(Text(report.model_dump_json(indent=2)), soft_wrap=True)
    return stream.getvalue()
