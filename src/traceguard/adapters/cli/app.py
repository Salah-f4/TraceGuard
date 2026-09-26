"""Terminal adapter for offline analysis."""

import asyncio
from collections.abc import Callable
from contextlib import ExitStack
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from traceguard.adapters.cli.inputs import read_input
from traceguard.adapters.cli.reporting import render_report
from traceguard.core.intelligence import EnrichedReport
from traceguard.core.investigation import analyze_text
from traceguard.core.models import InputError
from traceguard.core.scoring import assess_report

app = typer.Typer(help="TraceGuard: offline IOC investigation.", add_completion=False)


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Display help when invoked without a command."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command("help")
def show_help(ctx: typer.Context) -> None:
    """Show usage and current implementation scope."""
    if ctx.parent is not None:
        typer.echo(ctx.parent.get_help())
    typer.echo(
        "Offline by default; --enrich retrieves existing reports. "
        "Deterministic assessments; --ai enables constrained reporting. "
        "Persistence is not implemented."
    )


@app.command()
def analyze(
    text: Annotated[str | None, typer.Option(help="Raw security text.")] = None,
    file: Annotated[Path | None, typer.Option(help="UTF-8 .txt or .log file.")] = None,
    stdin: Annotated[bool, typer.Option("--stdin", help="Read UTF-8 standard input.")] = False,
    format: Annotated[
        OutputFormat, typer.Option("--format", help="Output representation.")
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None, typer.Option(help="Write the full report to a new file.")
    ] = None,
    enrich: Annotated[
        bool,
        typer.Option(
            "--enrich", help="Disclose eligible normalized IOCs for existing intelligence reports."
        ),
    ] = False,
    ai: Annotated[bool, typer.Option("--ai", help="Opt into constrained AI reporting.")] = False,
) -> None:
    """Analyze offline, or explicitly opt into existing-report enrichment."""

    redact: Callable[[str], str] = str

    interrupted = False
    try:
        if enrich:
            from traceguard.bootstrap import run_enrichment
            from traceguard.config import Credentials

            credentials = Credentials.from_environment()
            redact = credentials.redact
        content, source = read_input(text, file, stdin)
        report = analyze_text(content, source=source)
        if enrich:
            report = asyncio.run(run_enrichment(report, credentials))
            if isinstance(report, EnrichedReport):
                interrupted = report.enrichment.cancelled
                if report.enrichment.completeness != "complete":
                    typer.echo(
                        "Warning: enrichment is partial or unavailable; see provider statuses.",
                        err=True,
                    )
        assessed = assess_report(report, scoring_as_of=datetime.now(UTC))
        # Reserve an explicitly requested new report file before any AI request.
        with ExitStack() as stack:
            stream = (
                stack.enter_context(output.open("x", encoding="utf-8", newline="\n"))
                if output
                else None
            )
            if ai and not interrupted:
                from traceguard.ai_service import run_ai

                ai_report = asyncio.run(run_ai(assessed))
                assessed = ai_report
                status = ai_report.ai_reporting.status
                interrupted = status == "cancelled"
                if status != "completed":
                    typer.echo(
                        f"AI reporting: {status}; deterministic fallback retained.", err=True
                    )
            rendered = redact(render_report(assessed, json_format=format == OutputFormat.JSON))
            if stream is not None:
                stream.write(rendered)
                typer.echo(redact(f"Report written to {output}"), err=True)
            else:
                typer.echo(rendered, nl=False)
    except (InputError, OSError) as exc:
        typer.echo(redact(f"Error: {exc}"), err=True)
        raise typer.Exit(code=2) from exc
    if interrupted:
        raise typer.Exit(code=130)


if __name__ == "__main__":
    app()
