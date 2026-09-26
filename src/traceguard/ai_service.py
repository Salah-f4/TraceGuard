"""Optional AI orchestration: deterministic-first and fail-closed model output."""

import asyncio
import secrets
from collections.abc import Callable
from datetime import UTC, datetime

from traceguard.ai_config import AISettings
from traceguard.core.ai_contracts import (
    AdapterResult,
    AIAdapter,
    AIEnrichedReport,
    AILimits,
    AIReport,
    AIReporting,
    AIStatus,
    OutputValidationError,
    ValidationCounts,
)
from traceguard.core.ai_reporting import fallback, project, validate_output
from traceguard.core.assessment import AssessedEnrichedReport, AssessedReport

DEFAULT_LIMITS = AILimits()


async def run_ai(
    report: AssessedReport,
    *,
    limits: AILimits = DEFAULT_LIMITS,
    utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> AIReport:
    # Never give an adapter access to the original report or a mutable reference to it.
    snapshot = report.model_copy(deep=True)
    started = utcnow()
    sections = fallback(snapshot)
    status: AIStatus = "skipped_no_citable_evidence"
    result = AdapterResult(status=status)
    projected: list[str] = []
    omitted = {a.ioc_id: "no_citable_evidence" for a in snapshot.assessments}
    estimates: dict[str, int] = {}
    origin = "deterministic_fallback"
    try:
        projection = project(snapshot, secrets.token_hex(16))
        projected, omitted = projection.projected, projection.omitted
        if projection.request.iocs:
            from traceguard.adapters.ai.groq import GroqAdapter, fits_budget, token_estimates

            estimates = token_estimates(projection.request, limits)
            if not fits_budget(projection.request, limits):
                status = "skipped_budget"
            else:
                settings = AISettings.from_environment()
                if not settings.valid:
                    status = "invalid_configuration"
                elif settings.key is None:
                    status = "disabled_missing_key"
                else:
                    adapter: AIAdapter = GroqAdapter(settings.key)
                    result = await adapter.generate(
                        projection.request.model_copy(deep=True), limits
                    )
                    status = result.status
                    if status == "completed" and result.output is not None:
                        try:
                            selected = validate_output(snapshot, projection, result.output)
                            result = result.model_copy(
                                update={
                                    "output": None,
                                    "validation_counts": ValidationCounts(
                                        returned_claim_count=sum(len(v) for v in selected.values())
                                    ),
                                }
                            )
                            # Keep excluded local nodes visible as explicitly local supplements.
                            for section, items in sections.items():
                                selected[section].extend(
                                    c
                                    for c in items
                                    if any(node not in projected for node in c.ioc_ids)
                                )
                            sections = selected
                            origin = "ai_assisted"
                        except OutputValidationError as exc:
                            status = "invalid_output"
                            result = result.model_copy(
                                update={
                                    "output": None,
                                    "invalid_output_reason": exc.reason,
                                    "validation_counts": exc.counts,
                                }
                            )
                        except Exception:
                            status = "invalid_output"
                            result = result.model_copy(
                                update={
                                    "output": None,
                                    "invalid_output_reason": "other_validation_failure",
                                }
                            )
                    elif status == "completed":
                        status = "invalid_output"
                        result = result.model_copy(
                            update={"invalid_output_reason": "missing_structured_response"}
                        )
    except OverflowError:
        status = "skipped_budget"
        omitted = {a.ioc_id: "budget" for a in snapshot.assessments}
    except asyncio.CancelledError:
        status = "cancelled"
    except Exception:
        status = "privacy_blocked"
    info = AIReporting(
        status=status,
        origin="ai_assisted" if origin == "ai_assisted" else "deterministic_fallback",
        started_at=started,
        completed_at=utcnow(),
        attempts=result.attempts,
        usage=result.usage,
        projected_ioc_ids=projected,
        omitted_iocs=omitted,
        sections=sections,
        token_estimates=estimates,
        invalid_output_reason=result.invalid_output_reason,
        validation_counts=result.validation_counts,
    )
    data = snapshot.model_dump()
    data.update(schema_version="1.3", ai_reporting=info)
    output = (
        AIEnrichedReport.model_validate(data)
        if isinstance(snapshot, AssessedEnrichedReport)
        else AIReport.model_validate(data)
    )
    assert output.model_dump(exclude={"schema_version", "ai_reporting"}) == snapshot.model_dump(
        exclude={"schema_version"}
    )
    return output
