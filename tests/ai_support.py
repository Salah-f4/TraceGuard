"""Synthetic Groq fixtures only: never read developer credentials or make live calls."""

import json
from typing import Any

from tests.unit.test_scoring import NOW, report_for, vt
from traceguard.ai_config import MODEL
from traceguard.core.ai_contracts import AIRequest
from traceguard.core.ai_reporting import Projection, project
from traceguard.core.assessment import AssessedReport
from traceguard.core.scoring import assess_report


def assessed() -> AssessedReport:
    return assess_report(report_for([vt(6)]), scoring_as_of=NOW)


def projected() -> Projection:
    return project(assessed(), "a" * 32)


def valid_output(request: AIRequest) -> dict[str, Any]:
    return {"claims": [c.claim_alias for c in request.claims]}


def envelope(request: AIRequest) -> dict[str, Any]:
    return {
        "model": MODEL,
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": json.dumps(valid_output(request))},
            }
        ],
        "usage": {"prompt_tokens": 500, "completion_tokens": 200, "total_tokens": 700},
    }
