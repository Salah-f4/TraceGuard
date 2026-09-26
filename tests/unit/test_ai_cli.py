"""CLI opt-in, export and fallback regressions without network."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.ai_support import assessed, valid_output
from traceguard.adapters.ai.groq import GroqAdapter
from traceguard.adapters.cli.app import app
from traceguard.ai_config import KEY_NAME
from traceguard.core.ai_contracts import AdapterResult, AILimits, AIRequest


def test_offline_opt_in_and_export(tmp_path: Path) -> None:
    runner = CliRunner()
    normal = runner.invoke(app, ["analyze", "--text", "1.1.1.1", "--format", "json"])
    assert normal.exit_code == 0 and json.loads(normal.stdout)["schema_version"] == "1.2"
    target = tmp_path / "report.json"
    result = runner.invoke(
        app, ["analyze", "--text", "1.1.1.1", "--ai", "--format", "json", "--output", str(target)]
    )
    assert result.exit_code == 0
    report = json.loads(target.read_text())
    assert report["schema_version"] == "1.3"
    assert report["ai_reporting"]["status"] == "skipped_no_citable_evidence"
    assert report["ai_reporting"]["attempts"] == 0
    terminal = runner.invoke(app, ["analyze", "--text", "1.1.1.1", "--ai"])
    assert terminal.exit_code == 0 and "deterministic_fallback" in terminal.stdout


@pytest.mark.parametrize("status", ["completed", "cancelled", "refused"])
def test_cli_mocked_ai(monkeypatch: pytest.MonkeyPatch, status: str) -> None:
    import importlib

    cli = importlib.import_module("traceguard.adapters.cli.app")
    monkeypatch.setattr(cli, "assess_report", lambda *args, **kwargs: assessed())
    monkeypatch.setenv(KEY_NAME, "synthetic-cli-canary")

    async def generate(self: GroqAdapter, request: AIRequest, limits: AILimits) -> AdapterResult:
        return AdapterResult.model_validate(
            {
                "status": status,
                "attempts": 1,
                "output": json.dumps(valid_output(request)) if status == "completed" else None,
            }
        )

    monkeypatch.setattr(GroqAdapter, "generate", generate)
    result = CliRunner().invoke(app, ["analyze", "--text", "1.1.1.1", "--ai", "--format", "json"])
    assert result.exit_code == (130 if status == "cancelled" else 0)
    assert json.loads(result.stdout)["ai_reporting"]["status"] == status
    assert "synthetic-cli-canary" not in result.output


def test_existing_output_prevents_ai(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from traceguard import ai_service

    async def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("AI must not run")

    monkeypatch.setattr(ai_service, "run_ai", forbidden)
    target = tmp_path / "existing.json"
    target.write_text("preserve")
    result = CliRunner().invoke(
        app, ["analyze", "--text", "1.1.1.1", "--ai", "--output", str(target)]
    )
    assert result.exit_code == 2 and target.read_text() == "preserve"
