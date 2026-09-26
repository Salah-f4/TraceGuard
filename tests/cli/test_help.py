"""Smoke tests for the public CLI shell."""

import pytest
from typer.testing import CliRunner

from traceguard.adapters.cli.app import app

runner = CliRunner()


@pytest.mark.parametrize("arguments", [[], ["--help"], ["help"]])
def test_help_succeeds(arguments: list[str]) -> None:
    result = runner.invoke(app, arguments)
    assert result.exit_code == 0, result.output
    assert "TraceGuard" in result.output
    assert "Usage:" in result.output


def test_placeholder_describes_current_scope() -> None:
    result = runner.invoke(app, ["help"])
    assert result.exit_code == 0, result.output
    assert "not implemented" in result.output


def test_unknown_command_fails() -> None:
    result = runner.invoke(app, ["analyze"])
    assert result.exit_code != 0
