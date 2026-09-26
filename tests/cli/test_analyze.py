"""Exercise CLI inputs, report export, and explicit failure behavior."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from traceguard.adapters.cli.app import app
from traceguard.core.models import MAX_INPUT_BYTES, AnalysisReport

runner = CliRunner()


def test_json_text() -> None:
    result = runner.invoke(app, ["analyze", "--text", "Example.COM", "--format", "json"])
    assert result.exit_code == 0, result.output
    report = AnalysisReport.model_validate_json(result.stdout)
    assert report.results[0].normalized_value == "example.com"
    assert result.stderr == ""


def test_stdin() -> None:
    result = runner.invoke(app, ["analyze", "--stdin", "--format", "json"], input="192.0.2.1")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["source"] == "<stdin>"


def test_file_and_export(tmp_path: Path) -> None:
    source = tmp_path / "sample.log"
    output = tmp_path / "report.json"
    source.write_text("user@EXAMPLE.COM\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "analyze",
            "--file",
            str(source),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    assert result.stdout == ""
    report = AnalysisReport.model_validate_json(output.read_text(encoding="utf-8"))
    assert report.results[0].normalized_value == "user@example.com"
    assert report.source == str(source)


def test_bom_file(tmp_path: Path) -> None:
    source = tmp_path / "sample.TXT"
    source.write_bytes(b"\xef\xbb\xbfexample.com")
    result = runner.invoke(app, ["analyze", "--file", str(source), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["results"][0]["source_location"]["start_offset"] == 0


def test_terminal_does_not_interpret_markup() -> None:
    result = runner.invoke(app, ["analyze", "--text", "http://example.com/[bold]X[/bold]"])
    assert result.exit_code == 0
    assert "[bold]X[/bold]" in result.stdout
    assert "Zero/unknown never means safe" in result.stdout


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([], "exactly one"),
        (["--text", "example.com", "--stdin"], "exactly one"),
        (["--text", ""], "empty"),
        (["--text", "ordinary text"], "No supported"),
        (["--file", "sample.csv"], "Unsupported file type"),
        (["--file", "absent.log"], "not a regular file"),
        (["--text", "example.com", "--format", "xml"], "Invalid value"),
    ],
)
def test_errors(args: list[str], message: str) -> None:
    result = runner.invoke(app, ["analyze", *args])
    assert result.exit_code == 2, result.output
    assert message in result.output
    assert result.stdout == ""


@pytest.mark.parametrize(
    "data",
    [b"\xff", b"\x00example.com", b" " * (MAX_INPUT_BYTES + 1)],
    ids=["invalid-utf8", "binary", "too-large"],
)
def test_file_encoding_binary_and_size_errors(tmp_path: Path, data: bytes) -> None:
    source = tmp_path / "bad.log"
    source.write_bytes(data)
    result = runner.invoke(app, ["analyze", "--file", str(source)])
    assert result.exit_code == 2
    assert "Error:" in result.stderr


def test_oversized_stdin() -> None:
    result = runner.invoke(app, ["analyze", "--stdin"], input="x" * (MAX_INPUT_BYTES + 1))
    assert result.exit_code == 2
    assert "1,000,000" in result.stderr


def test_export_does_not_overwrite_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "existing.json"
    target.write_text("keep", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "analyze",
            "--text",
            "example.com",
            "--format",
            "json",
            "--output",
            str(target),
        ],
    )
    assert result.exit_code == 2
    assert target.read_text(encoding="utf-8") == "keep"


def test_failed_input_does_not_create_report(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            "--text",
            "",
            "--format",
            "json",
            "--output",
            str(target),
        ],
    )
    assert result.exit_code == 2
    assert not target.exists()
