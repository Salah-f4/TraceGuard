"""Schema 1.2 CLI contracts and synthetic credential redaction, with no live I/O."""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.unit.test_scoring import NOW, report_for, vt
from traceguard import bootstrap
from traceguard.adapters.cli import app as cli_module
from traceguard.config import ENV_NAMES, Credentials
from traceguard.core.intelligence import EnrichedReport
from traceguard.core.models import AnalysisReport


class FrozenDateTime:
    @classmethod
    def now(cls, tz: object = None) -> datetime:
        return NOW


def test_cli_offline_schema_and_terminal_json_export_parity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli_module, "datetime", FrozenDateTime)
    runner = CliRunner()
    args = ["analyze", "--text", "1.1.1.1 public-site.com https://public-site.com/"]
    j = runner.invoke(cli_module.app, [*args, "--format", "json"])
    t = runner.invoke(cli_module.app, args)
    assert j.exit_code == t.exit_code == 0
    report = json.loads(j.stdout)
    assert report["schema_version"] == "1.2" and "enrichment" not in report
    assert all(a["risk_score"] == a["evidence_confidence"] == 0 for a in report["assessments"])
    assert all(a["label"] == "unknown" for a in report["assessments"])
    assert report["relationships"]["edges"]
    assert (
        json.loads(
            t.stdout.split("Complete assessment and relationship breakdown (schema 1.2):\n")[1]
        )
        == report
    )
    output = tmp_path / "assessed.json"
    saved = runner.invoke(cli_module.app, [*args, "--format", "json", "--output", str(output)])
    assert saved.exit_code == 0 and json.loads(output.read_text()) == report


@pytest.mark.parametrize("format_name", ["terminal", "json"])
def test_new_breakdown_redacts_synthetic_credentials(
    monkeypatch: pytest.MonkeyPatch,
    credentials: Credentials,
    format_name: str,
) -> None:
    secret = credentials.get("virustotal")
    assert secret is not None
    monkeypatch.setenv(ENV_NAMES["virustotal"], secret.get_secret_value())
    item = vt(10)
    assert item.evidence is not None
    item.evidence.reference = "https://synthetic.invalid/" + secret.get_secret_value()

    async def fake_enrichment(report: AnalysisReport, configured: Credentials) -> EnrichedReport:
        return report_for([item])

    monkeypatch.setattr(bootstrap, "run_enrichment", fake_enrichment)
    result = CliRunner().invoke(
        cli_module.app, ["analyze", "--text", "1.1.1.1", "--enrich", "--format", format_name]
    )
    assert result.exit_code == 0
    assert not credentials.contains(result.output)
    assert "[REDACTED]" in result.output
    assert "evidence_id" in result.output


def test_replay_across_process_hash_seeds(tmp_path: Path) -> None:
    # Standalone children call only pure core functions; no config or enrichment.
    program = """
import socket
from datetime import UTC, datetime
from traceguard.core.investigation import analyze_text
from traceguard.core.scoring import assess_report
def forbidden(*args, **kwargs):
    raise AssertionError('network forbidden')
socket.getaddrinfo = forbidden
socket.socket.connect = forbidden
r=analyze_text('1.1.1.1 public-site.com https://public-site.com/')
print(assess_report(r,scoring_as_of=datetime(2026,9,25,tzinfo=UTC)).model_dump_json())
"""
    outputs = []
    for seed in ("1", "987"):
        result = subprocess.run(
            [sys.executable, "-c", program],
            cwd=tmp_path,
            env={**os.environ, "PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            check=True,
        )
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1]
