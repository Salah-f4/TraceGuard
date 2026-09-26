"""End-to-end opt-in CLI tests with mock transports and generated inert tokens."""

import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from typer.testing import CliRunner

from tests.support import Clock, body_for
from traceguard import bootstrap
from traceguard.adapters.cli.app import app
from traceguard.adapters.intelligence.http import LookupHTTP, Runtime
from traceguard.config import ENV_NAMES, Credentials
from traceguard.core.intelligence import EnrichedReport, LookupIOC, ProviderID
from traceguard.core.models import IOCType

runner = CliRunner()


@pytest.fixture
def mock_clients(monkeypatch: pytest.MonkeyPatch, credentials: Credentials) -> list[httpx.Request]:
    requests: list[httpx.Request] = []
    clock = Clock()
    for provider, name in ENV_NAMES.items():
        token = credentials.get(provider)
        assert token is not None
        monkeypatch.setenv(name, token.get_secret_value())

    def factory(provider: ProviderID, configured: Credentials, runtime: Runtime) -> LookupHTTP:
        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            value = (
                request.url.path.rsplit("/", 1)[-1]
                if provider == "virustotal"
                else request.url.params["ipAddress"]
                if provider == "abuseipdb"
                else parse_qs(request.content.decode())["host"][0]
            )
            ioc = LookupIOC(type=IOCType.IPV4, normalized_value=value)
            return httpx.Response(200, json=body_for(provider, ioc))

        return LookupHTTP(provider, configured, runtime, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(bootstrap, "LookupHTTP", factory)
    monkeypatch.setattr(bootstrap, "Runtime", clock.runtime)
    return requests


def test_no_enrich_does_not_load_credentials_or_make_client(
    monkeypatch: pytest.MonkeyPatch,
    mock_clients: list[httpx.Request],
) -> None:
    def forbidden() -> Credentials:
        pytest.fail("Offline analysis read provider credentials.")

    monkeypatch.setattr(Credentials, "from_environment", forbidden)
    result = runner.invoke(app, ["analyze", "--text", "8.8.8.8", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["schema_version"] == "1.2"
    assert "enrichment" not in json.loads(result.stdout)
    assert not mock_clients


@pytest.mark.parametrize("mode", ["terminal", "json"])
def test_enrich_cli(mode: str, mock_clients: list[httpx.Request], credentials: Credentials) -> None:
    result = runner.invoke(app, ["analyze", "--text", "8.8.8.8", "--enrich", "--format", mode])
    assert result.exit_code == 0
    assert len(mock_clients) == 3
    assert not credentials.contains(result.output)
    assert "virustotal" in result.stdout
    assert "abuseipdb" in result.stdout
    assert "urlhaus" in result.stdout
    if mode == "json":
        report = EnrichedReport.model_validate_json(result.stdout)
        assert report.enrichment.completeness == "complete"
        assert all(r.status == "found" for r in report.provider_results)


def test_missing_keys_json_keeps_offline_results() -> None:
    result = runner.invoke(app, ["analyze", "--text", "8.8.8.8", "--enrich", "--format", "json"])
    assert result.exit_code == 0
    report = EnrichedReport.model_validate_json(result.stdout)
    assert report.results[0].normalized_value == "8.8.8.8"
    assert report.enrichment.completeness == "unavailable"
    assert "Warning" in result.stderr


def test_enrich_with_local_dotenv(
    monkeypatch: pytest.MonkeyPatch,
    mock_clients: list[httpx.Request],
    credentials: Credentials,
) -> None:
    lines = []
    for provider, name in ENV_NAMES.items():
        token = credentials.get(provider)
        assert token is not None
        lines.append(f"{name}={token.get_secret_value()}")
        monkeypatch.delenv(name)
    Path(".env").write_text("\n".join(lines), encoding="utf-8")
    result = runner.invoke(app, ["analyze", "--text", "1.1.1.1", "--enrich", "--format", "json"])
    assert result.exit_code == 0
    assert len(mock_clients) == 3
    assert not credentials.contains(result.output)
    report = EnrichedReport.model_validate_json(result.stdout)
    assert all(outcome.status == "found" for outcome in report.provider_results)


def test_enriched_export(tmp_path: Path, mock_clients: list[httpx.Request]) -> None:
    target = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "analyze",
            "--text",
            "8.8.8.8",
            "--enrich",
            "--format",
            "json",
            "--output",
            str(target),
        ],
    )
    assert result.exit_code == 0
    assert result.stdout == ""
    report = EnrichedReport.model_validate_json(target.read_text(encoding="utf-8"))
    assert len(report.provider_results) == 3


def test_raw_context_not_in_requests(tmp_path: Path, mock_clients: list[httpx.Request]) -> None:
    source = tmp_path / "private-filename.log"
    source.write_text(
        "private-source-line src=8[.]8[.]8[.]8 user=private@public-site.com", encoding="utf-8"
    )
    result = runner.invoke(app, ["analyze", "--file", str(source), "--enrich", "--format", "json"])
    assert result.exit_code == 0
    for request in mock_clients:
        outbound = str(request.url) + request.content.decode()
        assert "private-" not in outbound
        assert "private@" not in outbound
        assert "[.]" not in outbound


def test_sensitive_urls_skipped_before_clients(mock_clients: list[httpx.Request]) -> None:
    result = runner.invoke(
        app,
        [
            "analyze",
            "--text",
            "https://public-site.com/?q=user@mail.com https://user:pass@public-site.com/",
            "--enrich",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0
    report = EnrichedReport.model_validate_json(result.stdout)
    assert {r.status for r in report.provider_results} == {
        "skipped_url_query",
        "skipped_sensitive_url",
    }
    assert not mock_clients


def test_no_query_override_yet() -> None:
    result = runner.invoke(app, ["analyze", "--text", "8.8.8.8", "--include-url-query"])
    assert result.exit_code == 2


def test_blank_keys_disable(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ENV_NAMES.values():
        monkeypatch.setenv(name, " ")
    assert all(Credentials.from_environment().get(provider) is None for provider in ENV_NAMES)


def test_interrupt_export_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tests.unit.test_enrichment import StubProvider
    from traceguard.core.enrichment import enrich_report
    from traceguard.core.models import AnalysisReport

    async def interrupted(report: AnalysisReport, credentials: Credentials) -> EnrichedReport:
        return await enrich_report(report, {"virustotal": StubProvider("virustotal", "cancelled")})

    monkeypatch.setattr(bootstrap, "run_enrichment", interrupted)
    result = runner.invoke(app, ["analyze", "--text", "8.8.8.8", "--enrich", "--format", "json"])
    assert result.exit_code == 130
    assert EnrichedReport.model_validate_json(result.stdout).enrichment.cancelled
