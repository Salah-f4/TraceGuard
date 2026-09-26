"""Local configuration tests use generated inert credentials in isolated directories."""

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from traceguard.adapters.cli.app import app
from traceguard.config import ENV_NAMES, Credentials
from traceguard.core.models import InputError


def test_local_dotenv(credentials: Credentials) -> None:
    lines = []
    for provider, name in ENV_NAMES.items():
        token = credentials.get(provider)
        assert token is not None
        lines.append(f'export {name}="{token.get_secret_value()}"')
    Path(".env").write_text("\n".join(lines), encoding="utf-8-sig")
    loaded = Credentials.from_environment()
    for provider, name in ENV_NAMES.items():
        assert loaded.get(provider) == credentials.get(provider)
        assert name not in os.environ
    assert not credentials.contains(repr(loaded))


@pytest.mark.parametrize("override", ["", " ", "synthetic-process-value"])
def test_environment_precedence(monkeypatch: pytest.MonkeyPatch, override: str) -> None:
    name = ENV_NAMES["virustotal"]
    Path(".env").write_text(f"{name}=synthetic-file-value", encoding="utf-8")
    monkeypatch.setenv(name, override)
    token = Credentials.from_environment().get("virustotal")
    assert (token.get_secret_value() if token else "") == override.strip()


def test_no_expansion_and_only_allowed_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXPAND_ME", "synthetic-expanded-value")
    Path(".env").write_text(
        "TRACEGUARD_VIRUSTOTAL_API_KEY=${EXPAND_ME}\nUNRELATED=ignored\n", encoding="utf-8"
    )
    loaded = Credentials.from_environment()
    token = loaded.get("virustotal")
    assert token is not None
    assert token.get_secret_value() == "${EXPAND_ME}"
    assert "UNRELATED" not in os.environ
    assert loaded.get("abuseipdb") is None


def test_no_parent_search_and_exact_filename(monkeypatch: pytest.MonkeyPatch) -> None:
    Path(".env").write_text("TRACEGUARD_VIRUSTOTAL_API_KEY=synthetic-parent", encoding="utf-8")
    Path("child").mkdir()
    monkeypatch.chdir("child")
    Path(".env.txt").write_text("TRACEGUARD_VIRUSTOTAL_API_KEY=synthetic-txt", encoding="utf-8")
    assert Credentials.from_environment().get("virustotal") is None


def test_disable_local_loading() -> None:
    Path(".env").write_text("TRACEGUARD_VIRUSTOTAL_API_KEY=synthetic-file", encoding="utf-8")
    assert Credentials.from_environment(dotenv_path=None).get("virustotal") is None


@pytest.mark.parametrize(
    "content", ["TRACEGUARD_VIRUSTOTAL_API_KEY=\n", "TRACEGUARD_VIRUSTOTAL_API_KEY\n"]
)
def test_empty_values(content: str) -> None:
    Path(".env").write_text(content, encoding="utf-8")
    assert Credentials.from_environment().get("virustotal") is None


def test_invalid_encoding_safe_cli_error() -> None:
    Path(".env").write_bytes(b"\xffsynthetic-private-content")
    with pytest.raises(InputError, match=r"^Unable to read local \.env configuration\.$"):
        Credentials.from_environment()
    result = CliRunner().invoke(app, ["analyze", "--text", "1.1.1.1", "--enrich"])
    assert result.exit_code == 2
    assert "synthetic-private-content" not in result.output
    assert "Unable to read local .env configuration." in result.output


def test_unreadable_file() -> None:
    Path(".env").mkdir()
    with pytest.raises(InputError, match="Unable to read local"):
        Credentials.from_environment()


def test_offline_does_not_read_dotenv() -> None:
    Path(".env").write_bytes(b"\xffinvalid")
    result = CliRunner().invoke(app, ["analyze", "--text", "1.1.1.1"])
    assert result.exit_code == 0
