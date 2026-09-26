"""All tests are offline and discard inherited provider credentials."""

import secrets
import socket
from pathlib import Path
from typing import NoReturn

import httpx
import pytest
from pydantic import SecretStr

from traceguard.config import ENV_NAMES, Credentials
from traceguard.core.intelligence import PROVIDERS


@pytest.fixture(autouse=True)
def no_live_network_or_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Never discover the developer's real .env during any test.
    monkeypatch.chdir(tmp_path)
    original_pair = socket.socketpair
    original_connect = socket.socket.connect

    def internal_socketpair() -> tuple[socket.socket, socket.socket]:
        # Windows asyncio needs its local wakeup pipe before any HTTP work.
        with monkeypatch.context() as local:
            local.setattr(socket.socket, "connect", original_connect)
            return original_pair()

    for name in (
        *ENV_NAMES.values(),
        "TRACEGUARD_AI_API_KEY",
        "TRACEGUARD_OPENAI_API_KEY",
        "TRACEGUARD_GROQ_API_KEY",
        "TRACEGUARD_AI_PROVIDER",
        "TRACEGUARD_AI_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)

    def forbidden(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("Live network is forbidden in tests.")

    async def async_forbidden(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("Live HTTP is forbidden in tests.")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "socketpair", internal_socketpair)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", async_forbidden)


@pytest.fixture
def credentials() -> Credentials:
    # Generated inert tokens only; never real keys or saved credential fixtures.
    return Credentials(
        {provider: SecretStr("mock-" + secrets.token_hex(24)) for provider in PROVIDERS}
    )
