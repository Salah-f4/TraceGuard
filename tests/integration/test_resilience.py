"""Deterministic retries, deadlines, response safety, and quota tests."""

import asyncio
import json
import ssl
from datetime import UTC, datetime

import httpx
import pytest

from tests.support import Clock, body_for, lookup
from traceguard.adapters.intelligence.http import MAX_RESPONSE_BYTES, LookupHTTP, retry_delay
from traceguard.adapters.intelligence.urlhaus import URLhaus
from traceguard.config import Credentials
from traceguard.core.intelligence import LookupIOC
from traceguard.core.models import IOCType

IOC = LookupIOC(type=IOCType.IPV4, normalized_value="8.8.8.8")


@pytest.mark.parametrize(
    ("code", "expected", "attempts"),
    [
        (401, "auth_error", 1),
        (403, "auth_error", 1),
        (404, "provider_error", 1),
        (400, "provider_error", 1),
        (302, "provider_error", 1),
        (408, "provider_error", 3),
        (429, "rate_limited", 3),
        (500, "provider_error", 3),
        (502, "provider_error", 3),
        (503, "provider_error", 3),
        (504, "provider_error", 3),
    ],
)
def test_http_failures(code: int, expected: str, attempts: int, credentials: Credentials) -> None:
    seen: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(code, headers={"Location": "https://unrelated.invalid/"})

    result = asyncio.run(lookup(credentials, "urlhaus", IOC, respond))
    assert result.status == expected
    assert result.attempts == attempts
    assert len(seen) == attempts
    assert set(seen) == {"urlhaus-api.abuse.ch"}


@pytest.mark.parametrize("error", [httpx.ReadTimeout, httpx.ConnectError])
def test_transport_retries(error: type[httpx.TransportError], credentials: Credentials) -> None:
    clock = Clock()

    def respond(_: httpx.Request) -> httpx.Response:
        raise error("Do not expose this raw exception.")

    result = asyncio.run(lookup(credentials, "urlhaus", IOC, respond, runtime=clock.runtime()))
    assert result.status == ("timeout" if error is httpx.ReadTimeout else "network_error")
    assert result.attempts == 3
    assert clock.waits == [1.0, 2.0]
    assert "raw exception" not in result.model_dump_json()


def test_tls_failure_not_retried(credentials: Credentials) -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("hidden") from ssl.SSLCertVerificationError("hidden")

    result = asyncio.run(lookup(credentials, "urlhaus", IOC, respond))
    assert result.attempts == 1
    assert result.status == "network_error"


@pytest.mark.parametrize("header", ["90", "999999", "Wed, 23 Sep 2026 00:02:00 GMT"])
def test_long_retry_after_not_shortened(header: str, credentials: Credentials) -> None:
    clock = Clock()
    result = asyncio.run(
        lookup(
            credentials,
            "urlhaus",
            IOC,
            lambda _: httpx.Response(429, headers={"Retry-After": header}),
            runtime=clock.runtime(),
        )
    )
    assert result.status == "rate_limited"
    assert result.attempts == 1
    assert not clock.waits


def test_retry_then_success_honors_server_delay(credentials: Credentials) -> None:
    clock = Clock()
    calls = 0

    def respond(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return (
            httpx.Response(429, headers={"Retry-After": "5"})
            if calls == 1
            else httpx.Response(200, json=body_for("urlhaus", IOC))
        )

    result = asyncio.run(lookup(credentials, "urlhaus", IOC, respond, runtime=clock.runtime()))
    assert result.status == "found"
    assert result.attempts == 2
    assert clock.waits == [5.0]


@pytest.mark.parametrize("value", [None, "nonsense", "-3", "Wed, 23 Sep 2026 00:00:00"])
def test_invalid_retry_after(value: str | None) -> None:
    assert retry_delay(value, datetime(2026, 9, 23, tzinfo=UTC)) is None


@pytest.mark.parametrize(("attempts", "seconds"), [(0, 120), (30, 0), (1, 120), (30, 0.5)])
def test_budget_exhaustion(attempts: int, seconds: float, credentials: Credentials) -> None:
    clock = Clock()
    result = asyncio.run(
        lookup(
            credentials,
            "urlhaus",
            IOC,
            lambda _: httpx.Response(503),
            runtime=clock.runtime(max_attempts=attempts, seconds=seconds),
        )
    )
    assert result.status == "skipped_budget"
    assert result.attempts <= attempts


def test_large_response(credentials: Credentials) -> None:
    result = asyncio.run(
        lookup(
            credentials,
            "urlhaus",
            IOC,
            lambda _: httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)),
        )
    )
    assert result.status == "response_too_large"


def test_malformed_json(credentials: Credentials) -> None:
    result = asyncio.run(
        lookup(credentials, "urlhaus", IOC, lambda _: httpx.Response(200, content=b"not json"))
    )
    assert result.status == "invalid_response"


def test_reflected_mock_token_not_reported(credentials: Credentials) -> None:
    token = credentials.get("urlhaus")
    assert token is not None
    payload = json.dumps({"query_status": "ok", "error": token.get_secret_value()})
    result = asyncio.run(
        lookup(credentials, "urlhaus", IOC, lambda _: httpx.Response(200, content=payload))
    )
    assert result.status == "invalid_response"
    assert not credentials.contains(result.model_dump_json())
    assert not credentials.contains(repr(credentials))


def test_missing_credentials_no_request() -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        pytest.fail("A disabled provider attempted a request.")

    result = asyncio.run(lookup(Credentials({}), "urlhaus", IOC, respond))
    assert result.status == "disabled_missing_key"


def test_quota_header_blocks_next_lookup(credentials: Credentials) -> None:
    async def run() -> None:
        client = LookupHTTP(
            "urlhaus",
            credentials,
            Clock().runtime(),
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    json=body_for("urlhaus", IOC),
                    headers={"X-RateLimit-Remaining": "0"},
                )
            ),
        )
        try:
            first = await URLhaus(client).lookup(IOC)
            second = await URLhaus(client).lookup(IOC)
            assert first.status == "found"
            assert second.status == "rate_limited"
            assert not second.attempted
        finally:
            await client.close()

    asyncio.run(run())
