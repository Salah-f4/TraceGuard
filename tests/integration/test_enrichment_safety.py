"""Additional trust-boundary, streaming, cancellation, and pacing regressions."""

import asyncio
import base64
import json
import logging
from collections.abc import AsyncIterator

import httpx
import pytest

from tests.support import Clock, adapter, body_for, lookup
from traceguard.adapters.intelligence.http import LookupHTTP
from traceguard.config import Credentials
from traceguard.core.enrichment import enrich_report
from traceguard.core.intelligence import PROVIDERS, LookupIOC
from traceguard.core.investigation import analyze_text
from traceguard.core.models import IOCType

IOC = LookupIOC(type=IOCType.IPV4, normalized_value="8.8.8.8")


def test_fragment_never_sent_and_reuses_lookup(credentials: Credentials) -> None:
    async def run() -> None:
        requests: list[httpx.Request] = []
        clean = LookupIOC(type=IOCType.URL, normalized_value="https://public-site.com/Path")

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            encoded = request.url.path.rsplit("/", 1)[-1]
            decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
            assert decoded == clean.normalized_value
            return httpx.Response(200, json=body_for("virustotal", clean))

        client = LookupHTTP(
            "virustotal", credentials, Clock().runtime(), transport=httpx.MockTransport(respond)
        )
        try:
            offline = analyze_text(
                "https://public-site.com/Path#user@mail.com https://public-site.com/Path#two"
            )
            report = await enrich_report(offline, {"virustotal": adapter("virustotal", client)})
            assert len(requests) == 1
            assert report.results[0].normalized_value.endswith("#user@mail.com")
            assert all(
                r.fragment_stripped
                for r in report.provider_results
                if r.provider_id == "virustotal"
            )
        finally:
            await client.close()

    asyncio.run(run())


def test_pacing_counts_retries(credentials: Credentials) -> None:
    clock = Clock()
    starts: list[float] = []

    def respond(_: httpx.Request) -> httpx.Response:
        starts.append(clock.now)
        return httpx.Response(503)

    result = asyncio.run(lookup(credentials, "virustotal", IOC, respond, runtime=clock.runtime()))
    assert starts == [0, 16, 32]
    assert result.attempts == 3


def test_global_budget_across_providers(credentials: Credentials) -> None:
    async def run() -> None:
        runtime = Clock().runtime(max_attempts=3)
        clients = {
            p: LookupHTTP(
                p,
                credentials,
                runtime,
                transport=httpx.MockTransport(lambda _: httpx.Response(500)),
            )
            for p in PROVIDERS
        }
        try:
            report = await enrich_report(
                analyze_text("8.8.8.8 1.1.1.1"), {p: adapter(p, clients[p]) for p in clients}
            )
            assert runtime.attempts == 3
            assert report.enrichment.attempts == 3
            assert len(report.provider_results) == 6
            assert any(r.status == "skipped_budget" for r in report.provider_results)
        finally:
            for client in clients.values():
                await client.close()

    asyncio.run(run())


def test_slow_stream_wall_deadline(credentials: Credentials) -> None:
    class WaitingStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            await asyncio.Event().wait()
            yield b"{}"

    result = asyncio.run(
        lookup(
            credentials,
            "urlhaus",
            IOC,
            lambda _: httpx.Response(200, stream=WaitingStream()),
            runtime=Clock().runtime(seconds=0.001),
        )
    )
    assert result.status in {"timeout", "skipped_budget"}
    assert result.attempts == 1


def test_cancel_inflight_transport_keeps_attempt_metadata(credentials: Credentials) -> None:
    async def run() -> None:
        entered = asyncio.Event()

        async def respond(_: httpx.Request) -> httpx.Response:
            entered.set()
            await asyncio.Event().wait()
            return httpx.Response(200)

        client = LookupHTTP(
            "urlhaus", credentials, Clock().runtime(), transport=httpx.MockTransport(respond)
        )
        try:
            task = asyncio.create_task(adapter("urlhaus", client).lookup(IOC))
            await entered.wait()
            task.cancel()
            result = await task
            assert result.status == "cancelled"
            assert result.attempts == 1
            assert result.completed_at is not None
        finally:
            await client.close()

    asyncio.run(run())


def test_escaped_reflected_mock_token_blocked(credentials: Credentials) -> None:
    token = credentials.get("urlhaus")
    assert token is not None
    body = body_for("urlhaus", IOC)
    body["signature"] = token.get_secret_value()
    payload = json.dumps(body)
    escaped = "".join(f"\\u{ord(char):04x}" for char in token.get_secret_value())
    payload = payload.replace(token.get_secret_value(), escaped)
    result = asyncio.run(
        lookup(credentials, "urlhaus", IOC, lambda _: httpx.Response(200, content=payload))
    )
    assert result.status == "invalid_response"
    assert not credentials.contains(result.model_dump_json())


def test_mock_token_cannot_be_sent_as_ioc_path(credentials: Credentials) -> None:
    token = credentials.get("urlhaus")
    assert token is not None
    ioc = LookupIOC(
        type=IOCType.URL, normalized_value="https://public-site.com/" + token.get_secret_value()
    )
    result = asyncio.run(lookup(credentials, "urlhaus", ioc, lambda _: pytest.fail("disclosure")))
    assert result.status == "skipped_sensitive_url"
    assert not result.attempted


def test_http_logging_is_suppressed(
    credentials: Credentials,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def respond(_: httpx.Request) -> httpx.Response:
        logging.getLogger("httpcore.http11").debug("synthetic header canary")
        return httpx.Response(200, json=body_for("urlhaus", IOC))

    with caplog.at_level(logging.DEBUG):
        result = asyncio.run(lookup(credentials, "urlhaus", IOC, respond))
    assert result.status == "found"
    assert "synthetic header canary" not in caplog.text
    assert not credentials.contains(caplog.text)


@pytest.mark.parametrize("payload", [b"not json", b'{"error": null}', b"{}"])
def test_vt_404_requires_documented_notfound(payload: bytes, credentials: Credentials) -> None:
    result = asyncio.run(
        lookup(credentials, "virustotal", IOC, lambda _: httpx.Response(404, content=payload))
    )
    assert result.status == "provider_error"


def test_remaining_zero_on_retryable_stops(credentials: Credentials) -> None:
    result = asyncio.run(
        lookup(
            credentials,
            "urlhaus",
            IOC,
            lambda _: httpx.Response(429, headers={"X-RateLimit-Remaining": "0"}),
        )
    )
    assert result.status == "rate_limited"
    assert result.attempts == 1
