"""Mocked HTTP boundary tests; no real credentials or quota."""

import asyncio
import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from tests.ai_support import envelope, projected
from traceguard.adapters.ai.groq import ENDPOINT, GroqAdapter
from traceguard.core.ai_contracts import AILimits


def run(
    status: int = 200, body: Any = None, headers: dict[str, str] | None = None
) -> tuple[Any, list[httpx.Request]]:
    request = projected().request
    calls: list[httpx.Request] = []

    async def sleep(seconds: float) -> None:
        assert 0 <= seconds <= 10

    def handler(r: httpx.Request) -> httpx.Response:
        calls.append(r)
        return httpx.Response(
            status, json=envelope(request) if body is None else body, headers=headers
        )

    adapter = GroqAdapter(
        SecretStr("synthetic-test-only"), transport=httpx.MockTransport(handler), sleep=sleep
    )
    assert "synthetic-test-only" not in repr(adapter)
    return asyncio.run(adapter.generate(request, AILimits())), calls


def test_success_and_request_privacy() -> None:
    result, calls = run()
    assert result.status == "completed" and result.usage.total_tokens == 700
    assert len(calls) == 1 and str(calls[0].url) == ENDPOINT
    body = json.loads(calls[0].content)
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["stream"] is False and body["max_completion_tokens"] == 1000
    assert body["reasoning_effort"] == "none" and "tools" not in body
    assert "1.1.1.1" not in calls[0].content.decode()
    assert "synthetic-test-only" not in calls[0].content.decode()


@pytest.mark.parametrize(
    ("status", "expected", "attempts"),
    [
        (401, "auth_error", 1),
        (403, "auth_error", 1),
        (400, "provider_error", 1),
        (302, "provider_error", 1),
        (429, "rate_limited", 2),
        (502, "provider_error", 2),
        (503, "provider_error", 2),
        (504, "provider_error", 2),
    ],
)
def test_http_status(status: int, expected: str, attempts: int) -> None:
    result, calls = run(status)
    assert result.status == expected and len(calls) == attempts


@pytest.mark.parametrize("header", ["900", "garbage", "0"])
def test_retry_after(header: str) -> None:
    result, calls = run(429, headers={"Retry-After": header})
    assert result.status == "rate_limited"
    assert len(calls) == (1 if header == "900" else 2)


@pytest.mark.parametrize(
    "case",
    [
        "model",
        "usage",
        "total",
        "budget",
        "choices",
        "message",
        "refusal",
        "length",
        "tools",
        "content",
        "secret",
    ],
)
def test_invalid_envelope(case: str) -> None:
    body = envelope(projected().request)
    choice = body["choices"][0]
    if case == "model":
        body["model"] = "unexpected"
    elif case == "usage":
        body["usage"] = None
    elif case == "total":
        body["usage"]["total_tokens"] = 1
    elif case == "budget":
        body["usage"] = {"prompt_tokens": 4001, "completion_tokens": 1, "total_tokens": 4002}
    elif case == "choices":
        body["choices"] = []
    elif case == "message":
        choice["message"] = None
    elif case == "refusal":
        choice["message"]["refusal"] = "refused"
    elif case == "length":
        choice["finish_reason"] = "length"
    elif case == "tools":
        choice["message"]["tool_calls"] = [{}]
    elif case == "content":
        choice["message"]["content"] = []
    else:
        choice["message"]["content"] = "synthetic-test-only"
    result, calls = run(body=body)
    assert result.status == (
        "refused"
        if case == "refusal"
        else "skipped_budget"
        if case == "budget"
        else "invalid_output"
    )
    assert len(calls) == 1 and result.output is None


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (httpx.ReadTimeout("synthetic"), "timeout"),
        (httpx.ConnectError("synthetic"), "network_error"),
        (asyncio.CancelledError(), "cancelled"),
        (ValueError("synthetic"), "invalid_output"),
    ],
)
def test_exceptions_no_retry(error: BaseException, expected: str) -> None:
    calls = 0

    def handler(r: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise error

    result = asyncio.run(
        GroqAdapter(SecretStr("synthetic"), transport=httpx.MockTransport(handler)).generate(
            projected().request, AILimits()
        )
    )
    assert result.status == expected and calls == 1


def test_oversize_and_budget() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 65537)

    adapter = GroqAdapter(SecretStr("synthetic"), transport=httpx.MockTransport(handler))
    assert (
        asyncio.run(adapter.generate(projected().request, AILimits())).status
        == "response_too_large"
    )
    assert (
        asyncio.run(adapter.generate(projected().request, AILimits(input_tokens=1))).attempts == 0
    )


def test_deadline_before_dispatch() -> None:
    times = iter([0.0, 46.0])
    result = asyncio.run(
        GroqAdapter(SecretStr("synthetic"), clock=lambda: next(times)).generate(
            projected().request, AILimits()
        )
    )
    assert result.status == "timeout" and result.attempts == 0


def test_retry_success() -> None:
    request = projected().request
    calls = 0

    async def sleep(seconds: float) -> None:
        assert seconds == 1

    def handler(r: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503) if calls == 1 else httpx.Response(200, json=envelope(request))

    result = asyncio.run(
        GroqAdapter(
            SecretStr("synthetic"), transport=httpx.MockTransport(handler), sleep=sleep
        ).generate(request, AILimits())
    )
    assert result.status == "completed" and result.attempts == 2


def test_token_and_cost_boundaries() -> None:
    from traceguard.adapters.ai.groq import fits_budget, input_bound, request_body

    request = projected().request
    bound = input_bound(request_body(request, AILimits()))
    assert bound <= 4000
    assert fits_budget(request, AILimits(input_tokens=bound))
    assert not fits_budget(request, AILimits(input_tokens=bound - 1))
    assert not fits_budget(request, AILimits(cost_microusd=1))
