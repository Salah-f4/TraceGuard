"""Fixed-origin, bounded report transport. Never scans or follows report links."""

import asyncio
import base64
import json
import logging
import random
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import quote

import httpx

from traceguard.config import Credentials
from traceguard.core.eligibility import eligible
from traceguard.core.intelligence import (
    CAPABILITIES,
    LookupIOC,
    ProviderEvidence,
    ProviderID,
    ProviderOutcome,
)
from traceguard.core.models import IOCType

Parser = Callable[[dict[str, object], LookupIOC], ProviderEvidence | None]
MAX_RESPONSE_BYTES = 2_000_000
_RETRYABLE = {408, 429, 500, 502, 503, 504}
_ORIGINS: dict[ProviderID, str] = {
    "virustotal": "https://www.virustotal.com",
    "abuseipdb": "https://api.abuseipdb.com",
    "urlhaus": "https://urlhaus-api.abuse.ch",
}
_HEADERS: dict[ProviderID, str] = {
    "virustotal": "x-apikey",
    "abuseipdb": "Key",
    "urlhaus": "Auth-Key",
}


def quiet_http_logs() -> None:
    # HTTP libraries can log IOC-bearing URLs and arbitrary server headers.
    # Silence these namespaces without changing the application's logger.
    for name in (
        "httpx",
        "httpcore",
        "httpcore.connection",
        "httpcore.http11",
        "httpcore.http2",
        "httpcore.proxy",
        "httpcore.socks",
        "httpcore.connection_pool",
        "httpcore.http_proxy",
        "httpcore.socks_proxy",
    ):
        logger = logging.getLogger(name)
        logger.disabled = True


@dataclass(frozen=True)
class RequestSpec:
    method: str
    url: str
    params: dict[str, str]
    data: dict[str, str]


def request_spec(provider: ProviderID, ioc: LookupIOC) -> RequestSpec:
    """Construct requests only from a closed method/endpoint/field allowlist."""
    decision = eligible(ioc)
    if decision.lookup != ioc or ioc.type not in CAPABILITIES[provider]:
        raise ValueError("Lookup is not eligible.")
    value = ioc.normalized_value
    params: dict[str, str] = {}
    data: dict[str, str] = {}
    method = "GET"
    if provider == "virustotal":
        if ioc.type in {IOCType.IPV4, IOCType.IPV6}:
            collection = "ip_addresses"
        elif ioc.type == IOCType.DOMAIN:
            collection = "domains"
        elif ioc.type == IOCType.URL:
            collection = "urls"
            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        else:
            collection = "files"
        path = f"/api/v3/{collection}/{quote(value, safe='')}"
    elif provider == "abuseipdb":
        path = "/api/v2/check"
        params = {"ipAddress": value, "maxAgeInDays": "90"}
    else:
        method = "POST"
        if ioc.type == IOCType.URL:
            path, data = "/v1/url/", {"url": value}
        elif ioc.type in {IOCType.IPV4, IOCType.DOMAIN}:
            path, data = "/v1/host/", {"host": value}
        else:
            field = "md5_hash" if ioc.type == IOCType.MD5 else "sha256_hash"
            path, data = "/v1/payload/", {field: value}
    return RequestSpec(method, _ORIGINS[provider] + path, params, data)


class Runtime:
    """One run's shared quota and injectable clocks; no disk quota persistence."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        jitter: Callable[[], float] = lambda: random.uniform(0, 0.5),
        max_attempts: int = 30,
        seconds: float = 120,
    ) -> None:
        self.clock, self.utcnow, self.sleep, self.jitter = clock, utcnow, sleep, jitter
        self.max_attempts = max_attempts
        self.deadline = clock() + seconds
        self.attempts = 0

    def remaining(self) -> float:
        return max(0, self.deadline - self.clock())

    def claim(self) -> bool:
        if not self.remaining() or self.attempts >= self.max_attempts:
            return False
        self.attempts += 1
        return True


def retry_delay(value: str | None, now: datetime) -> float | None:
    if value is None:
        return None
    try:
        if value.strip().isdigit():
            return float(value.strip())
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            return None
        return max(0, (parsed - now).total_seconds())
    except (ValueError, TypeError, OverflowError):
        return None


class LookupHTTP:
    def __init__(
        self,
        provider: ProviderID,
        credentials: Credentials,
        runtime: Runtime,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.provider = provider
        self._credentials = credentials
        self.runtime = runtime
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self._next_start = 0.0
        self._quota_exhausted = False

    def __repr__(self) -> str:
        return f"LookupHTTP(provider={self.provider!r})"

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def lookup(self, ioc: LookupIOC, parser: Parser) -> ProviderOutcome:
        result = ProviderOutcome(
            provider_id=self.provider,
            status="skipped_budget",
            reason="Enrichment budget exhausted.",
            started_at=self.runtime.utcnow(),
        )
        try:
            return await self._lookup(ioc, parser, result)
        except asyncio.CancelledError:
            result.status, result.reason = "cancelled", "Enrichment was interrupted."
            return result
        finally:
            result.completed_at = self.runtime.utcnow()

    async def _lookup(
        self,
        ioc: LookupIOC,
        parser: Parser,
        result: ProviderOutcome,
    ) -> ProviderOutcome:
        decision = eligible(ioc)
        if decision.lookup != ioc:
            result.status = decision.status or "skipped_sensitive_url"
            result.reason = "Lookup must pass the normalized disclosure policy."
            return result
        if ioc.type not in CAPABILITIES[self.provider]:
            result.status, result.reason = "skipped_unsupported", "Unsupported IOC type."
            return result
        token = self._credentials.get(self.provider)
        if token is None:
            result.status, result.reason = "disabled_missing_key", "Provider key is not configured."
            return result
        if self._credentials.contains(ioc.normalized_value):
            result.status, result.reason = "skipped_sensitive_url", "Credential disclosure blocked."
            return result
        if self._quota_exhausted:
            result.status, result.reason = "rate_limited", "Provider quota exhausted."
            return result
        spec = request_spec(self.provider, ioc)
        interval = 16.0 if self.provider == "virustotal" else 1.0
        backoff = 0.0
        for attempt in range(3):
            await asyncio.sleep(0)  # Share the attempt budget among ready provider queues.
            delay = max(backoff, self._next_start - self.runtime.clock(), 0)
            if (
                delay >= self.runtime.remaining()
                or self.runtime.attempts >= self.runtime.max_attempts
            ):
                result.status, result.reason = "skipped_budget", "Enrichment budget exhausted."
                return result
            if delay:
                await self.runtime.sleep(delay)
            if not self.runtime.claim():
                result.status, result.reason = "skipped_budget", "Enrichment budget exhausted."
                return result
            result.attempted = True
            result.attempts += 1
            self._next_start = self.runtime.clock() + interval
            if self._client is None:
                quiet_http_logs()
                self._client = httpx.AsyncClient(
                    verify=True,
                    trust_env=False,
                    follow_redirects=False,
                    transport=self._transport,
                    timeout=httpx.Timeout(connect=3, pool=3, write=5, read=10),
                )
            try:
                async with asyncio.timeout(min(15.0, self.runtime.remaining())):
                    async with self._client.stream(
                        spec.method,
                        spec.url,
                        params=spec.params,
                        data=spec.data or None,
                        headers={
                            _HEADERS[self.provider]: token.get_secret_value(),
                            "Accept": "application/json",
                        },
                    ) as response:
                        result.http_status = response.status_code
                        result.fetched_at = self.runtime.utcnow()
                        result.retry_after = retry_delay(
                            response.headers.get("Retry-After"), self.runtime.utcnow()
                        )
                        if response.headers.get("X-RateLimit-Remaining") == "0":
                            self._quota_exhausted = True
                        body = bytearray()
                        async for chunk in response.aiter_bytes(chunk_size=65_536):
                            if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                                result.status = "response_too_large"
                                result.reason = "Provider response exceeded the safe size limit."
                                return result
                            body.extend(chunk)
                        status = response.status_code
                # Reject reflected keys without exposing body or exception text.
                decoded = body.decode("utf-8", errors="replace")
                if self._credentials.contains(decoded):
                    result.status, result.reason = "invalid_response", "Unsafe provider response."
                    return result
                if status in {401, 403}:
                    result.status, result.reason = "auth_error", "Provider authentication failed."
                    return result
                if status in _RETRYABLE:
                    result.status = "rate_limited" if status == 429 else "provider_error"
                    result.reason = (
                        "Provider rate limit." if status == 429 else "Transient provider failure."
                    )
                    if self._quota_exhausted:
                        result.status, result.reason = "rate_limited", "Provider quota exhausted."
                        return result
                elif status == 404 and self.provider == "virustotal":
                    try:
                        payload = json.loads(decoded)
                        absent = (
                            isinstance(payload, dict)
                            and payload.get("error", {}).get("code") == "NotFoundError"
                        )
                    except (ValueError, AttributeError):
                        absent = False
                    result.status = "not_found" if absent else "provider_error"
                    result.reason = "No existing report." if absent else "Provider request failed."
                    return result
                elif status != 200:
                    result.status, result.reason = "provider_error", "Provider request failed."
                    return result
                else:
                    try:
                        payload = json.loads(decoded)
                        if not isinstance(payload, dict):
                            raise ValueError
                        evidence = parser(payload, ioc)
                        if evidence is not None and self._credentials.contains(
                            evidence.model_dump_json()
                        ):
                            raise ValueError
                    except (ValueError, TypeError, KeyError, OverflowError, OSError):
                        result.status, result.reason = (
                            "invalid_response",
                            "Invalid provider report.",
                        )
                        return result
                    result.evidence = evidence
                    result.status = "found" if evidence is not None else "not_found"
                    result.reason = (
                        "Existing provider report."
                        if evidence is not None
                        else "No existing report."
                    )
                    return result
            except (httpx.TimeoutException, TimeoutError):
                result.status, result.reason = "timeout", "Provider request timed out."
            except httpx.TransportError as exc:
                cause: BaseException | None = exc
                while cause is not None:
                    if isinstance(cause, ssl.SSLError):
                        result.status, result.reason = "network_error", "TLS verification failed."
                        return result
                    cause = cause.__cause__
                result.status, result.reason = "network_error", "Provider transport failed."
            if attempt == 2:
                return result
            if result.retry_after is not None:
                if result.retry_after > 60 or result.retry_after >= self.runtime.remaining():
                    result.status, result.reason = "rate_limited", "Provider retry deferred."
                    return result
            backoff = max(
                min(10, 2**attempt + self.runtime.jitter()),
                result.retry_after or 0,
            )
        return result
