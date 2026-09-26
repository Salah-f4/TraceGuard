"""Generated mock authentication and deterministic offline-only helpers."""

import asyncio
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx

from traceguard.adapters.intelligence.abuseipdb import AbuseIPDB
from traceguard.adapters.intelligence.http import LookupHTTP, Runtime
from traceguard.adapters.intelligence.urlhaus import URLhaus
from traceguard.adapters.intelligence.virustotal import VirusTotal
from traceguard.config import Credentials
from traceguard.core.intelligence import LookupIOC, ProviderID, ProviderOutcome
from traceguard.core.models import IOCType
from traceguard.core.ports import IntelligenceProvider


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.waits: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def utcnow(self) -> datetime:
        return datetime(2026, 9, 23, tzinfo=UTC) + timedelta(seconds=self.now)

    async def sleep(self, seconds: float) -> None:
        self.waits.append(seconds)
        self.now += seconds
        await asyncio.sleep(0)

    def runtime(self, *, max_attempts: int = 30, seconds: float = 120) -> Runtime:
        return Runtime(
            clock=self.monotonic,
            utcnow=self.utcnow,
            sleep=self.sleep,
            jitter=lambda: 0.0,
            max_attempts=max_attempts,
            seconds=seconds,
        )


def body_for(provider: ProviderID, ioc: LookupIOC) -> dict[str, object]:
    if provider == "virustotal":
        kind = (
            "ip_address"
            if ioc.type in {IOCType.IPV4, IOCType.IPV6}
            else "domain"
            if ioc.type == IOCType.DOMAIN
            else "url"
            if ioc.type == IOCType.URL
            else "file"
        )
        attrs: dict[str, object] = {
            "last_analysis_stats": {"malicious": 2, "harmless": 4},
            "last_analysis_date": 1_700_000_000,
        }
        report_id = ioc.normalized_value
        if kind == "url":
            attrs["url"] = report_id
            report_id = hashlib.sha256(report_id.encode()).hexdigest()
        if kind == "file":
            attrs[ioc.type.value] = ioc.normalized_value
            report_id = "a" * 64
        return {"data": {"id": report_id, "type": kind, "attributes": attrs}}
    if provider == "abuseipdb":
        return {
            "data": {
                "ipAddress": ioc.normalized_value,
                "isPublic": True,
                "abuseConfidenceScore": 30,
                "totalReports": 2,
                "numDistinctUsers": 2,
                "lastReportedAt": "2026-09-20T00:00:00Z",
            }
        }
    identity = (
        "url"
        if ioc.type == IOCType.URL
        else "host"
        if ioc.type in {IOCType.IPV4, IOCType.DOMAIN}
        else "md5_hash"
        if ioc.type == IOCType.MD5
        else "sha256_hash"
    )
    return {
        "query_status": "ok",
        identity: ioc.normalized_value,
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
        "url_count": "2",
        "firstseen": "2026-09-20 00:00:00",
        "tags": ["synthetic"],
        "file_size": 42,
    }


def adapter(provider: ProviderID, http: LookupHTTP) -> IntelligenceProvider:
    if provider == "virustotal":
        return VirusTotal(http)
    if provider == "abuseipdb":
        return AbuseIPDB(http)
    return URLhaus(http)


async def lookup(
    credentials: Credentials,
    provider: ProviderID,
    ioc: LookupIOC,
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    runtime: Runtime | None = None,
) -> ProviderOutcome:
    client = LookupHTTP(
        provider, credentials, runtime or Clock().runtime(), transport=httpx.MockTransport(handler)
    )
    try:
        return await adapter(provider, client).lookup(ioc)
    finally:
        await client.close()
