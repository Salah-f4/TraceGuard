"""Mocked endpoint, identity, attribution, and privacy contracts."""

import asyncio
import base64
from urllib.parse import parse_qs

import httpx
import pytest

from tests.support import body_for, lookup
from traceguard.adapters.intelligence.http import request_spec
from traceguard.config import Credentials
from traceguard.core.intelligence import CAPABILITIES, PROVIDERS, LookupIOC, ProviderID
from traceguard.core.models import IOCType

_VALUES = {
    IOCType.IPV4: "8.8.8.8",
    IOCType.IPV6: "2606:4700:4700::1111",
    IOCType.DOMAIN: "public-site.com",
    IOCType.URL: "https://public-site.com/Path",
    IOCType.EMAIL: "User@public-site.com",
    IOCType.MD5: "a" * 32,
    IOCType.SHA1: "b" * 40,
    IOCType.SHA256: "c" * 64,
}


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("kind", list(IOCType))
def test_matrix(provider: ProviderID, kind: IOCType, credentials: Credentials) -> None:
    ioc = LookupIOC(type=kind, normalized_value=_VALUES[kind])
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=body_for(provider, ioc))

    result = asyncio.run(lookup(credentials, provider, ioc, respond))
    if kind == IOCType.EMAIL:
        assert result.status == "skipped_email"
        assert not requests
    elif kind not in CAPABILITIES[provider]:
        assert result.status == "skipped_unsupported"
        assert not requests
    else:
        assert result.status == "found"
        assert len(requests) == 1
        request = requests[0]
        assert request.url.scheme == "https"
        assert request.method == ("POST" if provider == "urlhaus" else "GET")
        header = {"virustotal": "x-apikey", "abuseipdb": "key", "urlhaus": "auth-key"}[provider]
        assert header in request.headers
        assert result.evidence is not None
        assert result.evidence.observed_at is not None
        assert result.fetched_at is not None
        assert result.started_at is not None
        assert result.completed_at is not None
        assert not credentials.contains(result.model_dump_json())
        if provider == "virustotal" and kind == IOCType.URL:
            identifier = request.url.path.rsplit("/", 1)[-1]
            decoded = base64.urlsafe_b64decode(identifier + "=" * (-len(identifier) % 4)).decode()
            assert decoded == ioc.normalized_value
        if provider == "abuseipdb":
            assert dict(request.url.params) == {
                "ipAddress": ioc.normalized_value,
                "maxAgeInDays": "90",
            }
        if provider == "urlhaus":
            fields = parse_qs(request.content.decode())
            assert list(fields.values()) == [[ioc.normalized_value]]


@pytest.mark.parametrize("provider", PROVIDERS)
def test_no_results(provider: ProviderID, credentials: Credentials) -> None:
    ioc = LookupIOC(type=IOCType.IPV4, normalized_value="8.8.8.8")
    if provider == "virustotal":
        response = httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        expected = "not_found"
    elif provider == "urlhaus":
        response = httpx.Response(200, json={"query_status": "no_results"})
        expected = "not_found"
    else:
        body = body_for(provider, ioc)
        response = httpx.Response(200, json=body)
        expected = "found"
    result = asyncio.run(lookup(credentials, provider, ioc, lambda _: response))
    assert result.status == expected


@pytest.mark.parametrize("provider", PROVIDERS)
def test_mismatched_identity(provider: ProviderID, credentials: Credentials) -> None:
    ioc = LookupIOC(type=IOCType.IPV4, normalized_value="8.8.8.8")
    other = LookupIOC(type=IOCType.IPV4, normalized_value="1.1.1.1")
    result = asyncio.run(
        lookup(
            credentials,
            provider,
            ioc,
            lambda _: httpx.Response(200, json=body_for(provider, other)),
        )
    )
    assert result.status == "invalid_response"


@pytest.mark.parametrize(
    "body", [[], {}, {"query_status": "unknown"}, {"query_status": "ok", "host": 1}]
)
def test_invalid_body(body: object, credentials: Credentials) -> None:
    result = asyncio.run(
        lookup(
            credentials,
            "urlhaus",
            LookupIOC(type=IOCType.IPV4, normalized_value="8.8.8.8"),
            lambda _: httpx.Response(200, json=body),
        )
    )
    assert result.status == "invalid_response"


def test_transport_boundary_rejects_fragments_and_private_values() -> None:
    for value in [
        "https://public-site.com/#x",
        "https://127.0.0.1/",
        "https://public-site.com/?q=x",
    ]:
        with pytest.raises(ValueError):
            request_spec("virustotal", LookupIOC(type=IOCType.URL, normalized_value=value))


def test_no_raw_context_in_lookup_contract() -> None:
    assert set(LookupIOC.model_fields) == {"type", "normalized_value"}
