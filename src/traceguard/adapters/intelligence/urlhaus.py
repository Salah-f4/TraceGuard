"""URLhaus metadata lookups; never download payloads."""

from traceguard.adapters.intelligence.http import LookupHTTP
from traceguard.adapters.intelligence.parsing import attributes, reference, text, timestamp
from traceguard.core.intelligence import LookupIOC, ProviderEvidence, ProviderID, ProviderOutcome
from traceguard.core.models import IOCType


class URLhaus:
    provider_id: ProviderID = "urlhaus"

    def __init__(self, http: LookupHTTP) -> None:
        self.http = http

    async def lookup(self, ioc: LookupIOC) -> ProviderOutcome:
        return await self.http.lookup(ioc, self.parse)

    @staticmethod
    def parse(body: dict[str, object], ioc: LookupIOC) -> ProviderEvidence | None:
        if body["query_status"] == "no_results":
            return None
        if body["query_status"] != "ok":
            raise ValueError
        identity = (
            "url"
            if ioc.type == IOCType.URL
            else "host"
            if ioc.type in {IOCType.IPV4, IOCType.DOMAIN}
            else "md5_hash"
            if ioc.type == IOCType.MD5
            else "sha256_hash"
        )
        if text(body[identity]) != ioc.normalized_value:
            raise ValueError
        evidence = attributes(
            body,
            strings=("url_status", "threat", "signature", "file_type"),
        )
        if "file_size" in body:
            size = body["file_size"]
            if isinstance(size, str) and size.isdecimal():
                size = int(size)
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise ValueError
            evidence["file_size"] = size
        if "url_count" in body:
            value = body["url_count"]
            if isinstance(value, str) and value.isdecimal():
                evidence["url_count"] = int(value)
            elif isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                evidence["url_count"] = value
            else:
                raise ValueError
        if body.get("tags") is not None:
            tags = body["tags"]
            if not isinstance(tags, list) or len(tags) > 1000:
                raise ValueError
            evidence["tags"] = [text(tag) for tag in tags]
        observed, original = timestamp(
            body.get("lastseen") or body.get("date_added") or body.get("firstseen")
        )
        return ProviderEvidence(
            attributes=evidence,
            observed_at=observed,
            observed_at_original=original,
            reference=reference(body.get("urlhaus_reference"), "urlhaus.abuse.ch"),
        )
