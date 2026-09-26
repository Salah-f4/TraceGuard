"""AbuseIPDB check only. No abuse submissions or verbose comments."""

from traceguard.adapters.intelligence.http import LookupHTTP
from traceguard.adapters.intelligence.parsing import attributes, mapping, text, timestamp
from traceguard.core.intelligence import LookupIOC, ProviderEvidence, ProviderID, ProviderOutcome


class AbuseIPDB:
    provider_id: ProviderID = "abuseipdb"

    def __init__(self, http: LookupHTTP) -> None:
        self.http = http

    async def lookup(self, ioc: LookupIOC) -> ProviderOutcome:
        return await self.http.lookup(ioc, self.parse)

    @staticmethod
    def parse(body: dict[str, object], ioc: LookupIOC) -> ProviderEvidence:
        data = mapping(body["data"])
        if text(data["ipAddress"]) != ioc.normalized_value or data["isPublic"] is not True:
            raise ValueError
        evidence = attributes(
            data,
            counts=("abuseConfidenceScore", "totalReports", "numDistinctUsers"),
            strings=("countryCode", "usageType", "isp"),
        )
        score = evidence.get("abuseConfidenceScore")
        if not isinstance(score, int) or score > 100 or "totalReports" not in evidence:
            raise ValueError
        observed, original = timestamp(data.get("lastReportedAt"))
        evidence["maxAgeInDays"] = 90
        return ProviderEvidence(
            attributes=evidence,
            observed_at=observed,
            observed_at_original=original,
            reference="https://www.abuseipdb.com/check/" + ioc.normalized_value,
        )
