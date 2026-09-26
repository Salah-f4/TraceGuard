"""Existing VirusTotal reports only; no scanning endpoints."""

import hashlib
from urllib.parse import quote

from traceguard.adapters.intelligence.http import LookupHTTP
from traceguard.adapters.intelligence.parsing import integer, mapping, text, timestamp
from traceguard.core.intelligence import LookupIOC, ProviderEvidence, ProviderID, ProviderOutcome
from traceguard.core.models import IOCType


class VirusTotal:
    provider_id: ProviderID = "virustotal"

    def __init__(self, http: LookupHTTP) -> None:
        self.http = http

    async def lookup(self, ioc: LookupIOC) -> ProviderOutcome:
        return await self.http.lookup(ioc, self.parse)

    @staticmethod
    def parse(body: dict[str, object], ioc: LookupIOC) -> ProviderEvidence:
        data = mapping(body["data"])
        attrs = mapping(data["attributes"])
        report_id = text(data["id"])
        expected_type = (
            "ip_address"
            if ioc.type in {IOCType.IPV4, IOCType.IPV6}
            else "domain"
            if ioc.type == IOCType.DOMAIN
            else "url"
            if ioc.type == IOCType.URL
            else "file"
        )
        if data["type"] != expected_type:
            raise ValueError
        if expected_type == "file":
            if text(attrs[ioc.type.value]).lower() != ioc.normalized_value:
                raise ValueError
        elif expected_type == "url":
            if text(attrs["url"]) != ioc.normalized_value:
                raise ValueError
            if report_id != hashlib.sha256(ioc.normalized_value.encode()).hexdigest():
                raise ValueError
        elif report_id != ioc.normalized_value:
            raise ValueError
        stats = mapping(attrs["last_analysis_stats"])
        counts = {key: integer(value) for key, value in stats.items()}
        if not counts or any(
            key
            not in {
                "malicious",
                "suspicious",
                "undetected",
                "harmless",
                "timeout",
                "confirmed-timeout",
                "failure",
                "type-unsupported",
            }
            for key in counts
        ):
            raise ValueError
        observed, original = timestamp(attrs.get("last_analysis_date"))
        category = "ip-address" if expected_type == "ip_address" else expected_type
        return ProviderEvidence(
            attributes={"last_analysis_stats": counts, "report_id": report_id},
            observed_at=observed,
            observed_at_original=original,
            reference=f"https://www.virustotal.com/gui/{category}/{quote(report_id, safe='')}",
        )
