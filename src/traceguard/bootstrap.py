"""Compose optional enrichment only after explicit CLI opt-in."""

from collections.abc import Callable

from traceguard.adapters.intelligence.abuseipdb import AbuseIPDB
from traceguard.adapters.intelligence.http import LookupHTTP, Runtime
from traceguard.adapters.intelligence.urlhaus import URLhaus
from traceguard.adapters.intelligence.virustotal import VirusTotal
from traceguard.config import Credentials
from traceguard.core.enrichment import enrich_report
from traceguard.core.intelligence import PROVIDERS, EnrichedReport, ProviderID
from traceguard.core.models import AnalysisReport
from traceguard.core.ports import IntelligenceProvider


async def run_enrichment(report: AnalysisReport, credentials: Credentials) -> EnrichedReport:
    runtime = Runtime()
    adapters: dict[ProviderID, IntelligenceProvider] = {}
    clients: list[LookupHTTP] = []
    factories: dict[ProviderID, Callable[[LookupHTTP], IntelligenceProvider]] = {
        "virustotal": VirusTotal,
        "abuseipdb": AbuseIPDB,
        "urlhaus": URLhaus,
    }
    try:
        for provider in PROVIDERS:
            if credentials.get(provider) is not None:
                client = LookupHTTP(provider, credentials, runtime)
                clients.append(client)
                adapters[provider] = factories[provider](client)
        result = await enrich_report(report, adapters)
        # Prevent even a reflected secret in local input/provider evidence from export.
        return EnrichedReport.model_validate_json(credentials.redact(result.model_dump_json()))
    finally:
        for client in clients:
            await client.close()
