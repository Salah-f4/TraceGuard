"""Replaceable intelligence adapter protocol."""

from typing import Protocol

from traceguard.core.intelligence import LookupIOC, ProviderID, ProviderOutcome


class IntelligenceProvider(Protocol):
    provider_id: ProviderID

    async def lookup(self, ioc: LookupIOC) -> ProviderOutcome: ...
