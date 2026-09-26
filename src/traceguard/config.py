"""Redacted credentials with an explicit local-development dotenv fallback."""

import base64
import os
from pathlib import Path
from urllib.parse import quote

from dotenv import dotenv_values
from pydantic import SecretStr

from traceguard.core.intelligence import PROVIDERS, ProviderID
from traceguard.core.models import InputError

ENV_NAMES: dict[ProviderID, str] = {
    "virustotal": "TRACEGUARD_VIRUSTOTAL_API_KEY",
    "abuseipdb": "TRACEGUARD_ABUSEIPDB_API_KEY",
    "urlhaus": "TRACEGUARD_URLHAUS_AUTH_KEY",
}


class Credentials:
    def __init__(self, values: dict[ProviderID, SecretStr]) -> None:
        self._values = values

    def __repr__(self) -> str:
        return "Credentials(<redacted>)"

    @classmethod
    def from_environment(cls, *, dotenv_path: Path | None = Path(".env")) -> "Credentials":
        # Never search parent directories, interpolate variables, or mutate os.environ.
        local: dict[str, str | None] = {}
        if dotenv_path is not None:
            try:
                with dotenv_path.open(encoding="utf-8-sig") as stream:
                    local = dotenv_values(stream=stream, interpolate=False)
            except FileNotFoundError:
                pass
            except (OSError, UnicodeError):
                raise InputError("Unable to read local .env configuration.") from None
        values: dict[ProviderID, SecretStr] = {}
        for provider in PROVIDERS:
            name = ENV_NAMES[provider]
            value = (os.environ.get(name, local.get(name)) or "").strip()
            if value:
                values[provider] = SecretStr(value)
        return cls(values)

    def get(self, provider: ProviderID) -> SecretStr | None:
        return self._values.get(provider)

    def redact(self, text: str) -> str:
        for value in self._values.values():
            secret = value.get_secret_value()
            variants = {
                secret,
                quote(secret, safe=""),
                secret.encode().hex(),
                base64.b64encode(secret.encode()).decode(),
                base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
            }
            for variant in sorted(variants, key=len, reverse=True):
                text = text.replace(variant, "[REDACTED]")
        return text

    def contains(self, text: str) -> bool:
        return self.redact(text) != text
