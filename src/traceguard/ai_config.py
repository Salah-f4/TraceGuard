"""Opt-in Groq configuration. Never logs configuration or changes environment/files."""

import os
from pathlib import Path

from dotenv import dotenv_values
from pydantic import SecretStr

MODEL = "qwen/qwen3.8-27b"
KEY_NAME = "TRACEGUARD_GROQ_API_KEY"


class AISettings:
    def __init__(self, key: SecretStr | None, valid: bool = True) -> None:
        self.key, self.valid = key, valid

    def __repr__(self) -> str:
        return "AISettings(<redacted>)"

    @classmethod
    def from_environment(cls) -> "AISettings":
        try:
            values = dotenv_values(Path(".env"), encoding="utf-8-sig", interpolate=False)

            def get(name: str, default: str = "") -> str:
                return (os.environ.get(name, values.get(name, default)) or "").strip()

            key = get(KEY_NAME)
            valid = (
                get("TRACEGUARD_AI_PROVIDER", "groq") == "groq"
                and get("TRACEGUARD_AI_MODEL", MODEL) == MODEL
            )
            return cls(SecretStr(key) if key else None, valid)
        except (OSError, UnicodeError):
            return cls(None, False)
