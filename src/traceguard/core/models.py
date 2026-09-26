"""Shared offline report contracts."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

MAX_INPUT_BYTES = 1_000_000
MAX_INDICATORS = 10_000


class InputError(ValueError):
    """Input is unsupported or exceeds an explicit limit."""


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class SourceLocation(BaseModel):
    model_config = ConfigDict(frozen=True)
    source: str
    start_offset: int
    end_offset: int
    line: int
    column: int


class Occurrence(BaseModel):
    original_value: str
    is_defanged: bool
    source_location: SourceLocation


class IOCResult(BaseModel):
    type: IOCType
    original_value: str
    normalized_value: str
    is_defanged: bool
    is_valid: bool
    validation_message: str
    source_location: SourceLocation
    occurrences: list[Occurrence] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    schema_version: str = "1.0"
    source: str
    input_bytes: int
    extracted_count: int
    unique_count: int
    results: list[IOCResult]
