"""Offline service independent of terminal and infrastructure."""

from traceguard.core.extraction import extract
from traceguard.core.models import MAX_INPUT_BYTES, AnalysisReport, InputError, IOCResult, IOCType
from traceguard.core.normalization import normalize


def validate_text(text: str) -> int:
    try:
        size = len(text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise InputError("Input must be valid UTF-8 text.") from exc
    if size > MAX_INPUT_BYTES:
        raise InputError(f"Input exceeds {MAX_INPUT_BYTES:,} bytes (1 MB).")
    if not text.strip():
        raise InputError("Input is empty.")
    if any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        raise InputError("Unsupported binary/control characters in text input.")
    return size


def analyze_text(text: str, *, source: str = "<text>") -> AnalysisReport:
    size = validate_text(text)
    candidates = extract(text, source)
    if not candidates:
        raise InputError("No supported IOC candidates found in input.")
    unique: dict[tuple[IOCType, str], IOCResult] = {}
    for candidate in candidates:
        result = normalize(candidate.type, candidate.original_value, candidate.location)
        key = (result.type, result.normalized_value)
        if key in unique:
            unique[key].occurrences.extend(result.occurrences)
        else:
            unique[key] = result
    return AnalysisReport(
        source=source,
        input_bytes=size,
        extracted_count=len(candidates),
        unique_count=len(unique),
        results=list(unique.values()),
    )
