"""Bounded extraction with original source spans and overlap precedence."""

from __future__ import annotations

import re
from array import array
from bisect import bisect_right
from dataclasses import dataclass

from traceguard.core.models import MAX_INDICATORS, InputError, IOCType, SourceLocation
from traceguard.core.normalization import DEFANG_PATTERN, refang


@dataclass(frozen=True)
class Candidate:
    type: IOCType
    original_value: str
    location: SourceLocation


_URL = re.compile(r"(?<![\w+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"']*")
_EMAIL = re.compile(
    r"(?<![\w.!#$%&'*+/=?^_\x60{|}~@-])"
    r"[\w.!#$%&'*+/=?^_\x60{|}~@-]+@[^\s<>()\[\]{}\"',;:/\\]+"
)
_IPV6 = re.compile(
    r"(?<![A-Za-z0-9_:%.~-])[A-Za-z0-9_:%.~-]*:[A-Za-z0-9_:%.~-]+"
    r"(?![A-Za-z0-9_:%.~-])"
)
_IPV4 = re.compile(r"(?<![\w.])(?:[0-9]+\.){3}[0-9]+(?!\w|\.[\w])")
_DOMAIN = re.compile(
    r"(?<![\w.\u3002\uff0e\uff61@-])[\w\u0300-\u036f-]+"
    r"(?:[.\u3002\uff0e\uff61][\w\u0300-\u036f-]*)+"
    r"(?![\w@-])"
)
_EMAIL_LABEL = re.compile(r"(?:email|contact|user|from|to|sender|recipient|mail|address)=", re.I)
_IP_LABEL = re.compile(r"(?:ip|ipv6|src|dst|source|destination|address):", re.I)
_HASH = re.compile(r"(?<![\w-])(?:[A-Za-z0-9]{64}|[A-Za-z0-9]{40}|[A-Za-z0-9]{32})(?![\w-])")
_LABELED_HASH = re.compile(
    r"\b(?P<kind>md5|sha-?1|sha-?256)\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9_-]+)",
    re.I,
)
_HASH_TYPES = {32: IOCType.MD5, 40: IOCType.SHA1, 64: IOCType.SHA256}


def _mapped_refang(text: str) -> tuple[str, array[int], array[int]]:
    chunks: list[str] = []
    starts: array[int] = array("I")
    ends: array[int] = array("I")
    cursor = 0
    for match in DEFANG_PATTERN.finditer(text):
        chunks.append(text[cursor : match.start()])
        starts.extend(range(cursor, match.start()))
        ends.extend(range(cursor + 1, match.start() + 1))
        replacement = refang(match[0])
        chunks.append(replacement)
        starts.extend([match.start()] * len(replacement))
        ends.extend([match.end()] * len(replacement))
        cursor = match.end()
    chunks.append(text[cursor:])
    starts.extend(range(cursor, len(text)))
    ends.extend(range(cursor + 1, len(text) + 1))
    return "".join(chunks), starts, ends


def _trim(value: str, *, url: bool = False) -> str:
    value = value.rstrip(".,;!")
    if url:
        for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
            excess = value.count(closing) - value.count(opening)
            trailing = len(value) - len(value.rstrip(closing))
            if excess > 0 and trailing:
                value = value[: -min(excess, trailing)]
    return value


def extract(text: str, source: str) -> list[Candidate]:
    """Extract outer IOCs only, without also reporting their embedded hosts."""
    scan, starts, ends = _mapped_refang(text)
    occupied = bytearray(len(scan))
    candidates: list[Candidate] = []
    newlines = [index for index, char in enumerate(text) if char == "\n"]

    def add(kind: IOCType, start: int, end: int) -> None:
        if start == end or any(occupied[start:end]):
            return
        if len(candidates) >= MAX_INDICATORS:
            raise InputError(f"Input exceeds {MAX_INDICATORS:,} extracted indicator occurrences.")
        original_start, original_end = starts[start], ends[end - 1]
        line_index = bisect_right(newlines, original_start - 1)
        line_start = newlines[line_index - 1] + 1 if line_index else 0
        candidates.append(
            Candidate(
                type=kind,
                original_value=text[original_start:original_end],
                location=SourceLocation(
                    source=source,
                    start_offset=original_start,
                    end_offset=original_end,
                    line=line_index + 1,
                    column=original_start - line_start + 1,
                ),
            )
        )
        occupied[start:end] = b"\x01" * (end - start)

    for match in _URL.finditer(scan):
        add(IOCType.URL, match.start(), match.start() + len(_trim(match[0], url=True)))
    for match in _EMAIL.finditer(scan):
        value = _trim(match[0])
        label = _EMAIL_LABEL.match(value)
        start = match.start() + (label.end() if label else 0)
        add(IOCType.EMAIL, start, match.start() + len(value))
    for match in _LABELED_HASH.finditer(scan):
        kind = IOCType(match["kind"].lower().replace("-", ""))
        add(kind, match.start("value"), match.end("value"))
    for match in _IPV6.finditer(scan):
        value = _trim(match[0])
        label = _IP_LABEL.match(value)
        start = match.start()
        if label:
            value = value[label.end() :]
            start += label.end()
        if "::" not in value and value.count(":") < 3:
            continue
        if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", value):
            continue
        add(IOCType.IPV6, start, start + len(value))
    for match in _IPV4.finditer(scan):
        add(IOCType.IPV4, match.start(), match.end())
    for match in _DOMAIN.finditer(scan):
        if re.split(r"[.\u3002\uff0e\uff61]", match[0].rstrip(".\u3002\uff0e\uff61"))[-1].isdigit():
            continue
        add(IOCType.DOMAIN, match.start(), match.end())
    for match in _HASH.finditer(scan):
        add(_HASH_TYPES[len(match[0])], match.start(), match.end())
    candidates.sort(key=lambda candidate: candidate.location.start_offset)
    return candidates
