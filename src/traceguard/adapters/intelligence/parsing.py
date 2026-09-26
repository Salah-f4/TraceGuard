"""Small strict parsers: select evidence, never persist raw response bodies."""

from datetime import UTC, datetime
from typing import cast
from urllib.parse import urlsplit

from traceguard.core.intelligence import Attribute


def mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("Invalid object.")
    return cast(dict[str, object], value)


def text(value: object) -> str:
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid text.")
    return value


def integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Invalid count.")
    return value


def timestamp(value: object) -> tuple[datetime | None, str | int | None]:
    if value is None:
        return None, None
    if isinstance(value, int) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, UTC), value
    original = text(value)
    parsed = datetime.fromisoformat(original.replace(" UTC", "+00:00").replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)  # URLhaus documents UTC without a suffix.
    return parsed.astimezone(UTC), original


def attributes(
    data: dict[str, object], *, counts: tuple[str, ...] = (), strings: tuple[str, ...] = ()
) -> dict[str, Attribute]:
    result: dict[str, Attribute] = {}
    for key in counts:
        if key in data:
            result[key] = integer(data[key])
    for key in strings:
        if key in data and data[key] is not None:
            result[key] = text(data[key])
    return result


def reference(value: object, host: str) -> str | None:
    if value is None:
        return None
    link = text(value)
    parsed = urlsplit(link)
    if (
        parsed.scheme != "https"
        or parsed.hostname != host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid attribution link.")
    return link
