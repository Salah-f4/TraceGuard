"""Provider schema failures must not masquerade as clean results."""

from datetime import UTC

import pytest

from tests.support import body_for
from traceguard.adapters.intelligence.abuseipdb import AbuseIPDB
from traceguard.adapters.intelligence.parsing import integer, mapping, reference, text, timestamp
from traceguard.adapters.intelligence.urlhaus import URLhaus
from traceguard.adapters.intelligence.virustotal import VirusTotal
from traceguard.core.intelligence import LookupIOC
from traceguard.core.models import IOCType

IOC = LookupIOC(type=IOCType.IPV4, normalized_value="8.8.8.8")


@pytest.mark.parametrize("value", [-1, True, "2", None])
def test_invalid_integer(value: object) -> None:
    with pytest.raises(ValueError):
        integer(value)


@pytest.mark.parametrize("value", [1, "x" * 4097, "\x1bescape"])
def test_invalid_text(value: object) -> None:
    with pytest.raises(ValueError):
        text(value)


def test_invalid_mapping() -> None:
    with pytest.raises(ValueError):
        mapping({1: "x"})


@pytest.mark.parametrize(
    "url",
    [
        "http://urlhaus.abuse.ch/url/1/",
        "https://evil.com/",
        "https://u@urlhaus.abuse.ch/",
        "https://urlhaus.abuse.ch:123/",
        "https://urlhaus.abuse.ch/?q=x",
    ],
)
def test_unsafe_reference(url: str) -> None:
    with pytest.raises(ValueError):
        reference(url, "urlhaus.abuse.ch")


def test_optional_timestamps_and_links() -> None:
    assert timestamp(None) == (None, None)
    assert reference(None, "urlhaus.abuse.ch") is None
    parsed, original = timestamp("2026-09-23 00:00:00 UTC")
    assert parsed is not None and parsed.tzinfo == UTC
    assert original == "2026-09-23 00:00:00 UTC"


def test_abuse_score_range() -> None:
    body = body_for("abuseipdb", IOC)
    data = mapping(body["data"])
    data["abuseConfidenceScore"] = 101
    with pytest.raises(ValueError):
        AbuseIPDB.parse(body, IOC)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("query_status", "error"),
        ("url_count", -1),
        ("tags", "string"),
        ("host", "1.1.1.1"),
    ],
)
def test_urlhaus_bad_schema(field: str, value: object) -> None:
    body = body_for("urlhaus", IOC)
    body[field] = value
    with pytest.raises(ValueError):
        URLhaus.parse(body, IOC)


def test_urlhaus_optional_fields_and_integer_count() -> None:
    evidence = URLhaus.parse({"query_status": "ok", "host": "8.8.8.8", "url_count": 0}, IOC)
    assert evidence is not None
    assert evidence.attributes["url_count"] == 0
    assert evidence.observed_at is None


def test_urlhaus_documented_string_file_size() -> None:
    body = body_for("urlhaus", IOC)
    body["file_size"] = "241664"
    evidence = URLhaus.parse(body, IOC)
    assert evidence is not None
    assert evidence.attributes["file_size"] == 241664


@pytest.mark.parametrize("value", ["nonsense", True, -1])
def test_urlhaus_invalid_file_size(value: object) -> None:
    body = body_for("urlhaus", IOC)
    body["file_size"] = value
    with pytest.raises(ValueError):
        URLhaus.parse(body, IOC)


@pytest.mark.parametrize("change", ["type", "stats", "empty", "id"])
def test_virustotal_bad_schema(change: str) -> None:
    body = body_for("virustotal", IOC)
    data = mapping(body["data"])
    attrs = mapping(data["attributes"])
    if change == "type":
        data["type"] = "url"
    elif change == "id":
        data["id"] = "1.1.1.1"
    else:
        attrs["last_analysis_stats"] = {} if change == "empty" else {"unexpected": 1}
    with pytest.raises(ValueError):
        VirusTotal.parse(body, IOC)
