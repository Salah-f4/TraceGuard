"""Extraction, overlap, provenance, and hard-limit tests."""

import pytest

from traceguard.core.investigation import analyze_text
from traceguard.core.models import MAX_INDICATORS, MAX_INPUT_BYTES, InputError, IOCType


@pytest.mark.parametrize(
    ("value", "kind", "valid"),
    [
        ("192.0.2.1", IOCType.IPV4, True),
        ("192.0.2.1.", IOCType.IPV4, True),
        ("999.1.2.3", IOCType.IPV4, False),
        ("01.2.3.4", IOCType.IPV4, False),
        ("[2001:DB8::1]", IOCType.IPV6, True),
        ("::", IOCType.IPV6, True),
        ("::ffff:192.0.2.1", IOCType.IPV6, True),
        ("2001:gggg::1", IOCType.IPV6, False),
        ("2001:db8:::1", IOCType.IPV6, False),
        ("example(.)com", IOCType.DOMAIN, True),
        ("BÜCHER.DE", IOCType.DOMAIN, True),
        ("例え.テスト", IOCType.DOMAIN, True),
        ("-bad.example", IOCType.DOMAIN, False),
        ("user..name@EXAMPLE.COM", IOCType.EMAIL, False),
        ("First.Last+tag@Example.COM", IOCType.EMAIL, True),
        ("hxxps[:]//EXAMPLE[.]COM/AbC?X=Y", IOCType.URL, True),
        ("https://example.com:99999/X", IOCType.URL, False),
        ("http://", IOCType.URL, False),
        ("md5=abc", IOCType.MD5, False),
        ("SHA-1: " + "G" * 40, IOCType.SHA1, False),
        ("A" * 32, IOCType.MD5, True),
        ("B" * 40, IOCType.SHA1, True),
        ("C" * 64, IOCType.SHA256, True),
    ],
)
def test_extraction(value: str, kind: IOCType, valid: bool) -> None:
    report = analyze_text(value)
    assert report.unique_count == 1
    assert report.results[0].type == kind
    assert report.results[0].is_valid is valid


def test_outer_indicators_own_overlapping_spans() -> None:
    report = analyze_text(
        "https://User@example.com/192.0.2.1?q="
        + "a" * 32
        + " Person@example.com http://[::ffff:192.0.2.1]/ ::ffff:192.0.2.1"
    )
    assert [result.type for result in report.results] == [
        IOCType.URL,
        IOCType.EMAIL,
        IOCType.URL,
        IOCType.IPV6,
    ]


def test_dedup_preserves_all_occurrences_and_case_sensitive_email_local_parts() -> None:
    report = analyze_text(
        "EXAMPLE.COM example[.]com example.com "
        "User@EXAMPLE.COM User@example.com user@example.com "
        "2001:0DB8::1 2001:db8::1"
    )
    assert report.extracted_count == 8
    assert report.unique_count == 4
    domain = report.results[0]
    assert domain.original_value == "EXAMPLE.COM"
    assert [occ.is_defanged for occ in domain.occurrences] == [False, True, False]
    assert len(report.results[-1].occurrences) == 2


def test_original_offsets_survive_defanging_and_unicode() -> None:
    text = "note α\nurl=hxxps[:]//EXAMPLE[.]COM/A\nip=192[.]0[.]2[.]1"
    report = analyze_text(text, source="sample.log")
    for result in report.results:
        loc = result.source_location
        assert text[loc.start_offset : loc.end_offset] == result.original_value
        assert loc.source == "sample.log"
    assert report.results[0].source_location.line == 2
    assert report.results[0].source_location.column == 5
    assert report.results[1].source_location.line == 3
    assert report.results[1].source_location.column == 4


def test_log_labels_do_not_become_part_of_iocs() -> None:
    report = analyze_text("email=User@example.com dst:2001:db8::1")
    assert [r.original_value for r in report.results] == ["User@example.com", "2001:db8::1"]
    assert report.results[0].source_location.column == 7
    assert all(r.is_valid for r in report.results)


def test_email_equals_local_part_preserved() -> None:
    result = analyze_text("A=B@EXAMPLE.COM").results[0]
    assert result.normalized_value == "A=B@example.com"


def test_invalid_domain_not_partially_extracted() -> None:
    result = analyze_text("example..com").results[0]
    assert result.original_value == "example..com"
    assert not result.is_valid


@pytest.mark.parametrize("value", ["BU\u0308CHER.DE", "BÜCHER\u3002DE"])
def test_idna_unicode_variants(value: str) -> None:
    result = analyze_text(value).results[0]
    assert result.original_value == value
    assert result.normalized_value == "xn--bcher-kva.de"


def test_type_is_part_of_dedup_key() -> None:
    value = "a" * 32
    report = analyze_text(f"md5={value} sha1={value}")
    assert report.unique_count == 2
    assert [r.is_valid for r in report.results] == [True, False]


def test_unique_limit_does_not_truncate() -> None:
    report = analyze_text(" ".join(f"a{i}.example" for i in range(MAX_INDICATORS)))
    assert report.unique_count == MAX_INDICATORS
    with pytest.raises(InputError, match="10,000"):
        analyze_text(" ".join(f"a{i}.example" for i in range(MAX_INDICATORS + 1)))


def test_balanced_url_parentheses_and_prose_wrapper() -> None:
    result = analyze_text("(https://EXAMPLE.COM/A_(B)).").results[0]
    assert result.normalized_value == "https://example.com/A_(B)"


@pytest.mark.parametrize("text", ["", " \t\r\n", "ordinary words", "\x00example.com", "\ud800"])
def test_rejected_input(text: str) -> None:
    with pytest.raises(InputError):
        analyze_text(text)


def test_byte_limit_is_not_a_character_limit() -> None:
    with pytest.raises(InputError, match="1,000,000"):
        analyze_text("é" * (MAX_INPUT_BYTES // 2 + 1))


def test_exact_byte_limit() -> None:
    text = "example.com" + " " * (MAX_INPUT_BYTES - len("example.com"))
    assert analyze_text(text).input_bytes == MAX_INPUT_BYTES


def test_exact_indicator_limit_and_duplicates() -> None:
    report = analyze_text("example.com " * MAX_INDICATORS)
    assert report.extracted_count == MAX_INDICATORS
    assert report.unique_count == 1
    assert len(report.results[0].occurrences) == MAX_INDICATORS
    with pytest.raises(InputError, match="10,000"):
        analyze_text("example.com " * (MAX_INDICATORS + 1))


@pytest.mark.parametrize("text", ["12:34:56", "aa:bb:cc:dd:ee:ff", "a" * 65])
def test_non_indicators_not_reclassified(text: str) -> None:
    with pytest.raises(InputError, match="No supported"):
        analyze_text(text)
