"""Table-driven canonicalization and validation examples."""

import pytest

from traceguard.core.models import IOCType, SourceLocation
from traceguard.core.normalization import normalize, refang


def result_for(kind: IOCType, value: str) -> tuple[bool, str]:
    result = normalize(
        kind,
        value,
        SourceLocation(
            source="<test>",
            start_offset=0,
            end_offset=len(value),
            line=1,
            column=1,
        ),
    )
    assert result.original_value == value
    assert result.validation_message
    return result.is_valid, result.normalized_value


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        (IOCType.IPV4, "192.0.2.1", "192.0.2.1"),
        (IOCType.IPV4, "192[.]0(.)2.1", "192.0.2.1"),
        (IOCType.IPV6, "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        (IOCType.IPV6, "::FFFF:192.0.2.1", "::ffff:192.0.2.1"),
        (IOCType.IPV6, "::", "::"),
        (IOCType.IPV6, "2001[:]db8[:][:]1", "2001:db8::1"),
        (IOCType.DOMAIN, "EXAMPLE.COM.", "example.com"),
        (IOCType.DOMAIN, "BÜCHER.DE", "xn--bcher-kva.de"),
        (IOCType.DOMAIN, "例え.テスト", "xn--r8jz45g.xn--zckzah"),
        (
            IOCType.URL,
            "hxxps[:]//EXAMPLE[.]COM/Path?Q=AbC#Frag",
            "https://example.com/Path?Q=AbC#Frag",
        ),
        (IOCType.URL, "HTTP://BÜCHER.DE:8080/A%2FB?Q=Z", "http://xn--bcher-kva.de:8080/A%2FB?Q=Z"),
        (IOCType.URL, "https://[2001:0DB8::1]:443/A", "https://[2001:db8::1]:443/A"),
        (IOCType.URL, "http://User:Pass@EXAMPLE.COM/", "http://User:Pass@example.com/"),
        (IOCType.URL, "http://192.0.2.1/", "http://192.0.2.1/"),
        (IOCType.URL, "https://EXAMPLE.COM?#", "https://example.com?#"),
        (IOCType.EMAIL, "First.Last+Tag@EXAMPLE.COM", "First.Last+Tag@example.com"),
        (IOCType.EMAIL, "User@BÜCHER.DE", "User@xn--bcher-kva.de"),
        (IOCType.MD5, "A" * 32, "a" * 32),
        (IOCType.SHA1, "B" * 40, "b" * 40),
        (IOCType.SHA256, "C" * 64, "c" * 64),
    ],
)
def test_valid(kind: IOCType, value: str, expected: str) -> None:
    assert result_for(kind, value) == (True, expected)


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (IOCType.IPV4, "999.1.2.3"),
        (IOCType.IPV4, "01.2.3.4"),
        (IOCType.IPV4, "::1"),
        (IOCType.IPV6, "2001:db8:::1"),
        (IOCType.IPV6, "2001:gggg::1"),
        (IOCType.IPV6, "fe80::1%eth0"),
        (IOCType.DOMAIN, "-bad.example"),
        (IOCType.DOMAIN, "bad_.example"),
        (IOCType.DOMAIN, "localhost"),
        (IOCType.DOMAIN, "a.123"),
        (IOCType.DOMAIN, "a" * 64 + ".example"),
        (IOCType.URL, "http://"),
        (IOCType.URL, "https://example.com:99999/A"),
        (IOCType.URL, "https://example.com:/A"),
        (IOCType.URL, "https://[2001:db8::1]bad/A"),
        (IOCType.URL, "http://999.1.2.3/"),
        (IOCType.URL, "https://example.com/%ZZ"),
        (IOCType.URL, "https://example.com/a b"),
        (IOCType.URL, "https://example.com\\path"),
        (IOCType.EMAIL, ".User@example.com"),
        (IOCType.EMAIL, "User..Name@example.com"),
        (IOCType.EMAIL, "Üser@example.com"),
        (IOCType.EMAIL, "@example.com"),
        (IOCType.EMAIL, "x" * 65 + "@example.com"),
        (IOCType.EMAIL, "a" * 64 + "@" + ".".join(["b" * 63] * 3) + ".com"),
        (IOCType.MD5, "g" * 32),
        (IOCType.MD5, "a" * 31),
        (IOCType.SHA1, "a" * 39),
        (IOCType.SHA256, "a" * 65),
    ],
)
def test_invalid(kind: IOCType, value: str) -> None:
    assert result_for(kind, value)[0] is False


def test_refang_does_not_change_ordinary_case() -> None:
    assert refang("HTTP://EXAMPLE.COM/A") == "HTTP://EXAMPLE.COM/A"
    assert refang("hxxp[:]//A(.)EXAMPLE") == "http://A.EXAMPLE"
