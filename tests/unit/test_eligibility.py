"""Privacy boundary and URL preprocessing tests."""

import pytest

from traceguard.core.eligibility import eligible, public_ip
from traceguard.core.intelligence import LookupIOC
from traceguard.core.models import IOCType


@pytest.mark.parametrize(
    "value",
    [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "172.16.0.1",
        "192.168.1.1",
        "192.0.0.9",
        "192.0.2.1",
        "192.31.196.1",
        "192.52.193.1",
        "192.88.99.1",
        "192.175.48.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "::ffff:10.0.0.1",
        "64:ff9b::808:808",
        "2001::1",
        "2001:db8::1",
        "2002:808:808::1",
        "2620:4f:8000::1",
        "3fff::1",
        "5f00::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "fe80::1%eth0",
        "garbage",
    ],
)
def test_excluded_ip(value: str) -> None:
    assert not public_ip(value)


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "1.1.1.1",
        "100.63.255.255",
        "100.128.0.0",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ],
)
def test_public_ip(value: str) -> None:
    assert public_ip(value)


@pytest.mark.parametrize(
    ("kind", "value", "status"),
    [
        (IOCType.EMAIL, "User@public-site.com", "skipped_email"),
        (IOCType.IPV4, "01.2.3.4", "skipped_invalid"),
        (IOCType.IPV4, "10.0.0.1", "skipped_non_public"),
        (IOCType.DOMAIN, "host.local", "skipped_special_use_domain"),
        (IOCType.DOMAIN, "host.example.com", "skipped_special_use_domain"),
        (IOCType.DOMAIN, "host.home.arpa", "skipped_special_use_domain"),
        (IOCType.DOMAIN, "UPPER.COM", "skipped_invalid"),
        (IOCType.URL, "https://u:p@public-site.com/", "skipped_sensitive_url"),
        (IOCType.URL, "https://public-site.com/?", "skipped_url_query"),
        (IOCType.URL, "https://public-site.com/?q=value#x", "skipped_url_query"),
        (IOCType.URL, "ftp://public-site.com/", "skipped_unsupported"),
        (IOCType.URL, "https://host.local/", "skipped_special_use_domain"),
        (IOCType.URL, "https://127.0.0.1/", "skipped_non_public"),
        (IOCType.URL, "https://[::1]/", "skipped_non_public"),
        (IOCType.URL, "https://public-site.com/u%40mail.com", "skipped_sensitive_url"),
        (IOCType.URL, "https://public-site.com/u%2540mail.com", "skipped_sensitive_url"),
        (IOCType.URL, "https://public-site.com/%2525252540", "skipped_sensitive_url"),
        (IOCType.URL, "https://public-site.com/%FF", "skipped_sensitive_url"),
        (IOCType.URL, "https://public-site.com/%00", "skipped_sensitive_url"),
        (IOCType.URL, "https://public-site.com/%3Fsecret", "skipped_sensitive_url"),
        (IOCType.URL, "https://public-site.com/%252e%ZZ", "skipped_invalid"),
        (IOCType.URL, "https://public-site.com/10.0.0.1", "skipped_non_public"),
        (IOCType.URL, "https://public-site.com/[::1]", "skipped_non_public"),
    ],
)
def test_privacy_skip(kind: IOCType, value: str, status: str) -> None:
    result = eligible(LookupIOC(type=kind, normalized_value=value))
    assert result.lookup is None
    assert result.status == status


def test_fragment_removed_but_path_case_preserved() -> None:
    ioc = LookupIOC(type=IOCType.URL, normalized_value="https://public-site.com/Path#user@mail.com")
    result = eligible(ioc)
    assert result.lookup is not None
    assert result.lookup.normalized_value == "https://public-site.com/Path"
    assert result.fragment_stripped
    assert ioc.normalized_value.endswith("#user@mail.com")


def test_valid_public_ipv6_url() -> None:
    ioc = LookupIOC(type=IOCType.URL, normalized_value="https://[2606:4700:4700::1111]/Path")
    assert eligible(ioc).lookup == ioc
