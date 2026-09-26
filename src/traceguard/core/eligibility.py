"""Offline disclosure policy, reviewed against IANA registries 2026-09-23."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from traceguard.core.intelligence import LookupIOC, Status
from traceguard.core.models import IOCType, SourceLocation
from traceguard.core.normalization import normalize

POLICY_VERSION = "2026-09-23"
# Conservative supersets include special-purpose globally reachable exceptions.
_V4_DENY = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
    )
)
_V6_GLOBAL = ipaddress.ip_network("2000::/3")
_V6_DENY = tuple(
    ipaddress.ip_network(value)
    for value in (
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "2620:4f:8000::/48",
        "3fff::/20",
    )
)
_SPECIAL = (
    "arpa",
    "alt",
    "example",
    "example.com",
    "example.net",
    "example.org",
    "invalid",
    "local",
    "localhost",
    "onion",
    "test",
    "internal",
    "lan",
    "home",
    "corp",
)
_LOCATION = SourceLocation(source="<policy>", start_offset=0, end_offset=0, line=1, column=1)


@dataclass(frozen=True)
class URLPolicy:
    """Extension point for future query policy; no query opt-in exists yet."""

    decoding_rounds: int = 3


@dataclass(frozen=True)
class Eligibility:
    lookup: LookupIOC | None
    status: Status | None = None
    reason: str = "eligible"
    fragment_stripped: bool = False


def public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if "%" in value:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return not any(address in network for network in _V4_DENY)
    return address in _V6_GLOBAL and not any(address in network for network in _V6_DENY)


def special_domain(value: str) -> bool:
    value = value.lower().rstrip(".")
    return "." not in value or any(value == item or value.endswith("." + item) for item in _SPECIAL)


def _inspect_url(value: str, policy: URLPolicy) -> Status | None:
    decoded = value
    for _ in range(policy.decoding_rounds):
        if re.search(r"%(?![0-9a-fA-F]{2})", decoded):
            return "skipped_sensitive_url"
        try:
            next_value = unquote(decoded, errors="strict")
        except UnicodeDecodeError:
            return "skipped_sensitive_url"
        if next_value == decoded:
            break
        decoded = next_value
    if "%" in decoded or "@" in decoded or any(ord(char) < 32 for char in decoded):
        return "skipped_sensitive_url"
    # Encoded delimiters can conceal query data or a changed authority.
    if "?" in decoded or "#" in decoded or "\\" in decoded:
        return "skipped_sensitive_url"
    for token in re.findall(r"(?<!\w)(?:\d+\.){3}\d+(?!\w)", decoded):
        if not public_ip(token):
            return "skipped_non_public"
    for token in re.findall(r"[0-9a-fA-F:]+", decoded):
        if token.count(":") >= 2 and not public_ip(token):
            return "skipped_non_public"
    return None


_DEFAULT_URL_POLICY = URLPolicy()


def eligible(ioc: LookupIOC, *, policy: URLPolicy = _DEFAULT_URL_POLICY) -> Eligibility:
    if ioc.type == IOCType.EMAIL:
        return Eligibility(None, "skipped_email", "Email indicators are never disclosed.")
    checked = normalize(ioc.type, ioc.normalized_value, _LOCATION)
    if not checked.is_valid or checked.normalized_value != ioc.normalized_value:
        return Eligibility(None, "skipped_invalid", "Indicator is invalid or not canonical.")
    value = ioc.normalized_value
    if ioc.type in {IOCType.IPV4, IOCType.IPV6}:
        if not public_ip(value):
            return Eligibility(None, "skipped_non_public", "IP is not eligible public unicast.")
    elif ioc.type == IOCType.DOMAIN:
        if special_domain(value):
            return Eligibility(
                None, "skipped_special_use_domain", "Domain is special-use or local."
            )
    elif ioc.type == IOCType.URL:
        parts = urlsplit(value)
        if parts.username is not None or parts.password is not None:
            return Eligibility(
                None, "skipped_sensitive_url", "URL credentials are never disclosed."
            )
        if parts.scheme not in {"http", "https"}:
            return Eligibility(
                None, "skipped_unsupported", "Only HTTP(S) URL reports are supported."
            )
        if "?" in value.split("#", 1)[0]:
            return Eligibility(
                None, "skipped_url_query", "Privacy: URL query strings are excluded."
            )
        # Fragments are not sent to servers. Preserve the offline IOC unchanged.
        stripped = "#" in value
        value = value.split("#", 1)[0]
        host = parts.hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if special_domain(host):
                return Eligibility(None, "skipped_special_use_domain", "URL host is special-use.")
            if host.isdigit() or re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.[0-9a-fx]+)*", host):
                return Eligibility(None, "skipped_non_public", "Ambiguous numeric URL host.")
        else:
            if not public_ip(host):
                return Eligibility(None, "skipped_non_public", "URL IP host is not public.")
        status = _inspect_url(value, policy)
        if status:
            return Eligibility(None, status, "Privacy: sensitive or ambiguous URL components.")
        return Eligibility(
            LookupIOC(type=ioc.type, normalized_value=value), fragment_stripped=stripped
        )
    return Eligibility(ioc)
