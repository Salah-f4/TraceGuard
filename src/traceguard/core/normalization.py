"""Pure syntax validation and normalization; never resolves hosts."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

import idna

from traceguard.core.models import IOCResult, IOCType, Occurrence, SourceLocation

DEFANG_PATTERN = re.compile(r"\[\.\]|\(\.\)|\[:\]|\bhxxps?(?=(?::|\[:\])//)", re.I)
_HASH_LENGTHS = {IOCType.MD5: 32, IOCType.SHA1: 40, IOCType.SHA256: 64}
_LOCAL_PART = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_\x60{|}~.-]+", re.ASCII)


def refang(value: str) -> str:
    """Restore supported defanging without changing unrelated case."""
    return DEFANG_PATTERN.sub(
        lambda match: (
            "."
            if match[0] in ("[.]", "(.)")
            else ":"
            if match[0] == "[:]"
            else "https"
            if match[0].lower() == "hxxps"
            else "http"
        ),
        value,
    )


def normalize_domain(value: str) -> str:
    """Apply IDNA UTS #46 without DNS or public-suffix lookups."""
    encoded = idna.encode(value.lower(), uts46=True, std3_rules=True).decode("ascii")
    encoded = encoded.removesuffix(".")
    labels = encoded.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        raise ValueError("A domain needs at least two labels and a nonnumeric suffix.")
    return encoded


def _ip(value: str, version: int) -> str:
    if "%" in value:
        raise ValueError("Scoped IPv6 addresses are not supported.")
    address = ipaddress.ip_address(value)
    if address.version != version:
        raise ValueError(f"Expected IPv{version}.")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # Keep mapped-address spelling consistent across Python 3.12 and 3.14.
        return "::ffff:" + str(address.ipv4_mapped)
    return address.compressed


def _host(value: str) -> str:
    if ":" in value:
        return _ip(value, 6)
    if re.fullmatch(r"[0-9.]+", value):
        return _ip(value, 4)
    return normalize_domain(value)


def _url(value: str) -> str:
    if any(char.isspace() or ord(char) < 32 for char in value) or "\\" in value:
        raise ValueError("URL contains whitespace, controls, or a backslash.")
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("URL contains an invalid percent escape.")
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc or parts.hostname is None:
        raise ValueError("URL requires a scheme and a host.")
    host = _host(parts.hostname)
    _ = parts.port  # Validate numeric port syntax and range.
    authority = parts.netloc.rsplit("@", 1)[-1]
    if authority.endswith(":"):
        raise ValueError("URL port is empty.")
    userinfo = parts.netloc.rsplit("@", 1)[0] + "@" if "@" in parts.netloc else ""
    if authority.startswith("["):
        bracket_end = authority.index("]")
        port = authority[bracket_end + 1 :]
        if port and not re.fullmatch(r":[0-9]+", port):
            raise ValueError("Invalid bracketed URL authority.")
    else:
        port = ":" + authority.rsplit(":", 1)[1] if ":" in authority else ""
    hostname = f"[{host}]" if ":" in host else host
    normalized = urlunsplit(
        (parts.scheme.lower(), userinfo + hostname + port, parts.path, parts.query, parts.fragment)
    )
    if "?" in value.split("#", 1)[0] and not parts.query:
        before, marker, fragment = normalized.partition("#")
        normalized = before + "?" + marker + fragment
    if value.endswith("#") and not normalized.endswith("#"):
        normalized += "#"
    return normalized


def normalize(ioc_type: IOCType, original: str, location: SourceLocation) -> IOCResult:
    """Return invalid recognizable candidates rather than silently dropping them."""
    value = refang(original)
    normalized = value
    valid = True
    message = "Valid syntax; no threat assessment performed."
    try:
        if ioc_type == IOCType.IPV4:
            normalized = _ip(value, 4)
        elif ioc_type == IOCType.IPV6:
            normalized = _ip(value, 6)
        elif ioc_type == IOCType.DOMAIN:
            normalized = normalize_domain(value)
        elif ioc_type == IOCType.URL:
            normalized = _url(value)
        elif ioc_type == IOCType.EMAIL:
            local, separator, domain = value.rpartition("@")
            if not separator or not local or len(local) > 64:
                raise ValueError("Email requires a local part of 1 to 64 characters.")
            if not _LOCAL_PART.fullmatch(local) or local.startswith(".") or local.endswith("."):
                raise ValueError("Email local part must be an unquoted ASCII dot-atom.")
            if ".." in local:
                raise ValueError("Email local part contains consecutive dots.")
            normalized = local + "@" + normalize_domain(domain)
            if len(normalized.encode("utf-8")) > 254:
                raise ValueError("Email exceeds 254 bytes.")
        else:
            normalized = value.lower()
            length = _HASH_LENGTHS[ioc_type]
            if len(value) != length or not re.fullmatch(r"[0-9A-Fa-f]+", value):
                raise ValueError(
                    f"{ioc_type.value} requires exactly {length} hexadecimal characters."
                )
    except (ValueError, idna.IDNAError) as exc:
        valid = False
        message = str(exc)
    occurrence = Occurrence(
        original_value=original,
        is_defanged=value != original,
        source_location=location,
    )
    return IOCResult(
        type=ioc_type,
        original_value=original,
        normalized_value=normalized,
        is_defanged=occurrence.is_defanged,
        is_valid=valid,
        validation_message=message,
        source_location=location,
        occurrences=[occurrence],
    )
