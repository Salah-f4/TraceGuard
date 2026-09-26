"""A representative mixed log must work with network access disabled."""

import socket
from pathlib import Path
from typing import NoReturn

import pytest

from traceguard.core.investigation import analyze_text
from traceguard.core.models import IOCType


def test_mixed_log_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("Offline analysis attempted network access.")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    text = (Path(__file__).parents[1] / "fixtures" / "mixed.log").read_text(encoding="utf-8")
    report = analyze_text(text, source="mixed.log")
    assert {result.type for result in report.results} == set(IOCType)
    assert report.unique_count == 9
    assert report.extracted_count == 10
    assert sum(not result.is_valid for result in report.results) == 1
    email = next(result for result in report.results if result.type == IOCType.EMAIL)
    assert email.normalized_value == "Analyst@example.com"
