"""Bounded UTF-8 input acquisition."""

import sys
from pathlib import Path

from traceguard.core.investigation import validate_text
from traceguard.core.models import MAX_INPUT_BYTES, InputError


def read_input(text: str | None, file: Path | None, stdin: bool) -> tuple[str, str]:
    if sum((text is not None, file is not None, stdin)) != 1:
        raise InputError("Select exactly one of --text, --file, or --stdin.")
    if text is not None:
        validate_text(text)
        return text, "<text>"
    if file is not None:
        if file.suffix.lower() not in {".txt", ".log"}:
            raise InputError("Unsupported file type; use a .txt or .log file.")
        if not file.is_file():
            raise InputError(f"Input is not a regular file: {file}")
        with file.open("rb") as stream:
            data = stream.read(MAX_INPUT_BYTES + 1)
        source = str(file)
    else:
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        source = "<stdin>"
    if len(data) > MAX_INPUT_BYTES:
        raise InputError(f"Input exceeds {MAX_INPUT_BYTES:,} bytes (1 MB).")
    try:
        content = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError("Input must be UTF-8 text (optional UTF-8 BOM).") from exc
    validate_text(content)
    return content, source
